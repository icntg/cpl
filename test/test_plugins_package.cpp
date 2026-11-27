// Tests for cpl::plugins - the plugin package format (LoadPackageConfigFromBytes).
//
// Packages are assembled in memory and signed with a throwaway CA whose key pair is derived
// from a fixed seed, so the tests need no files and are deterministic. Layout of a package:
//   payload | configuration JSON | IfwPluginTrailer (28 bytes) | Ed25519 signature (64 bytes)
// The signature covers everything before it.
#include "../vendor/doctest/doctest.hpp"
#include "../plugins.hpp"

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

using namespace cpl;
using namespace cpl::plugins;

static_assert(sizeof(IfwPluginTrailer) == 28, "IfwPluginTrailer must stay 28 bytes on every platform");
static_assert(IFW_PLUGIN_SIGNATURE_BYTES == 64, "a package carries one Ed25519 signature");

static int64_t CodeOf(const cpl::Error &error) {
    return error.Code.i64;
}

TEST_SUITE("cpl::plugins::package") {
    // A throwaway CA: an Ed25519 key pair derived from a fixed seed.
    struct Ca {
        cpl::naion::EPK publicKey{};
        cpl::naion::ESK secretKey{};
    };

    static Ca MakeCa(const uint8_t firstByte) {
        Ca ca{};
        cpl::naion::ESD seed{};
        for (size_t i = 0; i < seed.size(); i++) {
            seed[i] = static_cast<uint8_t>(firstByte + i);
        }
        REQUIRE_EQ(naion_sign_ed25519_seed_keypair(
                       ca.publicKey.data(), ca.secretKey.data(), seed.data()), 0);
        return ca;
    }

    // Everything a package is made of. The default values give a valid package;
    // a test changes one of them to get a broken one.
    struct PackageSpec {
        Stream payload{}; // the shared library itself (arbitrary bytes here)
        std::string configJson{};
        std::string magic{IFW_PLUGIN_TRAILER_MAGIC};
        uint16_t packageVersion{static_cast<uint16_t>(IFW_PLUGIN_PACKAGE_VERSION)};
        // Zero means: derived from the payload and the JSON, which is the valid layout.
        uint32_t cfgOffset{0};
        uint32_t cfgSize{0};
        bool sign{true}; // false: the signature slot stays all zero
    };

    // Assembles payload ++ JSON ++ trailer ++ signature.
    static Stream BuildPackage(const Ca &ca, const PackageSpec &spec) {
        Stream data = spec.payload;
        const uint32_t payloadSize = static_cast<uint32_t>(spec.payload.size());
        const uint32_t jsonSize = static_cast<uint32_t>(spec.configJson.size());
        data.insert(data.end(), spec.configJson.begin(), spec.configJson.end());

        IfwPluginTrailer trailer{};
        REQUIRE_GE(spec.magic.size(), sizeof(trailer.magic));
        std::memcpy(trailer.magic, spec.magic.data(), sizeof(trailer.magic));
        trailer.package_version = spec.packageVersion;
        trailer.cfg_offset = spec.cfgOffset != 0 ? spec.cfgOffset : payloadSize;
        trailer.cfg_size = spec.cfgSize != 0 ? spec.cfgSize : jsonSize;
        const auto *trailerBytes = reinterpret_cast<const uint8_t *>(&trailer);
        data.insert(data.end(), trailerBytes, trailerBytes + sizeof(trailer));

        // The signature is detached and covers payload, JSON and trailer.
        unsigned char signature[naion_sign_ed25519_BYTES]{};
        if (spec.sign) {
            unsigned long long signatureSize = 0;
            REQUIRE_FALSE(data.empty());
            REQUIRE_EQ(naion_sign_ed25519_detached(
                           signature, &signatureSize, data.data(),
                           static_cast<unsigned long long>(data.size()), ca.secretKey.data()), 0);
            REQUIRE_EQ(signatureSize, static_cast<unsigned long long>(naion_sign_ed25519_BYTES));
        }
        data.insert(data.end(), signature, signature + sizeof(signature));
        return data;
    }

    // Loads a package the way the agent does: the CA key is a raw pointer and a size.
    static cpl::Result<PackageInfo> Load(const Stream &data, const Ca &ca) {
        return LoadPackageConfigFromBytes(
            data.data(), data.size(), ca.publicKey.data(), ca.publicKey.size(), "memory"
        );
    }

    // Loads `data` and requires it to be rejected with `code` and a reason containing `text`.
    static void CheckRejected(const Stream &data, const Ca &ca, const int64_t code, const char *text) {
        const auto pkg = Load(data, ca);
        CHECK_FALSE(pkg.has_value());
        if (!pkg.has_value()) {
            CHECK_EQ(CodeOf(pkg.error()), code);
            CHECK(pkg.error().Reason.find(text) != std::string::npos);
        }
    }

    static Stream MakePayload() {
        Stream payload{};
        for (size_t i = 0; i < 256; i++) {
            payload.push_back(static_cast<uint8_t>((i * 7 + 3) & 0xff));
        }
        return payload;
    }

    static const char *const kConfigJson =
            R"({"name":"demo","version":"1.0.0","run_mode":"repeat","interval_seconds":60})";

    // A valid package signed by `ca`.
    static Stream MakeValidPackage(const Ca &ca) {
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = kConfigJson;
        return BuildPackage(ca, spec);
    }

    // The code LoadPackageConfigFromBytes returns when the signature does not verify.
    static int64_t SignatureFailureCode() {
        const cpl::Error::CodeDef code = cpl::naion::Errors::CryptoSignVerifyDetached;
        return code.i64;
    }

    TEST_CASE("binary layout of the plugin ABI") {
        // magic[8] | package_version | flags | cfg_offset | cfg_size | reserved0 | reserved1
        CHECK_EQ(sizeof(IfwPluginTrailer), 28u);
        CHECK_EQ(offsetof(IfwPluginTrailer, package_version), 8u);
        CHECK_EQ(offsetof(IfwPluginTrailer, flags), 10u);
        CHECK_EQ(offsetof(IfwPluginTrailer, cfg_offset), 12u);
        CHECK_EQ(offsetof(IfwPluginTrailer, cfg_size), 16u);
        // cb + api_version + one pointer (send).
        CHECK_EQ(sizeof(IfwPluginHostApi), sizeof(uint32_t) + sizeof(uint32_t) + sizeof(void *));
        CHECK_EQ(IFW_PLUGIN_API_VERSION, 0x00010002u);
        CHECK_EQ(IFW_PLUGIN_PACKAGE_VERSION, 0x0001u);
        CHECK_EQ(std::string(IFW_PLUGIN_TRAILER_MAGIC, 8), std::string("IFWPLG01"));
    }

    TEST_CASE("a valid package passes") {
        const Ca ca = MakeCa(0x10);
        const Stream data = MakeValidPackage(ca);

        const auto pkg = Load(data, ca);
        REQUIRE(pkg.has_value());
        // The payload is everything before the configuration JSON.
        CHECK_EQ(pkg.value().payloadSize, MakePayload().size());
        CHECK_EQ(pkg.value().configJson, std::string(kConfigJson));
        CHECK_EQ(pkg.value().path, std::string("memory"));
        // The trailer is handed out as it was signed.
        CHECK_EQ(std::string(pkg.value().trailer.magic, 8), std::string(IFW_PLUGIN_TRAILER_MAGIC));
        CHECK_EQ(pkg.value().trailer.package_version, static_cast<uint16_t>(IFW_PLUGIN_PACKAGE_VERSION));
        CHECK_EQ(pkg.value().trailer.cfg_offset, static_cast<uint32_t>(MakePayload().size()));
        CHECK_EQ(pkg.value().trailer.cfg_size, static_cast<uint32_t>(std::strlen(kConfigJson)));
        // The configuration parses as the runtime configuration of the plugin.
        const auto runtime = ParseRuntimeConfig(pkg.value().configJson);
        REQUIRE(runtime.has_value());
        CHECK_EQ(runtime.value().name, std::string("demo"));
        CHECK_EQ(runtime.value().intervalSeconds, 60u);
    }

    TEST_CASE("a changed payload byte fails") {
        const Ca ca = MakeCa(0x10);
        Stream data = MakeValidPackage(ca);
        data[0] ^= 0xff;

        CheckRejected(data, ca, SignatureFailureCode(), "signature");
    }

    TEST_CASE("a changed JSON byte fails") {
        const Ca ca = MakeCa(0x10);
        Stream data = MakeValidPackage(ca);
        // Flip the case of a letter inside the JSON: the text stays valid JSON, so only
        // the signature can reject the package.
        const size_t jsonOffset = data.size() - IFW_PLUGIN_SIGNATURE_BYTES - sizeof(IfwPluginTrailer) -
                                  std::strlen(kConfigJson);
        REQUIRE_EQ(data[jsonOffset + 5], static_cast<uint8_t>('e'));
        data[jsonOffset + 5] = static_cast<uint8_t>('E');

        CheckRejected(data, ca, SignatureFailureCode(), "signature");
    }

    TEST_CASE("another CA key fails") {
        const Ca ca = MakeCa(0x10);
        const Ca other = MakeCa(0xa0);
        const Stream data = MakeValidPackage(ca);
        CHECK_NE(ca.publicKey, other.publicKey);

        CheckRejected(data, other, SignatureFailureCode(), "signature");
    }

    TEST_CASE("a wrong magic fails") {
        const Ca ca = MakeCa(0x10);
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = kConfigJson;
        spec.magic = "XFWPLG01";

        CheckRejected(BuildPackage(ca, spec), ca, static_cast<int64_t>(cpl::Error::InvalidArgument),
                      "magic");
    }

    TEST_CASE("a wrong package version fails") {
        const Ca ca = MakeCa(0x10);
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = kConfigJson;
        spec.packageVersion = static_cast<uint16_t>(IFW_PLUGIN_PACKAGE_VERSION) + 1;

        CheckRejected(BuildPackage(ca, spec), ca, static_cast<int64_t>(cpl::Error::InvalidArgument),
                      "package version");
    }

    TEST_CASE("a configuration range that does not end at the trailer fails") {
        const Ca ca = MakeCa(0x10);
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = kConfigJson;
        // One byte too long: the range ends inside the trailer.
        spec.cfgSize = static_cast<uint32_t>(std::strlen(kConfigJson)) + 1;

        CheckRejected(BuildPackage(ca, spec), ca, static_cast<int64_t>(cpl::Error::OutOfRange),
                      "cfg range");
    }

    TEST_CASE("a configuration range that starts at or after the trailer fails") {
        const Ca ca = MakeCa(0x10);
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = kConfigJson;
        // The JSON is where it belongs, but the trailer says it starts inside the trailer.
        spec.cfgOffset = static_cast<uint32_t>(MakePayload().size() + std::strlen(kConfigJson));

        CheckRejected(BuildPackage(ca, spec), ca, static_cast<int64_t>(cpl::Error::OutOfRange),
                      "cfg offset/size");
    }

    TEST_CASE("an invalid JSON fails") {
        const Ca ca = MakeCa(0x10);
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = "{not json";

        CheckRejected(BuildPackage(ca, spec), ca, static_cast<int64_t>(cpl::Error::InvalidArgument),
                      "not valid JSON");
    }

    TEST_CASE("a package without a valid signature fails") {
        const Ca ca = MakeCa(0x10);
        PackageSpec spec{};
        spec.payload = MakePayload();
        spec.configJson = kConfigJson;
        spec.sign = false;

        // The layout is intact, only the signature is missing: layout checks pass,
        // the verification does not.
        CheckRejected(BuildPackage(ca, spec), ca, SignatureFailureCode(), "signature");
    }

    TEST_CASE("an input shorter than the minimum size fails") {
        const Ca ca = MakeCa(0x10);
        const size_t minimum = sizeof(IfwPluginTrailer) + IFW_PLUGIN_SIGNATURE_BYTES;
        CHECK_EQ(minimum, 92u);

        // Exactly the trailer and the signature, with nothing in front of them.
        Stream exactlyMinimum(minimum, 0);
        CheckRejected(exactlyMinimum, ca, static_cast<int64_t>(cpl::Error::OutOfRange), "too small");

        // Shorter still, down to zero bytes.
        exactlyMinimum.resize(minimum - 1);
        CheckRejected(exactlyMinimum, ca, static_cast<int64_t>(cpl::Error::OutOfRange), "too small");
        const auto empty = LoadPackageConfigFromBytes(
            exactlyMinimum.data(), 0, ca.publicKey.data(), ca.publicKey.size());
        CHECK_FALSE(empty.has_value());
        CHECK(empty.error().Reason.find("too small") != std::string::npos);

        // One byte more passes the size check and is rejected for its content (no magic).
        Stream oneMore(minimum + 1, 0);
        CheckRejected(oneMore, ca, static_cast<int64_t>(cpl::Error::InvalidArgument), "magic");
    }

    TEST_CASE("null inputs and a wrong CA key size fail") {
        const Ca ca = MakeCa(0x10);
        const Stream data = MakeValidPackage(ca);

        auto pkg = LoadPackageConfigFromBytes(nullptr, data.size(), ca.publicKey.data(), ca.publicKey.size());
        CHECK_FALSE(pkg.has_value());
        CHECK_EQ(CodeOf(pkg.error()), static_cast<int64_t>(cpl::Error::NullPointer));

        pkg = LoadPackageConfigFromBytes(data.data(), data.size(), nullptr, ca.publicKey.size());
        CHECK_FALSE(pkg.has_value());
        CHECK_EQ(CodeOf(pkg.error()), static_cast<int64_t>(cpl::Error::NullPointer));

        pkg = LoadPackageConfigFromBytes(data.data(), data.size(), ca.publicKey.data(), 31);
        CHECK_FALSE(pkg.has_value());
        CHECK_EQ(CodeOf(pkg.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));
    }
}
