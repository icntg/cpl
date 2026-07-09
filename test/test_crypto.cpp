#include "../vendor/doctest/doctest.hpp"
#include "../crypto.hpp"

#include <cstring>
#include <string>

using namespace cpl;
using namespace cpl::crypto;

template <typename T>
static T Must(Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

static int32_t MustCode(Int32Result r) {
    REQUIRE(r.has_value());
    return r.value();
}

// Hex-encode 32 bytes for compact expected-value comparison.
static std::string Hex32(const uint8_t *p) {
    static const char *kHex = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (int i = 0; i < 32; ++i) {
        s.push_back(kHex[(p[i] >> 4) & 0xf]);
        s.push_back(kHex[p[i] & 0xf]);
    }
    return s;
}

TEST_SUITE("crypto SHA256") {
    using impl::SHA256;

    TEST_CASE("rejects empty input by design") {
        uint8_t out[32]{};
        size_t outSize = sizeof(out);
        // Update() refuses zero-length input; callers must supply at least one byte.
        CHECK_FALSE(impl::sha256(out, outSize, "", 0).has_value());
    }

    TEST_CASE("'abc' known vector") {
        uint8_t out[32]{};
        size_t outSize = sizeof(out);
        REQUIRE(impl::sha256(out, outSize, "abc", 3).has_value());
        CHECK_EQ(Hex32(out), std::string(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    TEST_CASE("long message spanning multiple blocks") {
        // Two-block FIPS 180-2 vector: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t out[32]{};
        size_t outSize = sizeof(out);
        REQUIRE(impl::sha256(out, outSize, msg, 56).has_value());
        CHECK_EQ(Hex32(out), std::string(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    }

    TEST_CASE("Update rejects null/empty") {
        SHA256 h;
        CHECK_FALSE(h.Update(nullptr, 0).has_value());
    }
}

TEST_SUITE("crypto HMAC-SHA256") {
    using impl::SHA256;

    TEST_CASE("RFC 4231 Test Case 1") {
        // Key = 0x0b*20, Data = "Hi There"
        uint8_t key[20];
        std::memset(key, 0x0b, sizeof(key));
        uint8_t out[32]{};
        size_t outSize = sizeof(out);
        REQUIRE(impl::hmac256(out, outSize, key, sizeof(key), "Hi There", 8).has_value());
        CHECK_EQ(Hex32(out), std::string(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }

    TEST_CASE("RFC 4231 Test Case 2") {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        const char *key = "Jefe";
        const char *data = "what do ya want for nothing?";
        uint8_t out[32]{};
        size_t outSize = sizeof(out);
        REQUIRE(impl::hmac256(out, outSize, key, 4, data, 28).has_value());
        CHECK_EQ(Hex32(out), std::string(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    }

    TEST_CASE("HMAC rejects null key") {
        uint8_t out[32]{};
        size_t outSize = sizeof(out);
        CHECK_FALSE(impl::hmac256(out, outSize, nullptr, 0, "x", 1).has_value());
    }
}

TEST_SUITE("crypto RC4") {
    using impl::RC4;

    TEST_CASE("RFC 6229 Test Case: key 0102030405") {
        // Key = [01,02,03,04,05], no drop. Keystream first 16 bytes per RFC 6229
        // (cross-checked against PyCryptodome's ARC4).
        const uint8_t key[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto rc4 = Must(RC4::Create(const_cast<uint8_t *>(key), sizeof(key)));
        uint8_t zero[16]{};
        uint8_t out[16]{};
        size_t outSize = 0;
        REQUIRE(rc4.Encrypt(out, outSize, zero, sizeof(zero)).has_value());
        const uint8_t expected[16] = {
            0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
            0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
        };
        CHECK(std::memcmp(out, expected, 16) == 0);
    }

    TEST_CASE("RC4 encrypt/decrypt round trip") {
        const uint8_t key[8] = {0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78};
        const std::string msg = "RC4 stream cipher round-trip test message.";
        // Encrypt
        auto enc = Must(RC4::Create(const_cast<uint8_t *>(key), sizeof(key)));
        std::vector<uint8_t> cipher(msg.size());
        size_t cipherLen = 0;
        REQUIRE(enc.Encrypt(cipher.data(), cipherLen,
                            reinterpret_cast<const uint8_t *>(msg.data()), msg.size()).has_value());
        // Decrypt (RC4 is symmetric)
        auto dec = Must(RC4::Create(const_cast<uint8_t *>(key), sizeof(key)));
        std::vector<uint8_t> plain(msg.size());
        size_t plainLen = 0;
        REQUIRE(dec.Decrypt(plain.data(), plainLen, cipher.data(), cipherLen).has_value());
        REQUIRE_EQ(plainLen, msg.size());
        CHECK(std::memcmp(plain.data(), msg.data(), msg.size()) == 0);
    }

    TEST_CASE("RC4 Create rejects null/empty key") {
        CHECK_FALSE(RC4::Create(nullptr, 0).has_value());
    }
}

TEST_SUITE("crypto Crypto_RC4_HMAC256") {
    using impl::Crypto_RC4_HMAC256;

    TEST_CASE("Encrypt/Decrypt round trip (raw impl)") {
        const Stream key{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
        const std::string msg = "authenticated encryption round-trip payload";
        const Stream in(msg.begin(), msg.end());

        Crypto_RC4_HMAC256 enc(key);
        Stream buf(in.size() + 64); // ample overhead
        size_t outSize = 0;
        REQUIRE(enc.Encrypt(buf.data(), outSize, in.data(), in.size()).has_value());
        buf.resize(outSize);
        CHECK_GT(buf.size(), in.size());

        Crypto_RC4_HMAC256 dec(key);
        Stream plain(in.size() + 16);
        size_t plainSize = plain.size();
        REQUIRE(dec.Decrypt(plain.data(), plainSize, buf.data(), buf.size()).has_value());
        REQUIRE_EQ(plainSize, in.size());
        CHECK(std::memcmp(plain.data(), in.data(), in.size()) == 0);
    }

    TEST_CASE("stl wrapper Encrypt/Decrypt round trip") {
        const Stream key{0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
        const Stream in{'s', 't', 'l', ' ', 'w', 'r', 'a', 'p', 'p', 'e', 'r'};

        stl::impl::Crypto_RC4_HMAC256 enc(key);
        const auto cipher = Must(enc.Encrypt(in));
        CHECK_GT(cipher.size(), in.size());

        stl::impl::Crypto_RC4_HMAC256 dec(key);
        const auto plain = Must(dec.Decrypt(cipher));
        REQUIRE_EQ(plain.size(), in.size());
        CHECK(std::memcmp(plain.data(), in.data(), in.size()) == 0);
    }

    TEST_CASE("Decrypt rejects tampered ciphertext") {
        const Stream key{0x01, 0x02, 0x03, 0x04};
        const Stream in{'t', 'a', 'm', 'p', 'e', 'r', '!'};

        stl::impl::Crypto_RC4_HMAC256 enc(key);
        auto cipher = Must(enc.Encrypt(in));

        // Flip a byte in the encrypted payload region (after the header).
        cipher.back() ^= 0x01;

        stl::impl::Crypto_RC4_HMAC256 dec(key);
        CHECK_FALSE(dec.Decrypt(cipher).has_value());
    }

    TEST_CASE("Decrypt rejects truncated input") {
        const Stream key{0x01, 0x02, 0x03, 0x04};
        stl::impl::Crypto_RC4_HMAC256 dec(key);
        const Stream tooShort(Crypto_RC4_HMAC256::SIGN_E_BYTES_LENGTH, 0);
        CHECK_FALSE(dec.Decrypt(tooShort).has_value());
    }
}

TEST_SUITE("crypto UnsafeRandom") {
    using impl::UnsafeRandom;

    TEST_CASE("Produces non-zero output and distinct calls") {
        UnsafeRandom &r = impl::GetUnsafeRandomProvider();
        Stream a(128, 0), b(128, 0);
        REQUIRE(MustCode(r.Rand(a.data(), a.size())) == 0);
        REQUIRE(MustCode(r.Rand(b.data(), b.size())) == 0);
        // Statistically extremely unlikely to be all zero.
        bool aHasNonZero = false;
        for (auto x : a) { if (x != 0) { aHasNonZero = true; break; } }
        CHECK(aHasNonZero);
        // Two consecutive draws should differ.
        CHECK(std::memcmp(a.data(), b.data(), a.size()) != 0);
    }

    TEST_CASE("Rejects null/empty") {
        UnsafeRandom &r = impl::GetUnsafeRandomProvider();
        CHECK_FALSE(r.Rand(nullptr, 0).has_value());
    }
};
