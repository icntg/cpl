// identity.hpp tests: base32x encoding/decoding, ObjectId and the machine seed.
//
// The fixed-length vectors were ported independently from the reference implementation
// (Python base32x) and verified bit by bit; the rest are round trip / boundary / thread
// safety tests.
#include "../vendor/doctest/doctest.hpp"
#include "../utility/identity.hpp"

#include <algorithm>
#include <set>
#include <string>
#include <thread>

#if !defined(_WIN32)
#include <unistd.h>
#endif

using namespace cpl;
using namespace cpl::identity;
using namespace cpl::codec;

template <typename T>
static T Must(Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

static Stream Unhex(const std::string &hex) {
    return Must(Hex::UnHexlify(hex));
}

static std::string HexOf(const Stream &in) {
    return Must(Hex::Hexlify(in));
}

TEST_SUITE("identity::Base32x") {
    TEST_CASE("known vectors (reference implementation compatible)") {
        // Deterministic input: bytes[i] = (i*31+11) & 0xff
        struct Vector {
            const char *hex;
            const char *enc; // Encode (with padding)
            const char *encNoPad;
            const char *forId; // EncodeForId (without padding)
            const char *forIdPad;
        };
        const Vector vectors[] = {
            {"0b",                 "1CL",                     "1C",                     "0B",                 "L0B"},
            {"0b2a",               "1CN0V",                   "1CN0",                   "02SA",               "V02SA"},
            {"0b2a49",             "1CN4JI",                  "1CN4J",                  "0PAJ9",              "I0PAJ9"},
            {"0b2a4968",           "1CN4JT0O",                "1CN4JT0",                "05JMJB8",            "O05JMJB8"},
            {"0b2a496887",         "1CN4JT47",                "1CN4JT47",               "1CN4JT47",           "1CN4JT47"}, // 40-bit aligned
            {"0b2a496887a6",       "1CN4JT47MRL",             "1CN4JT47MR",             "0B594PH1X6",         "L0B594PH1X6"},
            {"0b2a496887a6c5",     "1CN4JT47MU2GV",           "1CN4JT47MU2G",           "02SA95M8F9P5",       "V02SA95M8F9P5"},
            {"0b2a496887a6c5e4032241", "1CN4JT47MU2Y80S284L", "1CN4JT47MU2Y80S284",    "0B594PH1X6RQJ068J1", "L0B594PH1X6RQJ068J1"},
            {"0b2a496887a6c5e403224160", "1CN4JT47MU2Y80S285G0V", "1CN4JT47MU2Y80S285G0", "02SA95M8F9P5WG1J4GB0", "V02SA95M8F9P5WG1J4GB0"},
        };
        for (const auto &v : vectors) {
            const auto in = Unhex(v.hex);
            CHECK_EQ(Must(Base32x::Encode(in)), std::string(v.enc));
            CHECK_EQ(Must(Base32x::Encode(in, false)), std::string(v.encNoPad));
            CHECK_EQ(Must(Base32x::EncodeForId(in)), std::string(v.forId));
            CHECK_EQ(Must(Base32x::EncodeForId(in, true)), std::string(v.forIdPad));
            // The output of Encode is restored completely
            CHECK_EQ(HexOf(Must(Base32x::Decode(v.enc))), HexOf(in));
        }
    }

    TEST_CASE("python test vectors (ObjectId shaped ids)") {
        CHECK_EQ(Must(Base32x::EncodeForId(Unhex("5bbab4cf01d18529383f71b1"))),
                 std::string("0PXTPK7G3MC554W3YWDH"));
        CHECK_EQ(Must(Base32x::EncodeForId(Unhex("5bbab4cf01d18529383f71b2"))),
                 std::string("0PXTPK7G3MC554W3YWDJ"));
        CHECK_EQ(Must(Base32x::EncodeForId(Unhex("5bbab4cf01d18529383f71c1"))),
                 std::string("0PXTPK7G3MC554W3YWE1"));
    }

    TEST_CASE("encode/decode round trip across lengths") {
        for (size_t len = 1; len <= 24; len++) {
            Stream in{};
            for (size_t i = 0; i < len; i++) {
                in.push_back(static_cast<uint8_t>((i * 31 + 11) & 0xff));
            }
            const auto enc = Must(Base32x::Encode(in));
            // Output length: data characters ceil(len*8/5) + 1 padding when not aligned to 5 bits
            const size_t expect = (len * 8 + 4) / 5 + ((0 == len * 8 % 5) ? 0 : 1);
            CHECK_EQ(enc.size(), expect);
            const auto dec = Must(Base32x::Decode(enc));
            REQUIRE_EQ(dec.size(), in.size());
            for (size_t i = 0; i < in.size(); i++) {
                CHECK_EQ(dec[i], in[i]);
            }
        }
    }

    TEST_CASE("aligned input: Encode equals EncodeForId and decodes back") {
        for (size_t len : {5u, 10u, 15u, 20u}) {
            Stream in{};
            for (size_t i = 0; i < len; i++) {
                in.push_back(static_cast<uint8_t>((i * 7 + 3) & 0xff));
            }
            const auto enc = Must(Base32x::Encode(in, false));
            const auto forId = Must(Base32x::EncodeForId(in));
            CHECK_EQ(enc, forId);
            // When aligned, the output of EncodeForId is restored without padding
            CHECK_EQ(Must(Base32x::Decode(enc)), in);
        }
    }

    TEST_CASE("EncodeForId low-bit alignment keeps common suffix") {
        const auto id12 = Unhex("5bbab4cf01d18529383f71b1");
        const auto base = Must(Base32x::EncodeForId(id12));
        // When zero bytes are added at the high end (the low nibble is 0), the right-aligned encoding keeps the common suffix
        for (const auto prefix : {0xa0u, 0x00u, 0x10u}) {
            Stream id13{};
            id13.push_back(static_cast<uint8_t>(prefix));
            id13.insert(id13.end(), id12.begin(), id12.end());
            const auto enc = Must(Base32x::EncodeForId(id13));
            CHECK(enc.size() == base.size() + 1);
            CHECK(enc.substr(1) == base);
        }
    }

    TEST_CASE("output alphabet excludes I L O V except padding") {
        for (size_t len = 1; len <= 16; len++) {
            Stream in{};
            for (size_t i = 0; i < len; i++) {
                in.push_back(static_cast<uint8_t>((i * 131 + 7) & 0xff));
            }
            const auto enc = Must(Base32x::Encode(in, false));
            const auto forId = Must(Base32x::EncodeForId(in));
            for (const char c : enc) {
                CHECK(c != 'I');
                CHECK(c != 'L');
                CHECK(c != 'O');
                CHECK(c != 'V');
            }
            for (const char c : forId) {
                CHECK(c != 'I');
                CHECK(c != 'L');
                CHECK(c != 'O');
                CHECK(c != 'V');
            }
        }
    }

    TEST_CASE("Decode rejects invalid input") {
        // Empty / padding only / invalid character in the middle (I is not in the alphabet) / lower case
        CHECK_FALSE(Base32x::Decode("").has_value());
        CHECK_FALSE(Base32x::Decode("I").has_value());
        CHECK_FALSE(Base32x::Decode("0I0").has_value());
        CHECK_FALSE(Base32x::Decode("I0ZW").has_value());
        CHECK_FALSE(Base32x::Decode("zw").has_value());
        // The output of EncodeForId (padding on the left) cannot be decoded
        CHECK_FALSE(Base32x::Decode(Must(Base32x::EncodeForId(Unhex("0b2a")))).has_value());
        CHECK_FALSE(Base32x::Decode(Must(Base32x::EncodeForId(Unhex("0b"), true))).has_value());
    }

    TEST_CASE("Encode rejects null and empty") {
        CHECK_FALSE(Base32x::Encode(nullptr, 0).has_value());
        const Stream empty{};
        CHECK_FALSE(Base32x::Encode(empty).has_value());
        CHECK_FALSE(Base32x::EncodeForId(empty).has_value());
        CHECK_FALSE(Base32x::EncodeForId(nullptr, 4).has_value());
    }
}

TEST_SUITE("identity::ObjectId") {
    static uint32_t BigEndian32(const Stream &in, size_t off) {
        return (static_cast<uint32_t>(in[off]) << 24)
               | (static_cast<uint32_t>(in[off + 1]) << 16)
               | (static_cast<uint32_t>(in[off + 2]) << 8)
               | static_cast<uint32_t>(in[off + 3]);
    }

    static uint32_t BigEndian24(const Stream &in, size_t off) {
        return (static_cast<uint32_t>(in[off]) << 16)
               | (static_cast<uint32_t>(in[off + 1]) << 8)
               | static_cast<uint32_t>(in[off + 2]);
    }

    TEST_CASE("layout: timestamp / machine / pid / counter") {
        const auto now = static_cast<uint32_t>(time(nullptr));
        const auto id0 = Must(ObjectId::Generate());
        const auto id1 = Must(ObjectId::Generate());
        REQUIRE_EQ(id0.size(), static_cast<size_t>(ObjectId::SIZE));
        REQUIRE_EQ(id1.size(), static_cast<size_t>(ObjectId::SIZE));

        const auto ts0 = BigEndian32(id0, 0);
        CHECK(ts0 >= now - 300);
        CHECK(ts0 <= now + 300);
        // Same machine and process: the machine/pid fields agree
        for (size_t i = 4; i < 9; i++) {
            CHECK_EQ(id0[i], id1[i]);
        }
        // The pid field equals the real PID (when PID>1 the random branch is not taken)
        if (impl::CurrentPid() > 1) {
            const auto pid = static_cast<uint32_t>((id0[7] << 8) | id0[8]);
            CHECK_EQ(pid, impl::CurrentPid() & 0xffff);
        }
        // The counter increases monotonically by 1
        CHECK_EQ(BigEndian24(id1, 9), (BigEndian24(id0, 9) + 1) & 0xffffff);
    }

    TEST_CASE("uniqueness") {
        std::set<Stream> ids{};
        for (int i = 0; i < 10000; i++) {
            ids.insert(Must(ObjectId::Generate()));
        }
        CHECK_EQ(ids.size(), static_cast<size_t>(10000));
    }

    TEST_CASE("thread safety") {
        std::mutex mutex{};
        std::set<Stream> ids{};
        std::vector<std::thread> workers{};
        for (int t = 0; t < 4; t++) {
            workers.emplace_back([&]() {
                std::vector<Stream> local{};
                for (int i = 0; i < 2500; i++) {
                    const auto r0 = ObjectId::Generate();
                    if (r0) {
                        local.push_back(r0.value());
                    }
                }
                const std::lock_guard<std::mutex> guard(mutex);
                ids.insert(local.begin(), local.end());
            });
        }
        for (auto &worker : workers) {
            worker.join();
        }
        CHECK_EQ(ids.size(), static_cast<size_t>(10000));
    }

    TEST_CASE("GenerateEncoded: 12 bytes -> 20 chars, right-aligned base32x") {
        const auto s0 = Must(ObjectId::GenerateEncoded());
        const auto s1 = Must(ObjectId::GenerateEncoded());
        REQUIRE_EQ(s0.size(), static_cast<size_t>(20));
        CHECK(s0 != s1);
        const std::string alphabet = Base32x::EncodeTable();
        for (const char c : s0) {
            CHECK(alphabet.find(c) != std::string::npos);
        }
        // The right-aligned encoding has no padding and cannot be decoded (consistent with the reference implementations)
        CHECK_FALSE(Base32x::Decode(s0).has_value());
    }
}

TEST_SUITE("identity::MachineSeed") {
    // Hexlify prints upper case hex digits; the expected strings below are spelled the same way.
    static std::string HexOf(const cpl::naion::ESD &seed) {
        return Must(Hex::Hexlify(seed.data(), seed.size()));
    }

    // `times` copies of `s`, to spell out zero padding in the expected seeds.
    static std::string Repeat(const std::string &s, const size_t times) {
        std::string out{};
        for (size_t i = 0; i < times; i++) {
            out += s;
        }
        return out;
    }

#if !defined(_WIN32)
    // The host name of this machine, read through the same system call as identity.hpp.
    // Windows is left out: there MachineSeed() uses the derivation of the Windows client,
    // which has no host name.
    static std::string HostNameOfThisMachine() {
        char buffer[256]{};
        REQUIRE_EQ(gethostname(buffer, sizeof(buffer)), 0);
        return std::string(buffer);
    }
#endif

    TEST_CASE("layout: 16 bytes of machine id then 16 bytes of host name") {
        const auto seed = MachineSeedFrom("0123456789abcdef", "ABCDEFGHIJKLMNOP");
        CHECK_EQ(HexOf(seed), std::string(
            "30313233343536373839616263646566" // "0123456789abcdef"
            "4142434445464748494A4B4C4D4E4F50" // "ABCDEFGHIJKLMNOP"
        ));
    }

    TEST_CASE("zero padding of short inputs") {
        // 3 bytes of machine id and 1 byte of host name: everything else stays zero.
        const auto seed = MachineSeedFrom("abc", "h");
        CHECK_EQ(HexOf(seed), std::string("616263") + Repeat("00", 13) + "68" + Repeat("00", 15));
    }

    TEST_CASE("long inputs are truncated to 16 bytes per half") {
        // A machine id as /etc/machine-id holds it (32 hex characters) and a long host name.
        const auto seed = MachineSeedFrom("0123456789abcdef0123456789abcdef", "abcdefghijklmnopqrstuvwxyz");
        CHECK_EQ(HexOf(seed), std::string(
            "30313233343536373839616263646566" // "0123456789abcdef"
            "6162636465666768696A6B6C6D6E6F70" // "abcdefghijklmnop"
        ));
        CHECK_EQ(seed, MachineSeedFrom("0123456789abcdef", "abcdefghijklmnop"));
    }

    TEST_CASE("empty machine id leaves the first half zero") {
        const auto seed = MachineSeedFrom("", "host");
        CHECK_EQ(HexOf(seed), Repeat("00", 16) + "686F7374" + Repeat("00", 12));
        // Whitespace only is empty as well, and an empty host name works the same way.
        CHECK_EQ(MachineSeedFrom(" \n\t", "host"), seed);
        CHECK_EQ(HexOf(MachineSeedFrom("0123456789abcdef", "")),
                 std::string("30313233343536373839616263646566") + Repeat("00", 16));
    }

    TEST_CASE("a machine id that is not hex is copied as bytes") {
        // Nothing is decoded: the text lands in the seed exactly as it is written.
        const auto seed = MachineSeedFrom("not-hex-at-all!!", "host");
        CHECK_EQ(HexOf(seed), std::string("6E6F742D6865782D61742D616C6C2121") + "686F7374" + Repeat("00", 12));
    }

    TEST_CASE("whitespace in the machine id is removed") {
        // A machine-id file ends with a newline; the newline must not shift the bytes.
        CHECK_EQ(MachineSeedFrom("0123456789abcdef\n", "host"), MachineSeedFrom("0123456789abcdef", "host"));
        CHECK_EQ(MachineSeedFrom("0123456789abcde f", "host"), MachineSeedFrom("0123456789abcdef", "host"));
        // The product_uuid layout with its line break.
        CHECK_EQ(MachineSeedFrom("4C4C4544-0042-XX00-XXXX-B1C04F4C3132\n", "host"),
                 MachineSeedFrom("4C4C4544-0042-XX00-XXXX-B1C04F4C3132", "host"));
        // Only the machine id is cleaned: the whitespace of the host name is kept.
        CHECK_NE(MachineSeedFrom("id", "a b"), MachineSeedFrom("id", "ab"));
    }

    TEST_CASE("pure function: the same inputs give the same seed") {
        CHECK_EQ(MachineSeedFrom("0123456789abcdef", "host"), MachineSeedFrom("0123456789abcdef", "host"));
        CHECK_NE(MachineSeedFrom("0123456789abcdef", "host"), MachineSeedFrom("1123456789abcdef", "host"));
        CHECK_NE(MachineSeedFrom("0123456789abcdef", "host"), MachineSeedFrom("0123456789abcdef", "host2"));
    }

    TEST_CASE("MachineSeed is stable and, on Linux, carries the host name") {
        const auto first = Must(MachineSeed());
        const auto second = Must(MachineSeed());
        // The same machine gives the same 32 bytes.
        CHECK_EQ(first, second);
        CHECK_EQ(first.size(), static_cast<size_t>(32));
#if !defined(_WIN32)
        // The second half starts with the host name of this machine.
        const std::string hostName = HostNameOfThisMachine();
        REQUIRE_FALSE(hostName.empty());
        const size_t hostBytes = std::min<size_t>(hostName.size(), 16);
        bool carried = true;
        for (size_t i = 0; i < hostBytes; i++) {
            carried = carried && first[16 + i] == static_cast<uint8_t>(hostName[i]);
        }
        CHECK(carried);
        // A host name shorter than 16 bytes is zero padded.
        for (size_t i = 16 + hostBytes; i < first.size(); i++) {
            CHECK_EQ(first[i], static_cast<uint8_t>(0));
        }
        // The first half is the machine id. It was found, so it is not blank.
        CHECK(std::any_of(first.begin(), first.begin() + 16, [](const uint8_t b) { return b != 0; }));
#endif
    }
}
