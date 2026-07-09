#include "../vendor/doctest/doctest.hpp"
#include "../strings.hpp"

#include <string>
#include <vector>

using namespace cpl;
using namespace cpl::strings;
using namespace cpl::codec;

template <typename T>
static T Must(Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

TEST_SUITE("codec::Hex") {
    TEST_CASE("Hexlify / UnHexlify round trip") {
        const Stream in{0x00, 0x01, 0x7f, 0x80, 0xff, 0xab, 0xcd, 0xef};
        const auto hex = Must(Hex::Hexlify(in));
        CHECK_EQ(hex, std::string("00017F80FFABCDEF"));

        const auto back = Must(Hex::UnHexlify(hex));
        REQUIRE_EQ(back.size(), in.size());
        for (size_t i = 0; i < in.size(); ++i) {
            CHECK_EQ(back[i], in[i]);
        }
    }

    TEST_CASE("Hexlify rejects null/empty") {
        CHECK_FALSE(Hex::Hexlify(nullptr, 0).has_value());
        const Stream empty{};
        CHECK_FALSE(Hex::Hexlify(empty).has_value());
    }

    TEST_CASE("UnHexlify lower-case round trip") {
        const auto back = Must(Hex::UnHexlify(std::string("deadbeef")));
        REQUIRE_EQ(back.size(), 4u);
        CHECK_EQ(back[0], 0xde);
        CHECK_EQ(back[1], 0xad);
        CHECK_EQ(back[2], 0xbe);
        CHECK_EQ(back[3], 0xef);
    }

    TEST_CASE("UnHexlify rejects odd length") {
        CHECK_FALSE(Hex::UnHexlify(std::string("abc")).has_value());
    }

    TEST_CASE("UnHexlify rejects invalid character") {
        // 'g' is not a hex digit — must be an error, NOT a silent empty success.
        CHECK_FALSE(Hex::UnHexlify(std::string("gg")).has_value());
        CHECK_FALSE(Hex::UnHexlify(std::string("00g0")).has_value());
    }
}

TEST_SUITE("codec::Base64") {
    TEST_CASE("Encode / Decode round trip") {
        const std::string msg = "Hello, cpl! The quick brown fox jumps over the lazy dog.";
        const Stream in(msg.begin(), msg.end());
        const auto enc = Must(Base64::Base64Encode(in.data(), in.size()));
        const auto dec = Must(Base64::Base64Decode(enc.data()));
        REQUIRE_EQ(dec.size(), in.size());
        for (size_t i = 0; i < in.size(); ++i) {
            CHECK_EQ(dec[i], in[i]);
        }
    }

    TEST_CASE("Known vector") {
        // RFC 4648 §10 test vectors.
        const Stream f{'f'};
        const Stream fo{'f', 'o'};
        const Stream foo{'f', 'o', 'o'};
        const Stream foobar{'f', 'o', 'o', 'b', 'a', 'r'};
        CHECK_EQ(Must(Base64::Base64Encode(f.data(), f.size())), std::string("Zg=="));
        CHECK_EQ(Must(Base64::Base64Encode(fo.data(), fo.size())), std::string("Zm8="));
        CHECK_EQ(Must(Base64::Base64Encode(foo.data(), foo.size())), std::string("Zm9v"));
        CHECK_EQ(Must(Base64::Base64Encode(foobar.data(), foobar.size())), std::string("Zm9vYmFy"));
    }

    TEST_CASE("Url-safe round trip without padding") {
        const Stream in{0xfb, 0xff, 0xbf, 0x3f, 0x00, 0xff};
        const auto urlEnc = Must(Base64::UrlSafeBase64Encode(in));
        // url-safe must not contain '+' '/' or '='.
        CHECK(urlEnc.find('+') == std::string::npos);
        CHECK(urlEnc.find('/') == std::string::npos);
        CHECK(urlEnc.find('=') == std::string::npos);

        const auto dec = Must(Base64::UrlSafeBase64Decode(urlEnc.data()));
        REQUIRE_EQ(dec.size(), in.size());
        for (size_t i = 0; i < in.size(); ++i) {
            CHECK_EQ(dec[i], in[i]);
        }
    }

    TEST_CASE("Decode rejects invalid characters") {
        CHECK_FALSE(Base64::Base64Decode("!!!!").has_value());
        CHECK_FALSE(Base64::Base64Decode("Zg=").has_value()); // length not multiple of 4
    }
}

TEST_SUITE("codec::Length") {
    TEST_CASE("Encode / Decode round trip across boundaries") {
        const int64_t values[] = {
            0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536,
            1048576, 67108864, 1073741824
        };
        for (const auto v : values) {
            const auto enc = Must(Length::Encode(v));
            CHECK_FALSE(enc.empty());
            const auto dec = Must(Length::Decode(enc));
            const auto decoded = std::get<0>(dec);
            const auto nBytes = std::get<1>(dec);
            CHECK_EQ(decoded, v);
            CHECK_EQ(nBytes, static_cast<uint8_t>(enc.size()));
        }
    }

    TEST_CASE("Encode rejects negative and out-of-range") {
        CHECK_FALSE(Length::Encode(-1).has_value());
        // 1 << 42 is the documented maximum (exclusive).
        CHECK_FALSE(Length::Encode(static_cast<int64_t>(1) << 42).has_value());
    }

    TEST_CASE("Decode rejects empty and truncated") {
        CHECK_FALSE(Length::Decode(Stream{}).has_value());
        // Multi-byte header (0xC0 => 2-byte sequence) but no continuation byte.
        CHECK_FALSE(Length::Decode(Stream{0xC0}).has_value());
    }
}

TEST_SUITE("strings") {
    TEST_CASE("Format produces expected text") {
        CHECK_EQ(Must(Format("hello %d %s", 42, "world")), std::string("hello 42 world"));
        CHECK_EQ(Must(Format("%u-%u", 1u, 2u)), std::string("1-2"));
    }

    TEST_CASE("Format rejects null template") {
        CHECK_FALSE(Format(static_cast<const char *>(nullptr)).has_value());
    }

    TEST_CASE("Trim") {
        CHECK_EQ(Trim("  hello  "), std::string("hello"));
        CHECK_EQ(Trim("\t\nhello\r\n"), std::string("hello"));
        CHECK_EQ(Trim("hello"), std::string("hello"));
        // All-whitespace must collapse to empty, not return the whole string.
        CHECK_EQ(Trim("   \t\n  "), std::string(""));
        CHECK_EQ(Trim(""), std::string(""));
    }

    TEST_CASE("Split and Join") {
        const auto parts = Split("a,b,,c", ",");
        REQUIRE_EQ(parts.size(), 4u);
        CHECK_EQ(parts[0], std::string("a"));
        CHECK_EQ(parts[1], std::string("b"));
        CHECK_EQ(parts[2], std::string(""));
        CHECK_EQ(parts[3], std::string("c"));
        CHECK_EQ(Join(parts, ","), std::string("a,b,,c"));

        CHECK_EQ(Split("solo", ",").size(), 1u);
        CHECK_EQ(Join(std::vector<std::string>{"only"}, ","), std::string("only"));
        CHECK_EQ(Join(std::vector<std::string>{}, ","), std::string(""));
    }

    TEST_CASE("ReplaceAll") {
        CHECK_EQ(ReplaceAll("a.b.c", ".", "-"), std::string("a-b-c"));
        CHECK_EQ(ReplaceAll("nothing", "x", "y"), std::string("nothing"));
        // Empty `from` returns the original.
        CHECK_EQ(ReplaceAll("abc", "", "-"), std::string("abc"));
    }

    TEST_CASE("StartsWith / EndsWith") {
        CHECK(StartsWith("hello world", "hello"));
        CHECK_FALSE(StartsWith("hello world", "world"));
        CHECK(EndsWith("hello world", "world"));
        CHECK_FALSE(EndsWith("hello world", "hello"));
        CHECK_FALSE(StartsWith("ab", "abc"));
        CHECK_FALSE(EndsWith("ab", "abc"));
    }

    TEST_CASE("ToUpper / ToLower") {
        CHECK_EQ(ToUpper("Hello123"), std::string("HELLO123"));
        CHECK_EQ(ToLower("Hello123"), std::string("hello123"));
        CHECK_EQ(Upper('a'), 'A');
        CHECK_EQ(Upper('Z'), 'Z');
    }

    TEST_CASE("IsDigital") {
        CHECK(IsDigital("12345"));
        CHECK_FALSE(IsDigital("12a45"));
        CHECK(IsDigital(""));
    }

    TEST_CASE("StrInStr found and not-found") {
        CHECK(Must(StrInStr("Hello World", "world")) != nullptr); // case-insensitive
        CHECK(Must(StrInStr("Hello World", "WORLD")) != nullptr);
        // Not found must be an error, NOT a success holding nullptr.
        CHECK_FALSE(StrInStr("Hello World", "missing").has_value());
        CHECK_FALSE(StrInStr(nullptr, "x").has_value());
    }

    TEST_CASE("WString <-> UTF16LE bytes round trip") {
        const std::wstring ws = L"cpl\xc4e2\x6587"; // contains non-ASCII
        const Stream bytes = WStringToUTF16LEBytes(ws);
        const auto back = Must(UTF16LEBytesToWString(bytes));
        REQUIRE_EQ(back.size(), ws.size());
        for (size_t i = 0; i < ws.size(); ++i) {
            CHECK_EQ(back[i], ws[i]);
        }
    }

    TEST_CASE("UTF16LEBytesToWString rejects unaligned length") {
        const Stream bad{0x41, 0x00, 0x42}; // 3 bytes, not a multiple of sizeof(wchar_t)
        CHECK_FALSE(UTF16LEBytesToWString(bad).has_value());
    }
}
