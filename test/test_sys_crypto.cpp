// Tests for cpl::sys::crypto RNG providers (BCrypt/Rtl/Crypt/Unsafe).
//
// The providers are backed by the NEW api system (cpl::sys::api::API). Its
// singleton must be loaded first; entry.cpp's Win32APIInitializer calls
// API::Instance().Load() before any test runs, so the bcrypt/AdvAPI32 function
// pointers are populated by the time these cases execute. On older Windows
// (e.g. XP without bcrypt.dll) the bcrypt pointer is null and the providers
// rely on their internal fallback (CryptGenRandom); the tests therefore
// tolerate a null primary API by only asserting success + non-zero bytes, not
// which backend was actually used.
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/crypto.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace cpl;
using namespace cpl::sys::crypto;

// Helper: a buffer filled with a CSPRNG should contain some non-zero bytes.
// (We don't assert "all unique" — that is probabilistic and flaky for small
// sizes. Non-zero density is a strong, deterministic sanity signal.)
static bool HasEntropy(const std::vector<uint8_t> &buf) {
    return std::any_of(buf.begin(), buf.end(), [](uint8_t b) { return b != 0; });
}

TEST_SUITE("sys::crypto RandomProvider") {
    TEST_CASE("BCryptRandomProvider fills small buffer") {
        BCryptRandomProvider p{};
        std::vector<uint8_t> buf(32, 0);
        const auto r = p.Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        CHECK(HasEntropy(buf));
    }

    TEST_CASE("RtlRandomProvider fills small buffer") {
        RtlRandomProvider p{};
        std::vector<uint8_t> buf(32, 0);
        const auto r = p.Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        CHECK(HasEntropy(buf));
    }

    TEST_CASE("CryptRandomProvider fills small buffer") {
        CryptRandomProvider p{};
        std::vector<uint8_t> buf(32, 0);
        const auto r = p.Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        CHECK(HasEntropy(buf));
    }

    TEST_CASE("UnsafeRandomProvider fills small buffer") {
        UnsafeRandomProvider p{};
        std::vector<uint8_t> buf(32, 0);
        const auto r = p.Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        CHECK(HasEntropy(buf));
    }

    TEST_CASE("BCryptRandomProvider handles large (chunked) buffer") {
        BCryptRandomProvider p{};
        // 64 KiB exercises the DWORD-chunking loop (>0xFFFFFFFF is impractical,
        // but 64 KiB crosses the typical single-call path on some stacks).
        std::vector<uint8_t> buf(65536, 0);
        const auto r = p.Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        // For a 64 KiB CSPRNG fill, expect > 90% non-zero bytes.
        const auto nonZero = std::count_if(buf.begin(), buf.end(),
            [](uint8_t b) { return b != 0; });
        CHECK_GT(static_cast<size_t>(nonZero), buf.size() * 9 / 10);
    }

    TEST_CASE("CryptRandomProvider handles large (chunked) buffer") {
        CryptRandomProvider p{};
        std::vector<uint8_t> buf(65536, 0);
        const auto r = p.Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        const auto nonZero = std::count_if(buf.begin(), buf.end(),
            [](uint8_t b) { return b != 0; });
        CHECK_GT(static_cast<size_t>(nonZero), buf.size() * 9 / 10);
    }

    TEST_CASE("all providers reject null/zero-size") {
        BCryptRandomProvider b{};
        RtlRandomProvider r{};
        CryptRandomProvider c{};
        UnsafeRandomProvider u{};

        CHECK_FALSE(b.Rand(nullptr, 32).has_value());
        CHECK_FALSE(r.Rand(nullptr, 32).has_value());
        CHECK_FALSE(c.Rand(nullptr, 32).has_value());
        CHECK_FALSE(u.Rand(nullptr, 32).has_value());

        uint8_t dummy{};
        CHECK_FALSE(b.Rand(&dummy, 0).has_value());
        CHECK_FALSE(r.Rand(&dummy, 0).has_value());
        CHECK_FALSE(c.Rand(&dummy, 0).has_value());
        CHECK_FALSE(u.Rand(&dummy, 0).has_value());
    }

    TEST_CASE("providers are usable via cpl::crypto::IRandom base") {
        // Matches the ifw usage: unique_ptr<cpl::crypto::IRandom>.
        std::unique_ptr<cpl::crypto::IRandom> p = std::make_unique<BCryptRandomProvider>();
        std::vector<uint8_t> buf(64, 0);
        const auto r = p->Rand(buf.data(), buf.size());
        CHECK(r.has_value());
        CHECK(HasEntropy(buf));
    }

    TEST_CASE("repeated calls produce different output") {
        CryptRandomProvider p{};
        std::vector<uint8_t> a(16, 0);
        std::vector<uint8_t> b(16, 0);
        REQUIRE(p.Rand(a.data(), a.size()).has_value());
        REQUIRE(p.Rand(b.data(), b.size()).has_value());
        // Two independent CSPRNG draws of 16 bytes should differ.
        CHECK_NE(a, b);
    }
}
