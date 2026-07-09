// Tests for cpl::sys::file (GetFileSize / ReadFile).
//
// Covers win32/file.hpp, previously not exercised by any test. The public
// helpers GetFileSize and ReadFile are plain file I/O and fully testable
// against a temp file.
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/file.hpp"

#include <cstdio>
#include <fstream>
#include <string>

using namespace cpl;
using namespace cpl::sys::file;

namespace {
// Create a temp file with the given content; return its path.
static std::string WriteTempFile(const std::string &content) {
    char tmpPath[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tmpPath);
    char tmpFile[MAX_PATH]{};
    GetTempFileNameA(tmpPath, "cpl", 0, tmpFile);
    std::ofstream ofs(tmpFile, std::ios::binary);
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    ofs.close();
    return std::string(tmpFile);
}

static void RemoveTempFile(const std::string &path) {
    (void) DeleteFileA(path.c_str());
}
} // namespace

TEST_SUITE("sys::file") {
    TEST_CASE("GetFileSize reports correct size") {
        const std::string content = "hello cpl file test";
        const auto path = WriteTempFile(content);

        const auto size = GetFileSize(path);
        REQUIRE(size.has_value());
        CHECK_EQ(static_cast<size_t>(size.value()), content.size());

        RemoveTempFile(path);
    }

    TEST_CASE("GetFileSize rejects missing file") {
        const auto size = GetFileSize("Z:\\nonexistent\\cpl_test_no_such_file");
        CHECK_FALSE(size.has_value());
    }

    TEST_CASE("ReadFile returns exact content") {
        const std::string content = "The quick brown fox jumps over the lazy dog. 1234567890";
        const auto path = WriteTempFile(content);

        const auto data = ReadFile(path);
        REQUIRE(data.has_value());

        const Stream &buf = data.value();
        CHECK_EQ(buf.size(), content.size());
        CHECK(std::string(buf.begin(), buf.end()) == content);

        RemoveTempFile(path);
    }

    TEST_CASE("ReadFile handles empty file") {
        const auto path = WriteTempFile("");

        const auto data = ReadFile(path);
        // An empty file yields an empty stream (or an error depending on
        // impl); either is acceptable as long as it doesn't crash.
        if (data.has_value()) {
            CHECK_EQ(data.value().size(), 0u);
        }
        RemoveTempFile(path);
    }

    TEST_CASE("ReadFile rejects missing file") {
        const auto data = ReadFile("Z:\\nonexistent\\cpl_test_no_such_file");
        CHECK_FALSE(data.has_value());
    }
}
