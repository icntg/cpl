#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/utility.hpp"

#include <fstream>

using namespace cpl;
using namespace cpl::sys::utility;
using namespace cpl::sys::utility::process;
using namespace cpl::sys::utility::path;
using namespace cpl::sys::utility::session;

template <typename T>
static T Must(Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

static INT32 MustCode(Int32Result r) {
    REQUIRE(r.has_value());
    return r.value();
}

TEST_SUITE("win32 utility basic") {
    TEST_CASE("service/admin probes return Result<bool>") {
        CHECK(IsLikelyRunningAsService().has_value());
        CHECK(IsAdministrator().has_value());
    }

    TEST_CASE("computer names has known keys") {
        const auto names = GetComputerNames();
        CHECK_GE(names.size(), 1U);
        CHECK(names.count(static_cast<int>(COMPUTER_NAME_FORMAT::ComputerNameNetBIOS)) > 0U);
    }

    TEST_CASE("current user and session return valid values") {
        const auto user = Must(GetCurrentUser());
        CHECK_FALSE(user.empty());

        const auto sid = Must(GetCurrentSessionId());
        CHECK_NE(sid, 0xFFFFFFFFu);
    }

    TEST_CASE("windows version probe works") {
        const auto ver = Must(GetWindowsVersion());
        CHECK_GE(ver->dwMajorVersion, 5u);
    }

    TEST_CASE("screen size probe returns positive values") {
        const auto screen = Must(GetScreenSize());
        const auto x = std::get<0>(screen);
        const auto y = std::get<1>(screen);
        CHECK_GT(x, 0u);
        CHECK_GT(y, 0u);
    }

    TEST_CASE("machine identifiers are 16 bytes") {
        const auto guid = Must(GetSystemGUID());
        const auto hwid = Must(GetHardwareUUID());
        CHECK_EQ(guid.size(), 16U);
        CHECK_EQ(hwid.size(), 16U);
    }

    TEST_CASE("user sid returns SID-like string") {
        const auto sid = Must(GetUserSID());
        CHECK_GE(sid.size(), 4U);
        CHECK_EQ(sid.rfind("S-", 0), 0U);
    }
}

TEST_SUITE("win32 process/path") {
    TEST_CASE("parent pid and process path for current process") {
        const auto currentPid = GetCurrentProcessId();

        const auto parentPid = Must(GetParentPID(currentPid));
        CHECK_GT(parentPid, 0u);

        const auto exePath = Must(GetProcessPath(currentPid));
        CHECK_FALSE(exePath.empty());
        CHECK(exePath.find(".exe") != std::string::npos);
    }

    TEST_CASE("invalid pid parent query fails") {
        CHECK_FALSE(GetParentPID(0).has_value());
    }

    TEST_CASE("enumerate processes validates callback args") {
        std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> empty;
        const auto rc = MustCode(EnumerateProcesses(empty));
        CHECK_EQ(rc, ERROR_EMPTY);
    }

    TEST_CASE("current path/current dir return expected strings") {
        const auto exePath = Must(GetCurrentPath());
        const auto dirPath = Must(GetCurrentDir());
        CHECK_FALSE(exePath.empty());
        CHECK_FALSE(dirPath.empty());
    }
}

TEST_SUITE("win32 directory and command") {
    TEST_CASE("CreateDirectoryRecursive handles empty and normal input") {
        const auto baseDir = Must(GetCurrentDir()) + "\\test_win32_utility_new";
        const auto testDir = baseDir + "\\a\\b\\c";

        const auto cleanup = "rmdir /s /q \"" + baseDir + "\" 2>nul";
        (void) system(cleanup.c_str());

        CHECK_EQ(MustCode(CreateDirectoryRecursive("")), ERROR_EMPTY);
        CHECK_EQ(MustCode(CreateDirectoryRecursive(testDir)), ERROR_SUCCESS);
        CHECK_EQ(MustCode(CreateDirectoryRecursive(testDir)), ERROR_SUCCESS);

        (void) system(cleanup.c_str());
    }

    TEST_CASE("RunOnlyOnce returns success or already-exists") {
        const auto r0 = MustCode(RunOnlyOnce(0, "ut_run_only_once_user"));
        const auto r1 = MustCode(RunOnlyOnce(1, "ut_run_only_once_global"));
        CHECK((r0 == ERROR_SUCCESS || r0 == ERROR_ALREADY_EXISTS));
        CHECK((r1 == ERROR_SUCCESS || r1 == ERROR_ALREADY_EXISTS));
    }

    TEST_CASE("ExecuteCommandInCurrentSession basic command") {
        const auto tempPath = std::string(GetSystemTempPath()) + "cpl_test_echo.txt";
        const auto cmd = "cmd /c echo hello>" + tempPath;

        CHECK_EQ(MustCode(ExecuteCommandInCurrentSession(cmd)), ERROR_SUCCESS);
    }
}
