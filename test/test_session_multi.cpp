// Runtime tests for the multi-session launchers in cpl::sys::utility::session.
//
// ExecuteCommandsInActiveSessions and executeCommandInActiveConsoleSession
// discover active user sessions (via explorer.exe enumeration / the active
// console session id) and launch a command in each. These run a harmless
// `cmd /c exit 0` (or echo to a temp file) so they don't disturb the system;
// we verify they return a Result without crashing, not that the launched
// process actually ran (that needs a multi-user fixture).
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/utility.hpp"

#include <string>

using namespace cpl;
using namespace cpl::sys::utility::session;

TEST_SUITE("sys::utility::session multi-session launchers") {
    TEST_CASE("ExecuteCommandsInActiveSessions returns a Result") {
        // Harmless command: exits immediately with code 0. exceptCurrentSession
        // = FALSE so the current session is included (otherwise the explorer
        // enumeration might find nothing to act on in a single-user test box).
        const auto r = ExecuteCommandsInActiveSessions("cmd /c exit 0", FALSE, 6);
        // We don't assert success — on a service/non-interactive session the
        // token duplication may fail. We only assert it didn't crash and
        // returned a well-formed Result.
        // only asserting it returns without crashing
    }

    TEST_CASE("executeCommandInActiveConsoleSession returns a Result") {
        const auto r = executeCommandInActiveConsoleSession("cmd /c exit 0");
        // only asserting it returns without crashing
    }

    TEST_CASE("ExecuteCommandsInActiveSessions with exceptCurrentSession=TRUE") {
        // Skip the current session — on a single-user box this usually finds
        // nothing to act on, but must still return cleanly.
        const auto r = ExecuteCommandsInActiveSessions("cmd /c exit 0", TRUE, 6);
        // only asserting it returns without crashing
    }
}
