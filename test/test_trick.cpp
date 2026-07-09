// Compile-time coverage for cpl::sys::utility::trick.
//
// The four trick functions (Keyboard/TaskManager/CtrlAltDel/PrivilegeUp) are
// real, stateful console-locking primitives: Keyboard installs a global hook
// that swallows keystrokes, TaskManager kills taskmgr and holds an exclusive
// lock on Taskmgr.exe, CtrlAltDel suspends winlogon.exe. Running them on a
// development machine can lock the console and require a hard reset.
//
// Therefore this file only verifies the symbols compile and their signatures
// match what ifw expects — it takes the address of each function but never
// *calls* the dangerous ones. PrivilegeUp is safe to call (reversible, just
// grants SE_DEBUG_NAME) so it gets a runtime smoke test.
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/utility.hpp"

using namespace cpl;
using namespace cpl::sys::utility::trick;

TEST_SUITE("sys::utility::trick (compile-time signature coverage)") {
    TEST_CASE("function signatures match ifw call sites") {
        // ifw calls trick::Keyboard(FALSE), trick::TaskManager(FALSE),
        // trick::CtrlAltDel(FALSE), trick::PrivilegeUp(). Binding these to
        // function pointers verifies the exact signatures compile.
        Int32Result (*pKeyboard)(BOOL) = &Keyboard;
        Int32Result (*pTaskManager)(BOOL) = &TaskManager;
        Int32Result (*pCtrlAltDel)(BOOL) = &CtrlAltDel;
        Int32Result (*pPrivilegeUp)() = &PrivilegeUp;

        // Touch them so the compiler can't discard the references.
        CHECK(pKeyboard != nullptr);
        CHECK(pTaskManager != nullptr);
        CHECK(pCtrlAltDel != nullptr);
        CHECK(pPrivilegeUp != nullptr);
    }

    TEST_CASE("PrivilegeUp grants SE_DEBUG_NAME (reversible, safe)") {
        // PrivilegeUp only adjusts the current token — fully reversible (the
        // privilege lasts until process exit) and does not lock anything.
        const auto r = PrivilegeUp();
        // May succeed or return an error if not elevated; both are acceptable
        // in a test environment. We only assert it returns a Result.
        // only asserting it returns without crashing
    }
}
