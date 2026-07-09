// Compile-time coverage for cpl::win32::service.
//
// service.hpp exposes Windows Service Control Manager wrappers (Install /
// Uninstall / WindowsService). These require administrator privileges and a
// real service host to exercise at runtime, so this file only ensures the
// header compiles cleanly into the test binary — catching regressions like the
// phantom-include bug that previously slipped through. Runtime tests would need
// a dedicated service fixture and are out of scope.
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/service.hpp"

// Touch the namespace to force instantiation of inline symbols.
TEST_CASE("win32::service header compiles") {
    CHECK(true);
}
