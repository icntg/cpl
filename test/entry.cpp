// Unified test entry
//
// libsodium is not wired in by default (CPL_HAS_LIBSODIUM off); naion uses the built-in system RNG
// (CryptGenRandom / getrandom / urandom).
//
// The Windows-specific tests (test_win32_utility) need the cpl::sys::api dynamic module table loaded
// before the tests run; this initialization is switched on together with CPL_BUILD_WIN32_TESTS.
// api.hpp must be included at global scope (not inside an anonymous namespace), otherwise the namespace cpl
// defined inside it would be trapped in the anonymous namespace.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../vendor/doctest/doctest.hpp"

#include "../naion.hpp"

#if defined(_WIN32) && defined(CPL_BUILD_WIN32_TESTS)
#include "../win32/api.hpp"
#endif

namespace {
struct NaionInitializer {
    NaionInitializer() {
        // naion_init is idempotent; naion_get_random_provider() returns the built-in system provider
        // when no custom provider is set, so no extra registration is needed.
        (void)cpl::naion::Init();
    }
};
static NaionInitializer g_naionInitializer{};

#if defined(_WIN32) && defined(CPL_BUILD_WIN32_TESTS)
struct Win32APIInitializer {
    Win32APIInitializer() {
        // Load the dynamic module table (NTDLL/Kernel32/PsAPI/AdvAPI32/...). Failure is not fatal:
        // individual modules may be unavailable on specific Windows versions, and the related tests skip themselves.
        (void)cpl::sys::api::API::Instance().Load();
    }
};
static Win32APIInitializer g_win32ApiInitializer{};
#endif
} // namespace
