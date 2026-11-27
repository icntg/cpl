// Unified test entry
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../vendor/doctest/doctest.hpp"

// Initialize libsodium
#define SODIUM_STATIC
#include "../vendor/jedisct1/libsodium/sodium.h"

#include "../win32/api.hpp"

// Initialize libsodium before the tests
struct SodiumInitializer {
    SodiumInitializer() {
        if (sodium_init() < 0) {
            std::cerr << "Error: Failed to initialize libsodium" << std::endl;
            std::exit(1);
        }
    }
};

struct Win32APIInitializer {
    Win32APIInitializer() {
        cpl::sys::api::API::Instance().Load();
        //if (0!=cpl::sys::api::API::Instance().Load()) {
        //    std::cerr << "Error: Failed to initialize API" << std::endl;
        //    std::exit(1);
        //}
    }
};

// Global initialization objects, initialized at program startup
static SodiumInitializer sodiumInitializer{};
static Win32APIInitializer win32APIInitializer{};
// doctest configuration options
// Custom configuration can be added here, for example:
// DOCTEST_CONFIG_SUPER_FAST_ASSERTS
// DOCTEST_CONFIG_NO_EXCEPTIONS
// DOCTEST_CONFIG_TCHAR_CHARARGS