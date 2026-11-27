cmake_minimum_required(VERSION 3.24)

# Export the compilation database for the clangd/Serena code index.
# Note: only effective with the Makefile/Ninja generators; VS generators ignore it.
# Must be set before project() so that it takes effect on the first configure.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(cpl C CXX)

# ── Language standard ─────────────────────────────────────────────────────
# C++17: base.hpp uses inline variables (gDebug / exLoggerFunc), which C++11 lacks.
# C11  : naion.h is portable C; C11 has better compatibility.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Compilation options ───────────────────────────────────────────────────
if(MSVC)
    # Sources use utf-8 throughout; disable the unsafe-CRT warnings and the min/max macros.
    add_compile_options(/utf-8 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS)
    # Statically link the CRT for single-file distribution and XP compatibility.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# ── Test sources (platform-independent) ───────────────────────────────────
set(CPL_TEST_SOURCES
    test/entry.cpp
    test/test_net.cpp
    test/test_strings.cpp
    test/test_crypto.cpp
    test/test_naion.cpp
    test/test_plugins.cpp
    test/test_plugins_package.cpp
    test/test_plugin_loader.cpp
    test/test_identity.cpp
    test/test_cert.cpp
    test/test_warnwire.cpp
)

# Implementation TU of the naion single-header library (STB style: exactly one TU defines NAION_IMPLEMENTATION).
set(NAION_IMPL_SOURCE naion/naion_impl.cpp)

# ── POSIX-specific tests ──────────────────────────────────────────────────
# posix/network.hpp needs POSIX sockets, which the toolset of the Windows client does not have.
if(NOT WIN32)
    list(APPEND CPL_TEST_SOURCES
        test/test_posix_network.cpp
    )
endif()

# ── libsodium (off by default) ────────────────────────────────────────────
# sodium.hpp and its tests depend on external libsodium. To enable them, turn it on with -DCPL_HAS_LIBSODIUM=ON
# and make sure the libsodium headers/static libraries can be found yourself.
option(CPL_HAS_LIBSODIUM "Enable libsodium-backed wrapper and tests" OFF)
if(CPL_HAS_LIBSODIUM)
    add_compile_definitions(CPL_HAS_LIBSODIUM=1)
    list(APPEND CPL_TEST_SOURCES
        test/test_libsodium.cpp
        test/test_naion_libsodium_interop.cpp
    )
endif()

# ── Windows-specific tests ────────────────────────────────────────────────
# The Result-API migration of the legacy win32/utility layer is in progress (deep multi-file refactor of api.hpp/sys.hpp/utility/).
# Include them with -DCPL_BUILD_WIN32_TESTS=ON; off by default until the migration is complete.
option(CPL_BUILD_WIN32_TESTS "Build win32/utility tests (Windows only)" OFF)
if(CPL_BUILD_WIN32_TESTS AND WIN32)
    add_compile_definitions(CPL_BUILD_WIN32_TESTS=1)
    list(APPEND CPL_TEST_SOURCES
        test/test_win32_utility.cpp
        test/test_sys_crypto.cpp
        test/test_sys_network.cpp
        test/test_thread.cpp
        test/test_file.cpp
        test/test_service.cpp
        test/test_trick.cpp
        test/test_session_multi.cpp)
endif()

# ── Build the executable ──────────────────────────────────────────────────
add_executable(cpl_test ${CPL_TEST_SOURCES} ${NAION_IMPL_SOURCE})
target_include_directories(cpl_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    # Import libraries linked by the win32 layer (advapi32/psapi/userenv ship with the SDK).
    # Note: ws2_32 etc. are loaded dynamically via LoadLibrary through cpl::sys::api, not linked statically.
    target_link_libraries(cpl_test PRIVATE advapi32 psapi userenv)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)

# ── CTest ─────────────────────────────────────────────────────────────────
enable_testing()
add_test(NAME cpl_test COMMAND cpl_test)
