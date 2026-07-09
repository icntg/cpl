cmake_minimum_required(VERSION 3.24)
project(cpl C CXX)

# ── 语言标准 ──────────────────────────────────────────────────────────────
# C++17: base.hpp 使用 inline 变量 (gDebug / exLoggerFunc)，C++11 无此特性。
# C11  : naion.h 为可移植 C，C11 兼容更好。
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── 编译选项 ──────────────────────────────────────────────────────────────
if(MSVC)
    # 源码统一 utf-8；禁用不安全的 CRT 警告与 min/max 宏。
    add_compile_options(/utf-8 /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS)
    # 静态链接 CRT，便于单文件分发与 XP 兼容。
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# ── 测试源 (platform-independent) ─────────────────────────────────────────
set(CPL_TEST_SOURCES
    test/entry.cpp
    test/test_net.cpp
    test/test_strings.cpp
    test/test_crypto.cpp
    test/test_naion.cpp
)

# naion 单头库实现 TU (STB 风格：恰好一个 TU 定义 NAION_IMPLEMENTATION)。
set(NAION_IMPL_SOURCE naion/naion_impl.cpp)

# ── libsodium (默认关闭) ──────────────────────────────────────────────────
# sodium.hpp 与其测试依赖外部 libsodium。需接入时通过 -DCPL_HAS_LIBSODIUM=ON
# 开启，并自行保证 libsodium 头文件/静态库可被找到。
option(CPL_HAS_LIBSODIUM "Enable libsodium-backed wrapper and tests" OFF)
if(CPL_HAS_LIBSODIUM)
    add_compile_definitions(CPL_HAS_LIBSODIUM=1)
    list(APPEND CPL_TEST_SOURCES
        test/test_libsodium.cpp
        test/test_naion_libsodium_interop.cpp
    )
endif()

# ── Windows 专有测试 ──────────────────────────────────────────────────────
# win32/utility 遗留层 Result-API 迁移进行中 (api.hpp/sys.hpp/utility/ 多文件深层重构)。
# 通过 -DCPL_BUILD_WIN32_TESTS=ON 纳入；默认关闭直至迁移完成。
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

# ── 构建可执行 ────────────────────────────────────────────────────────────
add_executable(cpl_test ${CPL_TEST_SOURCES} ${NAION_IMPL_SOURCE})
target_include_directories(cpl_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    # win32 层链接的导入库 (advapi32/psapi/userenv 已随 SDK 提供)。
    # 注意: ws2_32 等通过 cpl::sys::api 动态 LoadLibrary 加载, 不静态链接。
    target_link_libraries(cpl_test PRIVATE advapi32 psapi userenv)
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)

# ── CTest ─────────────────────────────────────────────────────────────────
enable_testing()
add_test(NAME cpl_test COMMAND cpl_test)
