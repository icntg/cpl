// 统一测试入口
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../vendor/doctest/doctest.hpp"

// 初始化 libsodium
#define SODIUM_STATIC
#include "../vendor/jedisct1/libsodium/sodium.h"

#include "../win32/api.hpp"

// 测试前初始化 libsodium
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

// 全局初始化对象，在程序启动时初始化
static SodiumInitializer sodiumInitializer{};
static Win32APIInitializer win32APIInitializer{};
// doctest 配置选项
// 可以在这里添加自定义配置，例如：
// DOCTEST_CONFIG_SUPER_FAST_ASSERTS
// DOCTEST_CONFIG_NO_EXCEPTIONS
// DOCTEST_CONFIG_TCHAR_CHARARGS