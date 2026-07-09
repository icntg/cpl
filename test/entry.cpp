// 统一测试入口
//
// libsodium 默认不接入 (CPL_HAS_LIBSODIUM 关闭)；naion 使用内建系统 RNG
// (CryptGenRandom / getrandom / urandom)。
//
// Windows 专有测试 (test_win32_utility) 需要在测试前加载 cpl::sys::api 动态
// 模块表；该初始化随 CPL_BUILD_WIN32_TESTS 一并开启。api.hpp 必须在全局作用域
// include (不能在匿名 namespace 内)，否则其内部的 namespace cpl 会被困在匿名
// namespace 中。
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../vendor/doctest/doctest.hpp"

#include "../naion.hpp"

#if defined(_WIN32) && defined(CPL_BUILD_WIN32_TESTS)
#include "../win32/api.hpp"
#endif

namespace {
struct NaionInitializer {
    NaionInitializer() {
        // naion_init 幂等；naion_get_random_provider() 在未设置自定义 provider
        // 时返回内建系统 provider，无需额外注册。
        (void)cpl::naion::Init();
    }
};
static NaionInitializer g_naionInitializer{};

#if defined(_WIN32) && defined(CPL_BUILD_WIN32_TESTS)
struct Win32APIInitializer {
    Win32APIInitializer() {
        // 加载动态模块表 (NTDLL/Kernel32/PsAPI/AdvAPI32/...)。失败不致命：
        // 个别模块在特定 Windows 版本上可能不可用，相关测试会自行跳过。
        (void)cpl::sys::api::API::Instance().Load();
    }
};
static Win32APIInitializer g_win32ApiInitializer{};
#endif
} // namespace
