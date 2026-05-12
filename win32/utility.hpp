#pragma once

#include <vector>
#include <unordered_map>
#include "../base.hpp"
#include "api.hpp"
#include "file.hpp"

namespace cpl {
    namespace sys {
        namespace utility {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x16) << 32;
                static constexpr cpl::Error::CodeDef CreateMutexA_ = {base | 0x1};
                static constexpr cpl::Error::CodeDef GetTokenInformation_ = {base | 0x2};
                static constexpr cpl::Error::CodeDef CreateDirectoryA_ = {base | 0x3};
                static constexpr cpl::Error::CodeDef EnumerateProcesses_ = {base | 0x4};
            };

            // inline std::string ToErrorText(const Result<std::string> &msg) {
            //     return msg.value_or("[X] generate error message error" CPL_FILE_AND_LINE);
            // }
            //
            // inline std::string ToErrorText(const std::string &msg) {
            //     return msg.empty() ? std::string{"[X] unknown error" CPL_FILE_AND_LINE} : msg;
            // }
            //
            // inline std::string ToErrorText(const char *msg) {
            //     if (msg == nullptr || msg[0] == '\0') {
            //         return "[X] unknown error" CPL_FILE_AND_LINE;
            //     }
            //     return msg;
            // }

            // #define TRW_EXC(excType, appCode, errVal, msg) \
            //             return cpl::Err(cpl::Error( \
            //                 (static_cast<int64_t>(errVal) == static_cast<int64_t>(ERROR_API_UNAVAILABLE)) \
            //                     ? cpl::sys::utility::Errors::APIUnavailable \
            //                     : cpl::sys::utility::Errors::Win32CallFailed, \
            //                 cpl::sys::utility::ToErrorText(msg).c_str() \
            //             ))

            inline Result<bool> IsLikelyRunningAsService() {
                // 方法 A：Session 0 + LocalSystem
                DWORD sessionId = 0;
                const auto *api = &cpl::sys::api::API::Instance();
                if (api && api->Kernel32.ProcessIdToSessionId) {
                    const auto r00 = api->Kernel32.ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
                    if (!r00) {
                        return APICallingError("api->Kernel32.ProcessIdToSessionId", CPL_FILE_AND_LINE);
                    }
                } else {
                    // XP fallback: keep the heuristic usable even when ProcessIdToSessionId is unavailable.
                    sessionId = 0;
                }
                HANDLE hToken{};
                const auto defer = cpl::base::MakeDefer([&]() {
                    CloseHandle(hToken);
                });
                const auto r01 = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
                if (!r01) {
                    return APICallingError("OpenProcessToken", CPL_FILE_AND_LINE);
                }
                char sidBuffer[256]{};
                DWORD sidSize = sizeof(sidBuffer);
                const auto r02 = GetTokenInformation(hToken, TokenUser, sidBuffer, sidSize, &sidSize);
                if (!r02) {
                    return APICallingError("GetTokenInformation", CPL_FILE_AND_LINE);
                }
                const auto pUser = reinterpret_cast<PTOKEN_USER>(sidBuffer);
                // LocalSystem SID: S-1-5-18
                if (sessionId == 0 &&
                    IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid)) {
                    return true;
                }
                return false;
            }


            inline std::unordered_map<int, std::string> GetComputerNames() {
                std::unordered_map<int, std::string> ComputerNames = {
                    {COMPUTER_NAME_FORMAT::ComputerNameNetBIOS, "ComputerNameNetBIOS"},
                    {COMPUTER_NAME_FORMAT::ComputerNameDnsHostname, "ComputerNameDnsHostname"},
                    {COMPUTER_NAME_FORMAT::ComputerNameDnsDomain, "ComputerNameDnsDomain"},
                    {COMPUTER_NAME_FORMAT::ComputerNameDnsFullyQualified, "ComputerNameDnsFullyQualified"},
                    {COMPUTER_NAME_FORMAT::ComputerNamePhysicalNetBIOS, "ComputerNamePhysicalNetBIOS"},
                    {COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsHostname, "ComputerNamePhysicalDnsHostname"},
                    {COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsDomain, "ComputerNamePhysicalDnsDomain"},
                    {
                        COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsFullyQualified,
                        "ComputerNamePhysicalDnsFullyQualified"
                    },
                    {COMPUTER_NAME_FORMAT::ComputerNameMax, "ComputerNameMax"},
                };
                const auto getComputerName = [&](const COMPUTER_NAME_FORMAT &fmt) {
                    char buffer[MAX_PATH << 2u];
                    bzero(buffer, sizeof(buffer));
                    DWORD nBytes = sizeof(buffer);
                    const auto r00 = GetComputerNameExA(fmt, buffer, &nBytes);
                    if (!r00) {
                        ComputerNames[static_cast<int>(fmt)] = "";
                        const auto e = GetLastError();
                        const int idx = fmt;

                        const auto es = strings::Format(
                            "[X] GetComputerNameEx [%s] failed [0x%lx][%s]",
                            ComputerNames.at(idx).data(), e, FormatError(e).data());
                    }
                    ComputerNames.at(fmt) = buffer;
                };

                for (int i = COMPUTER_NAME_FORMAT::ComputerNameNetBIOS; i <= COMPUTER_NAME_FORMAT::ComputerNameMax; i
                     ++) {
                    getComputerName(static_cast<COMPUTER_NAME_FORMAT>(i));
                }
                return ComputerNames;
            }

            inline Result<std::string> GetCurrentUser() {
                std::string username{};
                DWORD size = BUFSIZ << 2u;
                username.reserve(size);
                username.resize(size);
                const auto r00 = GetUserNameA(&username[0], &size);
                if (!r00) {
                    return APICallingError("GetUserNameA", CPL_FILE_AND_LINE);
                }
                username.resize(size);
                return username;
            }

            inline Result<std::unique_ptr<RTL_OSVERSIONINFOW> > GetWindowsVersion() {
                const auto *api = &cpl::sys::api::API::Instance();
                if (!api || !api->NtDLL.RtlGetVersion) {
                    return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                }
                auto osVersionInfo = std::make_unique<RTL_OSVERSIONINFOW>();
                osVersionInfo->dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
                const auto r00 = api->NtDLL.RtlGetVersion(osVersionInfo.get());
                if (ERROR_SUCCESS != r00) {
                    return APICallingError("api->NtDLL.RtlGetVersion", CPL_FILE_AND_LINE);
                }
                return std::move(osVersionInfo);
            }

            inline Result<DWORD> GetCurrentSessionId() {
                const auto *api = &cpl::sys::api::API::Instance();
                if (!api || !api->Kernel32.ProcessIdToSessionId) {
                    return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                }
                DWORD sessionId = 0xffffffff;
                const auto r00 = api->Kernel32.ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
                if (!r00) {
                    return APICallingError("api->Kernel32.ProcessIdToSessionId", CPL_FILE_AND_LINE);
                }
                return sessionId;
            }

            /**
             * @brief 确保程序单实例运行
             *
             * 通过创建命名互斥体实现进程单实例控制。
             * - 若互斥体不存在，则创建成功，表示当前是首个实例
             * - 若互斥体已存在，则返回错误，表示已有实例在运行
             *
             * @param scope 互斥体作用域：
             *              - 0: 当前用户会话级别，仅当前用户受限制
             *              - 1: 全局级别，跨用户会话生效（需管理员权限）
             * @param name  互斥体名称，若为空则使用默认名称 "cpl_sys_run_only_once"
             *
             * @return Int32Result
             *         - 成功: 返回 ERROR_SUCCESS (0)，表示当前是首个实例，可继续运行
             *         - 失败: 返回错误状态，包含错误码 Errors::CreateMutexA_ (0x1600000001)
             *                和错误信息，表示已有实例运行，不应继续启动
             *
             * @note 全局作用域(scope=1)在 Windows 终端服务或多个会话环境中有效
             * @note 虽然互斥体创建成功（句柄有效），但 GetLastError() 返回 ERROR_ALREADY_EXISTS (183)
             *       表示打开的是已存在的互斥体而非新创建，本函数将此情况视为错误返回
             * @see https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa
             *
             * @example
             * @code
             * // 当前用户单实例
             * auto result = RunOnlyOnce(0, "my_app_instance");
             * if (!result) {
             *     // 已有实例运行，退出
             *     return 1;
             * }
             * // 继续执行主程序逻辑
             *
             * // 全局单实例
             * auto result = RunOnlyOnce(1, "my_app_instance_global");
             * @endcode
             */
            inline Int32Result RunOnlyOnce(const int scope = 0, const std::string &name = "") {
                std::string mutexName = name.empty() ? "cpl_sys_run_only_once" : name;
                if (scope == 1) {
                    mutexName = "Global\\" + mutexName;
                }
                const auto hMutex = ::CreateMutexA(nullptr, TRUE, mutexName.c_str());
                if (hMutex == nullptr) {
                    return APICallingError("CreateMutexA", CPL_FILE_AND_LINE);
                }
                const auto lastError = GetLastError();
                if (lastError == ERROR_ALREADY_EXISTS) {
                    auto es = cpl::strings::Format(
                        "[X] %s failed 0x[%lx][%s] %s",
                        "CreateMutexA",
                        lastError,
                        cpl::sys::FormatError(lastError).data(),
                        CPL_FILE_AND_LINE
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return Err(Errors::CreateMutexA_, es.value<>().data());
                }
                return ERROR_SUCCESS;
            }

            // 检测管理员权限
            inline Result<bool> IsAdministrator() {
                SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
                PSID adminGroup = nullptr;
                BOOL isMember = FALSE;

                const auto defer = base::MakeDefer([&]() {
                    if (adminGroup != nullptr) {
                        FreeSid(adminGroup);
                        adminGroup = nullptr;
                    }
                });

                const auto r00 = AllocateAndInitializeSid(
                    &ntAuthority,
                    2,
                    SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_ADMINS,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    &adminGroup
                );
                if (!r00) {
                    return APICallingError("AllocateAndInitializeSid", CPL_FILE_AND_LINE);
                }

                const auto r01 = CheckTokenMembership(nullptr, adminGroup, &isMember);
                if (!r01) {
                    return APICallingError("CheckTokenMembership", CPL_FILE_AND_LINE);
                }

                return isMember != FALSE;
            }

            inline Result<std::tuple<DWORD, DWORD> > GetScreenSize() {
                DWORD cxPhysical = 0, cyPhysical = 0, cxLogical = 0, cyLogical = 0;
                double horizontalScale = 0, verticalScale = 0;
                MONITORINFOEX miEx{};
                DEVMODE dm{};

                // 获取窗口当前显示的监视器
                const auto hWnd = GetDesktopWindow(); //根据需要可以替换成自己程序的句柄
                if (nullptr == hWnd) {
                    return APICallingError("GetDesktopWindow", CPL_FILE_AND_LINE);
                }
                const auto hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
                if (nullptr == hMonitor) {
                    // return static_cast<INT32>(GetLastError());
                    return APICallingError("MonitorFromWindow", CPL_FILE_AND_LINE);
                }

                // 获取监视器逻辑宽度与高度

                miEx.cbSize = sizeof(miEx);
                GetMonitorInfoA(hMonitor, &miEx);
                cxLogical = miEx.rcMonitor.right - miEx.rcMonitor.left;
                cyLogical = miEx.rcMonitor.bottom - miEx.rcMonitor.top;

                // 获取监视器物理宽度与高度

                dm.dmSize = sizeof(dm);
                dm.dmDriverExtra = 0;
                EnumDisplaySettingsA(miEx.szDevice, ENUM_CURRENT_SETTINGS, &dm);
                cxPhysical = dm.dmPelsWidth;
                cyPhysical = dm.dmPelsHeight;

                //缩放比例计算
                horizontalScale = static_cast<double>(cxPhysical) / static_cast<double>(cxLogical);
                verticalScale = static_cast<double>(cyPhysical) / static_cast<double>(cyLogical);
                const auto x = cxLogical;
                const auto y = cyLogical;
                return std::tuple<DWORD, DWORD>{x, y};
            }

            // inline INT32 GetScreenSize(_Out_ DWORD &x, _Out_ DWORD &y) {
            //     auto ret = GetScreenSize();
            //     if (!ret) {
            //         return static_cast<INT32>(ret.error().Code.i64);
            //     }
            //     const auto t = ret.value<>();
            //     x = std::get<0>(t);
            //     y = std::get<1>(t);
            //     return ERROR_SUCCESS;
            // }

            inline Result<Stream> GetSystemGUID() {
                Stream ret(16);
                HKEY hKey{};

                const auto defer = base::MakeDefer([&]() {
                    if (hKey) {
                        RegCloseKey(hKey);
                        hKey = nullptr;
                    }
                });

                // 尝试打开注册表键 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
                const auto keyName = "SOFTWARE\\Microsoft\\Cryptography";
                const auto r0 = RegOpenKeyExA(
                    HKEY_LOCAL_MACHINE,
                    keyName,
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &hKey
                );

                if (r0 != ERROR_SUCCESS) {
                    // 注册表键打开失败，返回全零 GUID
                    // 可能的原因：权限不足、容器环境、虚拟机等
                    return ret;
                }

                // 读取 MachineGuid 值
                {
                    DWORD type = 0;
                    DWORD bufferSize = 0;
                    const auto valueName = "MachineGuid";

                    // 第一次调用：获取所需缓冲区大小
                    const auto r00 = RegQueryValueExA(
                        hKey,
                        valueName,
                        nullptr,
                        &type,
                        nullptr,
                        &bufferSize
                    );

                    if (r00 == ERROR_FILE_NOT_FOUND) {
                        // 值不存在，返回全零 GUID
                        return ret;
                    }

                    if (r00 != ERROR_SUCCESS) {
                        // 其他错误，返回全零 GUID
                        return ret;
                    }

                    // 分配足够的缓冲区
                    std::vector<char> w(bufferSize + 1, 0);

                    // 第二次调用：读取数据
                    const auto r01 = RegQueryValueExA(
                        hKey,
                        valueName,
                        nullptr,
                        &type,
                        reinterpret_cast<LPBYTE>(w.data()),
                        &bufferSize
                    );

                    if (r01 != ERROR_SUCCESS) {
                        // 读取失败，返回全零 GUID
                        return ret;
                    }

                    // 转换 GUID 字符串
                    {
                        // 移除 GUID 字符串中的连字符 '-'，得到纯十六进制字符串
                        std::string guid{};
                        for (const auto &c: w) {
                            if (c != '-' && c != '\0') {
                                guid.push_back(c);
                            }
                        }

                        // 如果成功转换，使用结果；否则返回全零
                        auto rHex = codec::Hex::UnHexlify(guid.data());
                        if (!rHex) {
                            return Err(rHex.error().Append(CPL_FILE_AND_LINE));
                        }

                        ret = rHex.value<>();
                    }
                }

                return ret;
            }

            inline Result<Stream> GetHardwareUUID() {
                Stream ret(16, 0);

                HANDLE hReadPipe = nullptr;
                HANDLE hWritePipe = nullptr;
                PROCESS_INFORMATION pi{};

                const auto defer = base::MakeDefer([&]() {
                    if (!pi.hThread) {
                        CloseHandle(pi.hThread);
                        pi.hThread = nullptr;
                    }
                    if (!pi.hProcess) {
                        CloseHandle(pi.hProcess);
                        pi.hProcess = nullptr;
                    }
                    if (nullptr != hReadPipe) {
                        CloseHandle(hReadPipe);
                        hReadPipe = nullptr;
                    }
                    if (nullptr != hWritePipe) {
                        CloseHandle(hWritePipe);
                        hWritePipe = nullptr;
                    }
                });

                // 构造 PowerShell 命令
                const std::string command =
                        R"(powershell.exe -NoProfile -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID")";

                SECURITY_ATTRIBUTES sa{};
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.bInheritHandle = TRUE;
                sa.lpSecurityDescriptor = nullptr;


                // 创建匿名管道用于读取输出
                {
                    const auto r0 = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
                    if (!r0) {
                        return APICallingError("CreatePipe", CPL_FILE_AND_LINE);
                    }
                }

                // 设置读取句柄不继承
                {
                    const auto r0 = SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
                    if (!r0) {
                        return APICallingError("SetHandleInformation", CPL_FILE_AND_LINE);
                    }
                }

                // 启动 PowerShell 进程
                {
                    STARTUPINFOA si{};

                    si.cb = sizeof(si);
                    si.hStdError = hWritePipe;
                    si.hStdOutput = hWritePipe;
                    si.dwFlags |= STARTF_USESTDHANDLES;

                    // 创建命令的副本（CreateProcess会修改它）
                    std::vector<char> cmdLine(command.begin(), command.end());
                    cmdLine.push_back('\0');

                    const auto r0 = CreateProcessA(
                        nullptr,
                        cmdLine.data(),
                        nullptr,
                        nullptr,
                        TRUE,
                        CREATE_NO_WINDOW,
                        nullptr,
                        nullptr,
                        &si,
                        &pi
                    );

                    if (!r0) {
                        return APICallingError("CreateProcessA", CPL_FILE_AND_LINE);
                    }

                    // 关闭写入端
                    CloseHandle(hWritePipe);
                    hWritePipe = nullptr;

                    // 等待进程完成
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hProcess);
                    pi.hProcess = nullptr;
                    CloseHandle(pi.hThread);
                    pi.hThread = nullptr;

                    // 读取输出
                    DWORD bytesRead = 0;
                    CHAR buffer[1024]{};
                    const auto r1 = ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);

                    if (!r1 || bytesRead <= 0) {
                        return APICallingError("ReadFile", CPL_FILE_AND_LINE);
                    }


                    buffer[bytesRead] = '\0';

                    // 转换为 string 并处理
                    std::string uuidStr(buffer);

                    // 移除空白字符（包括换行符）
                    std::string trimmedUuid{};
                    for (const char c: uuidStr) {
                        if (!isspace(static_cast<unsigned char>(c))) {
                            trimmedUuid += c;
                        }
                    }

                    // 移除 UUID 字符串中的连字符 '-'，得到纯十六进制字符串
                    {
                        std::string b{};
                        b.reserve(trimmedUuid.length());

                        for (const char c: trimmedUuid) {
                            if (c != '-') {
                                b.push_back(c);
                            }
                        }
                        auto r00 = codec::Hex::UnHexlify(b);
                        if (!r00) {
                            return MakeErr(Error::InvalidArgument, (b + CPL_FILE_AND_LINE));
                        }
                        ret = r00.value();
                    }
                }
                return ret;
            }

            inline Result<std::string> GetUserSID() {
                const auto &api = cpl::sys::api::API::Instance();
                if (!api.AdvAPI32.ConvertStringSidToSidA) {
                    return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                }
                HANDLE hToken = nullptr;
                LPSTR sidString = nullptr;

                const auto defer = base::MakeDefer([&]() {
                    if (hToken) {
                        CloseHandle(hToken);
                        hToken = nullptr;
                    }
                    if (sidString) {
                        LocalFree(sidString);
                        sidString = nullptr;
                    }
                });

                // 打开当前进程的令牌
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                    return APICallingError("OpenProcessToken", CPL_FILE_AND_LINE);
                }

                // 获取用户SID信息
                DWORD tokenInfoSize = 0;
                GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoSize);

                if (tokenInfoSize == 0) {
                    return APICallingError("GetTokenInformation", CPL_FILE_AND_LINE);
                }

                std::vector<char> tokenInfo(tokenInfoSize);
                const auto r01 = GetTokenInformation(hToken, TokenUser, tokenInfo.data(), tokenInfoSize,
                                                     &tokenInfoSize);
                if (!r01) {
                    return APICallingError("GetTokenInformation", CPL_FILE_AND_LINE);
                }

                // 获取SID字符串
                const auto pTokenUser = reinterpret_cast<PTOKEN_USER>(tokenInfo.data());

                if (!api.AdvAPI32.ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
                    return APICallingError("api.AdvAPI32.ConvertSidToStringSidA", CPL_FILE_AND_LINE);
                }
                // 转换为string并移除连字符
                const auto sidStr = std::string(sidString);
                return sidStr;
            }

            namespace process {
                using ProcessIdentity = DWORD;

                class CallbackElement {
                public:
                    ProcessIdentity Identity{};
#if defined(DEBUG) && DEBUG
                    std::string Path{};
#endif
                };

                inline Result<DWORD> GetParentPID(_In_ const ProcessIdentity pid) {
                    DWORD ppid{};
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->NtDLL.NtQueryInformationProcess) {
                        return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                    }
                    HANDLE hProcess = nullptr;

                    const auto defer = base::MakeDefer([&]() {
                        if (!hProcess) {
                            CloseHandle(hProcess);
                            hProcess = nullptr;
                        }
                    });

                    NTSTATUS ntStatus = 0;
                    PROCESS_BASIC_INFORMATION processBasicInformation{};

                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (nullptr == hProcess) {
                        return APICallingError("OpenProcess", CPL_FILE_AND_LINE);
                    }
                    bzero(&processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION));
                    ntStatus = api->NtDLL.NtQueryInformationProcess(
                        hProcess,
                        ProcessBasicInformation,
                        &processBasicInformation,
                        sizeof(PROCESS_BASIC_INFORMATION),
                        nullptr
                    );
                    // if (!NT_SUCCESS(ntStatus))
                    if (ntStatus < 0) {
                        const auto e = ntStatus;
                        auto es = strings::Format("[X] NtQueryInformationProcess failed [0x%lx][%s]", e,
                                                  FormatError(e).data());
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }

                        return MakeErr(sys::Errors::Win32CallFailed, es.value<>());
                    }
                    // *ppid = (DWORD)processBasicInformation.Reserved3;
                    memmove(&ppid, &processBasicInformation.Reserved3, sizeof(DWORD));

                    return ppid;
                }

                inline Result<std::string> GetProcessPath(_In_ HANDLE hProcess) {
                    const auto &api = cpl::sys::api::API::Instance();

                    char buffer[MAX_PATH << 1u] = {};

                    // api->Kernel32.QueryFullProcessImageNameA
                    // QueryFullProcessImageName 是Vista及以上才支持的API，优先调用该API
                    if (api.Kernel32.QueryFullProcessImageNameA) {
                        DWORD bufferSize = sizeof(buffer);
                        const auto r00 = api.Kernel32.QueryFullProcessImageNameA(hProcess, 0, buffer, &bufferSize);
                        if (!r00) {
                            // 失败的话不应该直接返回，而是尝试下一个api
                            // return APIError("api.Kernel32.QueryFullProcessImageNameA", CPL_FILE_AND_LINE);
                            goto __NEXT__;
                        }
                        return buffer;
                    }
                __NEXT__:
                    // api->PsAPI.GetModuleFileNameExA
                    // 如果QueryFullProcessImageName不可用，则调用传统的GetModuleFileNameExA（x64/x86体系结构可能会影响）
                    if (api.PsAPI.GetModuleFileNameExA) {
                        const auto dwRet = api.PsAPI.GetModuleFileNameExA(hProcess, nullptr, buffer, sizeof(buffer));
                        if (0 == dwRet) {
                            return APICallingError("api.PsAPI.GetModuleFileNameExA", CPL_FILE_AND_LINE);
                        }
                        return buffer;
                    }
                    return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                }

                inline Result<std::string> GetProcessPath(_In_ const ProcessIdentity pid) {
                    if (pid == GetCurrentProcessId()) {
                        char buffer[MAX_PATH << 2u] = {};
                        const auto len = GetModuleFileNameA(nullptr, buffer, static_cast<DWORD>(sizeof(buffer)));
                        if (len > 0 && len < sizeof(buffer)) {
                            return std::string(buffer, buffer + len);
                        }
                    }

                    HANDLE hProcess{};
                    std::string ret{};
                    const auto defer = base::MakeDefer([&]() {
                        if (hProcess) {
                            CloseHandle(hProcess);
                            hProcess = nullptr;
                        }
                    });
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                           PROCESS_VM_READ,
                                           FALSE, pid);
                    if (!hProcess) {
                        return APICallingError("OpenProcess", CPL_FILE_AND_LINE);
                    }
                    return GetProcessPath(hProcess);
                }

                /**
                 * 枚举所有进程，并调用callback处理。
                 * @param callbacks
                 * @return
                 */
                inline Int32Result EnumerateProcesses(
                    _In_ const std::vector<
                        base::callback::ICallback<ProcessIdentity &, Int32Result> *> &callbacks
                ) {
                    if (callbacks.empty()) {
                        return ERROR_EMPTY;
                    }

                    const auto &api = cpl::sys::api::API::Instance();
                    if (!api.PsAPI.EnumProcesses) {
                        return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                    }
                    std::vector<ProcessIdentity> processes{};

                    // 分配合适的内存空间，获得当前全部进程ID。
                    {
                        processes.resize(1024);
                        for (;;) {
                            DWORD cb = 1024 * sizeof(DWORD);
                            DWORD cbNeeded{};
                            // [out] lpidProcess
                            // 指向接收进程标识符列表的数组的指针。
                            // [in] cb
                            // pProcessIds 数组的大小（以字节为单位）。
                            // [out] lpcbNeeded
                            // pProcessIds 数组中返回的字节数。
                            const auto r00 = api.PsAPI.EnumProcesses(processes.data(), cb, &cbNeeded);
                            if (!r00) {
                                return APICallingError("api.PsAPI.EnumProcesses", CPL_FILE_AND_LINE);
                            }
                            if (cbNeeded >= cb) {
                                cb = cbNeeded << 1u; // 为防止进程增加，扩大一倍再调整空间。
                                processes.resize(cb);
                            } else {
                                processes.resize(cbNeeded / sizeof(DWORD));
                                break;
                            }
                        }
                    }
                    // callback
                    std::vector<Int32Result> rv{}; // result vectors
                    {
                        bool allToBeContinued = false;
                        for (auto &pid: processes) {
                            if (pid == 0) {
                                continue;
                            }
                            for (const auto &callback: callbacks) {
                                if (!callback) {
                                    continue;
                                }
                                if (!callback->ToBeContinued()) {
                                    // 说明当前callback已经获得结果，不需要再调用了。
                                    // 直接调用下一个callback
                                    continue;
                                }
                                auto ret = callback->Callback(pid);
                                rv.push_back(std::move(ret));
                                // 只要有一个true，allToBeContinued == true，就应该继续循环
                                allToBeContinued |= callback->ToBeContinued();
                            }
                            if (!allToBeContinued) {
                                // 如果所有callback都不需要继续时，就直接退出。
                                break;
                            }
                        }
                    }
                    // result
                    {
                        std::vector<std::string> reasons{};
                        for (const auto &r: rv) {
                            if (!r) {
                                reasons.push_back(r.error().Reason);
                            }
                        }
                        if (!reasons.empty()) {
                            auto e = Error{
                                Errors::EnumerateProcesses_,
                                strings::Join(reasons, ", ").data()
                            };
#if defined(DEBUG) && DEBUG
                            std::vector<std::system_error> errors{};
                            for (const auto &r: rv) {
                                if (!r) {
                                    errors.insert(errors.end(), r.error().Errors.begin(), r.error().Errors.end());
                                }
                            }
#endif
                            return Err(e);
                        }
                        return 0;
                        //
                        // #if defined(DEBUG) && DEBUG
                        //                         std::vector<std::string> errors{};
                        //                         std::vector<DWORD> error5pid{};
                        //                         std::vector<DWORD> error87pid{};
                        //                         for (const auto &r: rv) {
                        //                             // 调试情况下，如果有异常，生成报告一起抛出
                        //                             if (r.Exception) {
                        //                                 if (r.RetCode == ERROR_ACCESS_DENIED) {
                        //                                     error5pid.push_back(r.Element->Identity);
                        //                                 } else if (r.RetCode == ERROR_INVALID_PARAMETER) {
                        //                                     error87pid.push_back(r.Element->Identity);
                        //                                 } else {
                        //                                     const auto es = cpl::strings::Format(
                        //                                         "\tCallback[%s] Process[%lu][%s] RetCode[%d] Error[%s]",
                        //                                         r.Identity.data(),
                        //                                         r.Element ? r.Element->Identity : 0,
                        //                                         r.Element ? r.Element->Path.data() : "",
                        //                                         r.RetCode,
                        //                                         r.Exception->what()
                        //                                     );
                        //                                     errors.push_back(es);
                        //                                 }
                        //                             }
                        //                         }
                        //                         bool hasError{false};
                        //                         std::string aes = "[X] EnumerateProcesses error:\n";
                        //                         if (!error5pid.empty()) {
                        //                             // 无权限访问进程不算错误
                        //                             // hasError = true;
                        //                             aes += "\tACCESS_DENIED [";
                        //                             for (const auto &pid: error5pid) {
                        //                                 aes += std::to_string(pid);
                        //                                 aes += ",";
                        //                             }
                        //                             aes += "]\n";
                        //                             LOG_D("%s", aes.data());
                        //                         }
                        //                         if (!error87pid.empty()) {
                        //                             hasError = true;
                        //                             aes += "\tINVALID_PARAMETER [";
                        //                             for (const auto &pid: error87pid) {
                        //                                 aes += std::to_string(pid);
                        //                                 aes += ",";
                        //                             }
                        //                             aes += "]\n";
                        //                         }
                        //                         if (!errors.empty()) {
                        //                             hasError = true;
                        //                             aes += cpl::strings::Join(errors, "\n");
                        //                         }
                        //                         if (hasError) {
                        //                             return cpl::Err(cpl::Error(Errors::Win32CallFailed, aes.c_str()));
                        //                         }
                        // #endif
                    }
                    // return 0;
                }

                /**
                 * 对与单个参数HANDLE并且结果是BOOL的统一定义一个类型
                 */
                // int (*const)(const void *)
                using Win32ProcessAPI = BOOL (WINAPI *)(HANDLE hProcess);

                /**
                 * 根据路径调用WIN32API处理
                 */
                class CallbackForBoolWIN32ProcessAPIByPath final : public base::callback::ICallback<
                            ProcessIdentity &, Int32Result> {
                protected:
                    std::string targetProcessPath{};
                    Win32ProcessAPI function{};
                    bool toFindFirst{true};
                    bool firstBeFound{false};

                public:
                    std::vector<BOOL> results;

                    CallbackForBoolWIN32ProcessAPIByPath(
                        const std::string &targetProcessPath,
                        Win32ProcessAPI function,
                        const bool toFindFirst,
                        const base::callback::Identity &identity = "CallbackForBoolWIN32ProcessAPIByPath"
                    ) : ICallback(identity) {
                        this->targetProcessPath = targetProcessPath;
                        this->function = function;
                        this->toFindFirst = toFindFirst;
                    }

                    Int32Result Callback(_In_ ProcessIdentity &pid) override {
                        if (!this->function) {
                            return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                        }

                        HANDLE hProcess{};

                        const auto defer = base::MakeDefer([&]() {
                            if (hProcess) {
                                CloseHandle(hProcess);
                                hProcess = nullptr;
                            }
                        });

                        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                        if (nullptr == hProcess) {
                            return APICallingError("GetTokenInformation", CPL_FILE_AND_LINE);
                        }
                        // compare path
                        const auto currentProcessPath_ = GetProcessPath(hProcess);
                        if (!currentProcessPath_) {
                            return Err(currentProcessPath_.error());
                        }
                        const auto &currentProcessPath = currentProcessPath_.value();
                        const auto r00 = _stricmp(currentProcessPath.data(), this->targetProcessPath.data());
                        if (r00 != 00) {
                            return Err(Error{
                                ERROR_WRONG_TARGET_NAME,
                                CPL_FILE_AND_LINE
                            });
                        }

                        const auto r01 = function(hProcess);
                        results.push_back(r01);
                        if (r01 && this->toFindFirst) {
                            this->firstBeFound = true;
                        }
                        return ERROR_SUCCESS;
                    }

                    bool ToBeContinued() override {
                        return !this->firstBeFound;
                    }
                };

                /**
                 * 需要匹配 typedef BOOL (WINAPI *Win32ProcessAPI)(HANDLE hProcess);
                 * @param hProcess
                 * @return
                 */
                static BOOL WINAPI NtTerminateProcessWrapper(HANDLE hProcess) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->NtDLL.NtTerminateProcess) {
                    }
                    if (nullptr == api->NtDLL.NtTerminateProcess) {
                        return FALSE;
                    }
                    return api->NtDLL.NtTerminateProcess(hProcess, 0);
                }

                inline Int32Result TerminateProcesses(_In_ const std::string &processName) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->NtDLL.NtTerminateProcess) {
                        return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                    }
                    CallbackForBoolWIN32ProcessAPIByPath callback(processName, NtTerminateProcessWrapper, false,
                                                                  "TerminateProcesses");
                    const std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> callbacks{
                        &callback
                    };
                    return EnumerateProcesses(callbacks);
                }

                inline Int32Result SuspendProcesses(_In_ const std::string &processName) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->NtDLL.NtSuspendProcess) {
                        return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                    }

                    CallbackForBoolWIN32ProcessAPIByPath callback(processName, api->NtDLL.NtSuspendProcess, false,
                                                                  "SuspendProcesses");
                    const std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> callbacks{
                        &callback
                    };
                    return EnumerateProcesses(callbacks);
                }

                inline Int32Result ResumeProcesses(_In_ const std::string &processName) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->NtDLL.NtResumeProcess) {
                        return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                    }
                    CallbackForBoolWIN32ProcessAPIByPath callback(processName, api->NtDLL.NtResumeProcess, false,
                                                                  "ResumeProcesses");
                    const std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> callbacks{
                        &callback
                    };
                    return EnumerateProcesses(callbacks);
                }
            }

            namespace path {
                inline Result<std::string> GetCurrentPath() {
                    return process::GetProcessPath(GetCurrentProcessId());
                }

                inline Result<std::string> GetCurrentDir() {
                    const auto p = GetCurrentPath();
                    if (!p) {
                        return cpl::Err(cpl::Error{p.error().Code, (p.error().Reason + CPL_FILE_AND_LINE).data()});
                    }
                    const auto n = p.value<>().rfind('\\');
                    if (n == std::string::npos) {
                        auto es = cpl::strings::Format(
                            "[X] cannot find [\\] in [%s]" CPL_FILE_AND_LINE, p.value<>().data());
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(ERROR_NOT_FOUND, es.value<>());
                    }
                    return p.value<>().substr(0, n);
                }

                inline Int32Result CreateDirectoryRecursive(_In_ const std::string &path) {
                    if (path.empty()) {
                        return ERROR_EMPTY;
                    }

                    size_t pos = 0;
                    std::string toCreatePath = path;

                    // 处理路径分隔符：替换正斜杠为反斜杠
                    toCreatePath = strings::ReplaceAll(toCreatePath, "/", "\\");


                    // toCreatePath.replace(toCreatePath.begin(), toCreatePath.end(), '/', '\\');

                    // 逐级创建目录
                    pos = 0;
                    while ((pos = toCreatePath.find('\\', pos + 1)) != std::string::npos) {
                        std::string subPath = toCreatePath.substr(0, pos);

                        // 跳过无效路径：
                        // 1. 只包含一个或多个反斜杠的路径（\ 或 \\ 或 \\\ 等）
                        bool onlyBackslashes = true;
                        for (size_t i = 0; i < subPath.length(); i++) {
                            if (subPath[i] != '\\') {
                                onlyBackslashes = false;
                                break;
                            }
                        }
                        if (onlyBackslashes && subPath.length() <= 2) {
                            continue;
                        }
                        // 2. 单个盘符（如 "C:"）
                        // 3. 盘符根目录（如 "C:\"）
                        // 4. 网络路径前缀（如 "\\"）
                        // 5. 网络共享根目录（如 "\\server\"）
                        if ((subPath.length() == 2 && subPath[1] == ':') ||
                            (subPath.length() == 3 && subPath[1] == ':' && subPath[2] == '\\') ||
                            (subPath.length() > 2 && subPath.substr(0, 2) == "\\\\" &&
                             subPath.rfind('\\') == subPath.length() - 1)) {
                            continue;
                        }

                        // 检查目录是否存在
                        const DWORD attr = GetFileAttributesA(subPath.data());
                        if (attr == INVALID_FILE_ATTRIBUTES) {
                            // 目录不存在，创建
                            if (!CreateDirectoryA(subPath.data(), nullptr)) {
                                const auto e = GetLastError();
                                if (e != ERROR_ALREADY_EXISTS) {
                                    auto es = strings::Format(
                                        "[X] CreateDirectoryA [%s] failed [0x%lx][%s]" CPL_FILE_AND_LINE,
                                        subPath.data(), e, FormatError(e).data()
                                    );
                                    if (!es) {
                                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                                    }
                                    return MakeErr(Errors::CreateDirectoryA_, es.value<>());
                                }
                            }
                        } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                            // 路径存在但不是目录
                            auto es = strings::Format(
                                "[X] Path [%s] already exists" CPL_FILE_AND_LINE, subPath.data());
                            if (!es) {
                                return Err(es.error().Append(CPL_FILE_AND_LINE));
                            }
                            return MakeErr(Errors::CreateDirectoryA_, es.value<>());
                        }
                    }

                    // 创建最后一级目录
                    if (!CreateDirectoryA(toCreatePath.data(), nullptr)) {
                        const auto e = GetLastError();
                        if (e != ERROR_ALREADY_EXISTS) {
                            auto es = strings::Format(
                                "[X] Path [%s] already exists" CPL_FILE_AND_LINE, toCreatePath.data());
                            if (!es) {
                                return Err(es.error().Append(CPL_FILE_AND_LINE));
                            }
                            return MakeErr(Errors::CreateDirectoryA_, es.value<>());
                        }
                    }
                    return ERROR_SUCCESS;
                }

                inline Int32Result CreateDirectoryRecursive(_In_ const std::wstring &path) {
                    auto p = cpl::sys::FromWString(path);
                    if (!p) {
                        return Err(p.error().Append(CPL_FILE_AND_LINE));
                    }
                    return CreateDirectoryRecursive(p.value<>());
                }

                inline const char *GetWindowsPath() {
                    static char buffer[MAX_PATH << 2]{};
                    GetWindowsDirectoryA(buffer, sizeof(buffer));
                    return buffer;
                }

                inline const char *GetSystemPath() {
                    static char buffer[MAX_PATH << 2]{};
                    GetSystemDirectoryA(buffer, sizeof(buffer));
                    return buffer;
                }

                inline const char *GetExplorerPath() {
                    static std::string buffer{};
                    const auto windowsPath = GetWindowsPath();
                    buffer = std::string(windowsPath);
                    buffer.append("\\explorer.exe");
                    return buffer.data();
                }

                inline const char *GetWinLogoPath() {
                    static std::string buffer{};
                    buffer = std::string(GetSystemPath());
                    buffer.append("\\winlogon.exe");
                    return buffer.data();
                }

                inline const char *GetTaskMgrPath() {
                    static std::string buffer{};
                    buffer = GetSystemPath();
                    buffer.append("\\Taskmgr.exe");
                    return buffer.data();
                }

                inline const char *GetSystemTempPath() {
                    static std::string buffer{};
                    if (buffer.empty()) {
                        char tempPath[MAX_PATH] = {0};
                        // 获取系统临时目录（通常是 C:\Windows\Temp）
                        const auto result = GetTempPathA(MAX_PATH, tempPath);
                        if (result > 0 && result <= MAX_PATH) {
                            buffer = std::string(tempPath);
                            // 确保路径以反斜杠结尾
                            if (!buffer.empty() && buffer.back() != '\\') {
                                buffer.push_back('\\');
                            }
                        } else {
                            // 如果获取失败，使用默认的系统临时目录
                            buffer = std::string(GetWindowsPath()) + "\\Temp\\";
                        }
                    }
                    return buffer.data();
                }
            }

            namespace trick {
                inline Int32Result PrivilegeUp() {
                    HANDLE hToken = nullptr;
                    LUID luId;
                    TOKEN_PRIVILEGES tkp;

                    const auto defer = base::MakeDefer([&]() {
                        if (nullptr != hToken) {
                            CloseHandle(hToken);
                            hToken = nullptr;
                        }
                    });

                    BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
                    if (!bRet) {
                        return APICallingError("OpenProcessToken", CPL_FILE_AND_LINE);
                    }
                    bRet = LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luId);
                    if (!bRet) {
                        return APICallingError("LookupPrivilegeValueA", CPL_FILE_AND_LINE);
                    }
                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[0].Luid = luId;
                    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr);
                    if (!bRet) {
                        return APICallingError("AdjustTokenPrivileges", CPL_FILE_AND_LINE);
                    }
                    return 0;
                }

                static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wEvent, LPARAM lpKBDLLHookStructParam) {
                    const auto lpHookSt = reinterpret_cast<LPKBDLLHOOKSTRUCT>(lpKBDLLHookStructParam);

                    LRESULT result;

                    if (lpHookSt->vkCode == VK_LBUTTON || lpHookSt->vkCode == 0x57) {
                        // 除了 【w】 + LButton 按键之外，其他全部屏蔽（但是无法屏蔽CTRL + ALT + DEL）
                        result = 0; // 等于0就此为止
                    } else {
                        result = 1; // 其他值会被后续处理
                    }

#if (defined DEBUG) && DEBUG
                    PCTSTR szEvent = nullptr;
                    switch (wEvent) {
                        case WM_KEYDOWN: {
                            szEvent = "WM_KEYDOWN";
                        }
                        break;
                        case WM_KEYUP: {
                            szEvent = "WM_KEYUP";
                        }
                        break;
                        case WM_SYSKEYDOWN: {
                            szEvent = "WM_SYSKEYDOWN";
                        }
                        break;
                        case WM_SYSKEYUP: {
                            szEvent = "WM_SYSKEYUP";
                        }
                        break;
                        default: {
                            szEvent = "UNKNOWN EVENT";
                        }
                        break;
                    }
                    LOG_D("KeyboardProc Event [%s], vkCode [%lu], result [%lld]", szEvent, lpHookSt->vkCode,
                          result);
#endif

                    return result;
                }

                inline Int32Result Keyboard(const BOOL enable) {
                    // 全局钩子
                    static HHOOK hKeyBoard = nullptr;
                    if (!enable && !hKeyBoard) {
                        hKeyBoard = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandleA(nullptr), 0);
                        if (!hKeyBoard) {
                            return APICallingError("SetWindowsHookExA", CPL_FILE_AND_LINE);
                        }
                    } else if (enable && hKeyBoard) {
                        const auto r00 = UnhookWindowsHookEx(hKeyBoard);
                        if (!r00) {
                            return APICallingError("UnhookWindowsHookEx", CPL_FILE_AND_LINE);
                        }
                        hKeyBoard = nullptr;
                    }
                    // 其他情况什么也不做
                    return 0;
                }

                inline Int32Result TaskManager(const BOOL enable) {
                    if (!enable) {
                        const auto *api = &cpl::sys::api::API::Instance();
                        if (!api || !api->NtDLL.NtTerminateProcess) {
                            return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                        }
                        // 两种方法
                        // 1. 直接执行命令 taskkill.exe /f /im taskmgr.exe
                        // 2. 遍历进程后发送关闭的消息
                        {
                            const auto &tm_path = path::GetTaskMgrPath();
                            // 关闭已开启的 【任务管理器】
                            process::TerminateProcesses(tm_path);
                        }
                    }
                    // 以独占方式打开 taskmgr.exe，防止被运行。
                    {
                        static auto hTaskMgr = INVALID_HANDLE_VALUE;
                        if (INVALID_HANDLE_VALUE != hTaskMgr && enable) {
                            CloseHandle(hTaskMgr);
                            hTaskMgr = INVALID_HANDLE_VALUE;
                        }
                        if (INVALID_HANDLE_VALUE == hTaskMgr && !enable) {
                            // 以独占方式打开 taskmgr.exe，防止被运行。
                            hTaskMgr = CreateFileA(
                                path::GetTaskMgrPath(),
                                0,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr
                            );
                            if (INVALID_HANDLE_VALUE == hTaskMgr) {
                                return APICallingError("CreateFileA", CPL_FILE_AND_LINE);
                            }
                        }
                    }
                    return 0;
                }

                inline Int32Result CtrlAltDel(const BOOL enable) {
                    // 参考 https://blog.csdn.net/qq_23313467/article/details/107957442
                    if (enable) {
                        return process::ResumeProcesses(path::GetWinLogoPath());
                    } else {
                        return process::SuspendProcesses(path::GetWinLogoPath());
                    }
                }
            }

            namespace session {
                using SessionIdentity = DWORD;
                using CallbackElement = process::CallbackElement;
                // using CallbackResult = Int32Result;

                /**
                 * 依赖 api->kernel32.ProcessIdToSessionId
                 * WindowsXP下有，但session机制并为起作用，系统服务和第一个登录的用户都运行在Session0。
                 */
                class CallbackFindActiveSessionsWithExplorer : public cpl::base::callback::ICallback<
                            process::ProcessIdentity &, Int32Result> {
                    std::unordered_map<DWORD, DWORD> mapSessionIdToFirstProcessId{};
                    std::unordered_map<DWORD, DWORD> mapProcessIdToSessionId{};
                    std::string targetProcessName{};

                public:
                    explicit CallbackFindActiveSessionsWithExplorer(const std::string &targetProcessName)
                        : ICallback("CallbackFindActiveSessionsWithExplorer") {
                        this->targetProcessName = targetProcessName;
                        strings::Lower(this->targetProcessName);
                    }

                    ~CallbackFindActiveSessionsWithExplorer() override = default;

                    Int32Result Callback(process::ProcessIdentity &pid) override {
                        const auto *api = &cpl::sys::api::API::Instance();
                        Int32Result result{};
                        if (!api || !api->Kernel32.ProcessIdToSessionId) {
                            return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                        }
                        // 比较进程信息是否与目标进程名称相同
                        {
                            const auto pathRet = process::GetProcessPath(pid);
                            if (!pathRet) {
                                return Err(Error{
                                    pathRet.error().Code,
                                    (pathRet.error().Reason + CPL_FILE_AND_LINE).data()
                                });
                            }
                            auto path = pathRet.value();
                            strings::Lower(path);
                            if (path != targetProcessName) {
                                // 非目标进程
                                return Err(Error{
                                    ERROR_WRONG_TARGET_NAME,
                                    "ERROR_WRONG_TARGET_NAME" CPL_FILE_AND_LINE
                                });
                            }
                        }
                        // GetSession
                        {
                            SessionIdentity sid{};
                            const auto r1 = api->Kernel32.ProcessIdToSessionId(pid, &sid);
                            if (!r1) {
                                return APICallingError("api->Kernel32.ProcessIdToSessionId", CPL_FILE_AND_LINE);
                            }
                            // 将sessionId和processId加入map。每个session只要第一个process就够了。
                            {
                                this->mapProcessIdToSessionId[pid] = sid;
                                if (this->mapSessionIdToFirstProcessId.find(sid) == this->mapSessionIdToFirstProcessId.
                                    end()) {
                                    this->mapSessionIdToFirstProcessId[sid] = pid;
                                }
                            }
                        }
                        return result;
                    }

                    std::unordered_map<DWORD, DWORD> GetMapSessionIdToProcessId() const {
                        return mapSessionIdToFirstProcessId;
                    }

                    std::unordered_map<DWORD, DWORD> GetMapProcessIdToSessionId() const {
                        return mapProcessIdToSessionId;
                    }
                };

                inline Int32Result ExecuteCommandInCurrentSession(_In_ const std::string &cmd) {
                    PROCESS_INFORMATION pi{};
                    STARTUPINFOA si = {sizeof(si)};

                    const auto defer = base::MakeDefer([&]() {
                        if (nullptr != pi.hThread) {
                            CloseHandle(pi.hThread);
                            pi.hThread = nullptr;
                        }
                        if (nullptr != pi.hProcess) {
                            CloseHandle(pi.hProcess);
                            pi.hProcess = nullptr;
                        }
                    });

                    // 创建进程
                    const auto r0 = CreateProcessA(
                        nullptr, // 不指定模块名称，使用命令行
                        const_cast<LPSTR>(cmd.data()), // 命令行字符串
                        nullptr, // 默认进程属性
                        nullptr, // 默认线程属性
                        FALSE, // 不继承句柄
                        0, // 无创建标志
                        nullptr, // 使用父进程的环境变量
                        nullptr, // 使用父进程的当前目录
                        &si, // 指向 STARTUPINFO 结构
                        &pi // 接收 PROCESS_INFORMATION 结构
                    );
                    if (!r0) {
                        return APICallingError("CreateProcessA", CPL_FILE_AND_LINE);
                    }
                    return 0;
                }

                inline Int32Result ExecuteCommandInCurrentSession(_In_ const std::wstring &cmd) {
                    const auto command = cpl::sys::FromWString(cmd);
                    if (command) {
                        return ExecuteCommandInCurrentSession(command.value<>());
                    }
                    return cpl::Err(cpl::Error{
                        command.error().Code, (command.error().Reason + CPL_FILE_AND_LINE).data()
                    });
                }

                static Int32Result executeCommandInSessionFromProcessId(
                    _In_ const std::string &cmd,
                    _In_ const process::ProcessIdentity processId
                );

                static std::unordered_map<DWORD, DWORD> getMapSessionIdToProcessId();

                /**
                 * 也许服务权限下可用。管理员权限下无法使用。
                 * @param cmd
                 * @param sid
                 * @return
                 */
                static Int32Result
                executeCommandInSession(_In_ const std::string &cmd, _In_ const SessionIdentity sid) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api) {
                        return cpl::Err(cpl::Error(cpl::Error::UnavailableAPI, CPL_FILE_AND_LINE));
                    }
                    if (!api->WtsAPI32.WTSQueryUserToken) {
                        const auto mapSessionIdToProcessId = getMapSessionIdToProcessId();
                        const auto it = mapSessionIdToProcessId.find(sid);
                        if (it != mapSessionIdToProcessId.end()) {
                            return executeCommandInSessionFromProcessId(cmd, it->second);
                        }
                        return ExecuteCommandInCurrentSession(cmd);
                    }
                    HANDLE hToken{}, hNewToken{};
                    STARTUPINFOA si = {sizeof(si)};
                    si.lpDesktop = const_cast<LPSTR>("winsta0\\default");
                    PROCESS_INFORMATION pi{};

                    const auto defer = cpl::base::MakeDefer([&]() {
                        if (nullptr != pi.hThread) {
                            CloseHandle(pi.hThread);
                            pi.hThread = nullptr;
                        }
                        if (nullptr != pi.hProcess) {
                            CloseHandle(pi.hProcess);
                            pi.hProcess = nullptr;
                        }
                        if (nullptr != hNewToken) {
                            CloseHandle(hNewToken);
                            hNewToken = nullptr;
                        }
                        if (nullptr != hToken) {
                            CloseHandle(hToken);
                            hToken = nullptr;
                        }
                    });
                    //
                    {
                        // todo 这里直接获取是会出错的，应该通过遍历explorer获取token
                        const auto r0 = api->WtsAPI32.WTSQueryUserToken(sid, &hToken);
                        if (!r0) {
                            return APICallingError("api->WtsAPI32.WTSQueryUserToken", CPL_FILE_AND_LINE);
                        }
                    }
                    //
                    {
                        const auto r0 = DuplicateTokenEx(
                            hToken,
                            MAXIMUM_ALLOWED,
                            nullptr,
                            SecurityIdentification,
                            TokenPrimary,
                            &hNewToken);
                        if (!r0) {
                            return APICallingError("DuplicateTokenEx", CPL_FILE_AND_LINE);
                        }
                    }
                    //
                    {
                        const auto r0 = CreateProcessAsUserA(
                            hNewToken,
                            nullptr,
                            const_cast<LPSTR>(cmd.data()),
                            nullptr,
                            nullptr,
                            FALSE,
                            0,
                            nullptr,
                            nullptr,
                            &si,
                            &pi
                        );
                        if (!r0) {
                            return APICallingError("CreateProcessAsUserA", CPL_FILE_AND_LINE);
                        }
                    }
                    return 0;
                }

                /**
                 * 也许服务权限下可用。管理员权限下无法使用。
                 * @param cmd
                 * @param sid
                 * @return
                 */
                static Int32Result
                executeCommandInSession(_In_ const std::wstring &cmd, _In_ const SessionIdentity sid) {
                    const auto command = cpl::sys::FromWString(cmd);
                    if (command) {
                        return executeCommandInSession(command.value(), sid);
                    }
                    return cpl::Err(cpl::Error{
                        command.error().Code, (command.error().Reason + CPL_FILE_AND_LINE).data()
                    });
                }

                /**
                 * 不知道什么用，大概是远程桌面用？
                 * @param cmd
                 * @return
                 */
                static Int32Result executeCommandInActiveConsoleSession(_In_ const std::string &cmd) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->Kernel32.WTSGetActiveConsoleSessionId) {
                        auto currentSessionId = GetCurrentSessionId();
                        if (currentSessionId) {
                            return executeCommandInSession(cmd, currentSessionId.value<>());
                        }
                        return ExecuteCommandInCurrentSession(cmd);
                    }
                    const auto sessionId = api->Kernel32.WTSGetActiveConsoleSessionId();
                    return executeCommandInSession(cmd, sessionId);
                }

                /**
                 * 不知道什么用，大概是远程桌面用？
                 * @param cmd
                 * @return
                 */
                static Int32Result executeCommandInActiveConsoleSession(_In_ const std::wstring &cmd) {
                    const auto command = cpl::sys::FromWString(cmd);
                    if (command) {
                        return executeCommandInActiveConsoleSession(command.value<>());
                    }
                    return cpl::Err(cpl::Error{
                        command.error().Code, (command.error().Reason + CPL_FILE_AND_LINE).data()
                    });
                }

                static Int32Result executeCommandInSessionFromProcessHandle(
                    _In_ const std::string &cmd,
                    _In_ const HANDLE hProcess
                ) {
                    HANDLE hToken{}, hNewToken{};
                    STARTUPINFOA si = {sizeof(si)};
                    si.lpDesktop = const_cast<LPSTR>("winsta0\\default");
                    PROCESS_INFORMATION pi{};

                    const auto defer = base::MakeDefer([&]() {
                        if (nullptr != pi.hThread) {
                            CloseHandle(pi.hThread);
                            pi.hThread = nullptr;
                        }
                        if (nullptr != pi.hProcess) {
                            CloseHandle(pi.hProcess);
                            pi.hProcess = nullptr;
                        }
                        if (nullptr != hNewToken) {
                            CloseHandle(hNewToken);
                        }
                        if (nullptr != hToken) {
                            CloseHandle(hToken);
                        }
                    });
                    // 打开进程
                    {
                        const auto r0 = OpenProcessToken(
                            hProcess,
                            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                            &hToken
                        );
                        if (!r0) {
                            return APICallingError("OpenProcessToken", CPL_FILE_AND_LINE);
                        }
                    }
                    // 复制令牌
                    {
                        const auto r0 = DuplicateTokenEx(
                            hToken,
                            MAXIMUM_ALLOWED,
                            nullptr,
                            SecurityIdentification,
                            TokenPrimary,
                            &hNewToken);
                        if (!r0) {
                            return APICallingError("DuplicateTokenEx", CPL_FILE_AND_LINE);
                        }
                    }
                    // 使用令牌在桌面用户中执行
                    {
                        std::vector<char> _cmd(cmd.begin(), cmd.end());
                        _cmd.push_back('\0');
                        const auto r0 = CreateProcessAsUserA(
                            hNewToken,
                            nullptr,
                            _cmd.data(),
                            nullptr,
                            nullptr,
                            FALSE,
                            0,
                            nullptr,
                            nullptr,
                            &si,
                            &pi
                        );
                        if (!r0) {
                            return APICallingError("CreateProcessAsUserA", CPL_FILE_AND_LINE);
                        }
                    }
                    return 0;
                }

                static Int32Result executeCommandInSessionFromProcessId(
                    _In_ const std::string &cmd,
                    _In_ const process::ProcessIdentity processId
                ) {
                    HANDLE hProcess{};

                    const auto defer = base::MakeDefer([&]() {
                        if (hProcess) {
                            CloseHandle(hProcess);
                            hProcess = nullptr;
                        }
                    });

                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
                    if (hProcess == nullptr) {
                        return APICallingError("OpenProcess", CPL_FILE_AND_LINE);
                    }
                    return executeCommandInSessionFromProcessHandle(cmd, hProcess);
                }

                static std::unordered_map<DWORD, DWORD> getMapSessionIdToProcessId() {
                    CallbackFindActiveSessionsWithExplorer callback{"CallbackFindActiveSessionsWithExplorer"};
                    const std::vector<base::callback::ICallback<process::ProcessIdentity &, Int32Result> *> callbacks
                            {&callback};
                    process::EnumerateProcesses(callbacks);
                    const auto mapSessionIdToProcessId = callback.GetMapSessionIdToProcessId();
                    return mapSessionIdToProcessId;
                }

                inline Int32Result ExecuteCommandsInActiveSessions(
                    _In_ const std::string &cmd,
                    _In_ const BOOL exceptCurrentSession = TRUE,
                    _In_ const DWORD windowsMajorVersion = 6,
                    _In_ const std::string &processName = path::GetExplorerPath()
                ) {
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (windowsMajorVersion <= 5 || !api->Kernel32.ProcessIdToSessionId) {
                        LOG_D(
                            "[!] ExecuteCommandsInActiveSessions using XP-compatible path; "
                            "trying active console session first\n"
                        );
                        const auto r00 = executeCommandInActiveConsoleSession(cmd);
                        if (r00) {
                            LOG_D("[!] ExecuteCommandsInActiveSessions launched successfully in active console session\n");
                            return ERROR_SUCCESS;
                        }
                        LOG_D(
                            "[X] ExecuteCommandsInActiveSessions failed in active console session: [%s]\n",
                            r00.error().Reason.data()
                        );
                        LOG_D("[^] ExecuteCommandsInActiveSessions falling back to current session\n");
                        const auto r01 = ExecuteCommandInCurrentSession(cmd);
                        if (r01) {
                            LOG_D("[!] ExecuteCommandsInActiveSessions launched successfully in current session fallback\n");
                            return ERROR_SUCCESS;
                        }
                        auto e = r01.error();
                        return Err(e.Append(CPL_FILE_AND_LINE));
                    }
                    const auto mapSessionIdToProcessId = getMapSessionIdToProcessId();
                    const auto currentSessionId = GetCurrentSessionId();
                    DWORD currentSid = 0xffffffff;
                    if (currentSessionId) {
                        currentSid = currentSessionId.value<>();
                    }

                    if (mapSessionIdToProcessId.empty()) {
                        LOG_D(
                            "[!] ExecuteCommandsInActiveSessions found no active [%s] process; "
                            "falling back to active console session\n",
                            processName.data()
                        );
                        return executeCommandInActiveConsoleSession(cmd);
                    }

                    bool launched = false;
                    cpl::Error lastError{};

                    for (auto it = mapSessionIdToProcessId.begin(); it != mapSessionIdToProcessId.end(); ++it) {
                        const auto sessionId = it->first;
                        const auto processId = it->second;
                        if (sessionId == currentSid && !exceptCurrentSession) {
                            LOG_D(
                                "[^] ExecuteCommandsInActiveSessions launching in current session [%lu]\n",
                                sessionId
                            );
                            const auto r00 = ExecuteCommandInCurrentSession(cmd);
                            if (!r00) {
                                lastError = r00.error();
                                LOG_D(
                                    "[X] ExecuteCommandsInActiveSessions failed in current session [%lu]: [%s]\n",
                                    sessionId,
                                    r00.error().Reason.data()
                                );
                                continue;
                            }
                            launched = true;
                            LOG_D(
                                "[!] ExecuteCommandsInActiveSessions launched successfully in current session [%lu]\n",
                                sessionId
                            );
                        } else {
                            LOG_D(
                                "[^] ExecuteCommandsInActiveSessions launching in session [%lu] via process [%lu]\n",
                                sessionId,
                                processId
                            );
                            const auto r00 = executeCommandInSessionFromProcessId(cmd, processId);
                            if (!r00) {
                                lastError = r00.error();
                                LOG_D(
                                    "[X] ExecuteCommandsInActiveSessions failed in session [%lu] via process [%lu]: [%s]\n",
                                    sessionId,
                                    processId,
                                    r00.error().Reason.data()
                                );
                                continue;
                            }
                            launched = true;
                            LOG_D(
                                "[!] ExecuteCommandsInActiveSessions launched successfully in session [%lu] via process [%lu]\n",
                                sessionId,
                                processId
                            );
                        }
                    }
                    if (!launched) {
                        if (!lastError.Reason.empty()) {
                            return Err(lastError.Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(
                            Error::NoData,
                            "[X] ExecuteCommandsInActiveSessions failed to launch in any active session"
                            CPL_FILE_AND_LINE
                        );
                    }
                    return ERROR_SUCCESS;
                }
            }
        }
    }
}
