#ifndef CPL_WIN32_UTILITY_HPP_SYS_RESULT_API
#define CPL_WIN32_UTILITY_HPP_SYS_RESULT_API

// Win32 utility layer — cpl::sys::utility, new Result<T>-based API.
//
// This header is Windows-only. It consumes the top-level platform-independent
// headers (base.hpp / strings.hpp) and the cpl::sys::api dynamic-loader. For
// Win32 entry points not yet present in the generated api table it falls back
// to runtime GetProcAddress so the same binary runs on XP–Win11.
//
// Namespace layout (matches test_win32_utility.cpp):
//   cpl::sys::utility
//     ::process   (process enumeration, parent pid, process path)
//     ::path      (current path/dir, recursive mkdir)
//     ::session   (session id, execute-in-session)

#include <string>
#include <vector>
#include <tuple>
#include <cstdint>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#include <sddl.h>

#include "api.hpp"
#include "../base.hpp"
#include "../strings.hpp"

// Link the Win32 import libraries used by this layer. These are present on
// every supported Windows toolchain (MSVC v141_xp and MinGW-w64).
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#endif

namespace cpl {
    namespace sys {
        namespace utility {
            using cpl::Result;
            using cpl::Int32Result;
            using cpl::Stream;
            using cpl::Err;
            using cpl::Error;
            using cpl::MakeErr;

            // Translate a Win32 GetLastError() into a cpl::Error.
            inline Error Win32Error(const DWORD e, const char *where) {
                auto es = cpl::strings::Format("[X] %s failed [0x%lX]" CPL_FILE_AND_LINE, where,
                                               static_cast<uint32_t>(e));
                if (!es) {
                    return Error(cpl::sys::Errors::Win32CallFailed, where);
                }
                return Error(cpl::sys::Errors::Win32CallFailed, es.value().c_str());
            }

            namespace process {
                // Process identity handed to enumeration callbacks.
                struct ProcessIdentity {
                    DWORD pid{0};
                    std::string path{};
                };

                inline Result<DWORD> GetParentPID(const DWORD pid) {
                    const auto &api = api::API::Instance();
                    if (!api.NtDLL.NtQueryInformationProcess) {
                        return Err(Win32Error(ERROR_API_UNAVAILABLE, "NtQueryInformationProcess"));
                    }
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProcess == nullptr) {
                        return Err(Win32Error(GetLastError(), "OpenProcess"));
                    }
                    const auto closeHandle = cpl::base::MakeDefer([&]() {
                        if (hProcess != nullptr) { CloseHandle(hProcess); }
                    });
                    PROCESS_BASIC_INFORMATION pbi{};
                    bzero(&pbi, sizeof(pbi));
                    const NTSTATUS st = api.NtDLL.NtQueryInformationProcess(
                        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
                    if (st < 0) {
                        return Err(Win32Error(static_cast<DWORD>(st), "NtQueryInformationProcess"));
                    }
                    // winternl.h names the parent-PID field Reserved3 (MSVC) or
                    // InheritedFromUniqueProcessId (MinGW); pick whichever exists.
#ifdef _MSC_VER
                    DWORD ppid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3));
#else
                    DWORD ppid = static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);
#endif
                    if (pid == 0 || ppid == 0) {
                        return Err(cpl::Error(Error::InvalidArgument, "[X] GetParentPID invalid pid" CPL_FILE_AND_LINE));
                    }
                    return ppid;
                }

                inline Result<std::string> GetProcessPath(const DWORD pid) {
                    const auto &api = api::API::Instance();
                    if (!api.Kernel32.QueryFullProcessImageNameA && !api.PsAPI.GetModuleFileNameExA) {
                        return Err(Win32Error(ERROR_API_UNAVAILABLE, "GetProcessPath"));
                    }
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                    if (hProcess == nullptr) {
                        return Err(Win32Error(GetLastError(), "OpenProcess"));
                    }
                    const auto closeHandle = cpl::base::MakeDefer([&]() {
                        if (hProcess != nullptr) { CloseHandle(hProcess); }
                    });
                    char buffer[MAX_PATH << 1] = {};
                    if (api.Kernel32.QueryFullProcessImageNameA) {
                        DWORD size = sizeof(buffer);
                        if (api.Kernel32.QueryFullProcessImageNameA(hProcess, 0, buffer, &size) != 0) {
                            return std::string(buffer);
                        }
                    }
                    if (api.PsAPI.GetModuleFileNameExA) {
                        if (api.PsAPI.GetModuleFileNameExA(hProcess, nullptr, buffer, sizeof(buffer)) != 0) {
                            return std::string(buffer);
                        }
                    }
                    return Err(Win32Error(GetLastError(), "GetProcessPath"));
                }

                // Enumerate running processes, invoking the callback for each.
                // Returns ERROR_EMPTY when no callback accepted any process (empty
                // callback list) — matches the test expectation.
                inline Int32Result EnumerateProcesses(
                    std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> &callbacks) {
                    // Empty callback list short-circuits before touching the API.
                    if (callbacks.empty()) {
                        return ERROR_EMPTY;
                    }
                    const auto &api = api::API::Instance();
                    if (!api.PsAPI.EnumProcesses) {
                        return Err(Win32Error(ERROR_API_UNAVAILABLE, "EnumProcesses"));
                    }
                    DWORD cb = 1024 * sizeof(DWORD);
                    std::vector<DWORD> pids(cb / sizeof(DWORD));
                    DWORD cbNeeded = 0;
                    for (;;) {
                        if (!api.PsAPI.EnumProcesses(pids.data(), cb, &cbNeeded)) {
                            return Err(Win32Error(GetLastError(), "EnumProcesses"));
                        }
                        if (cbNeeded >= cb) {
                            cb = cbNeeded << 1u;
                            pids.resize(cb / sizeof(DWORD));
                        } else {
                            break;
                        }
                    }
                    const DWORD count = cbNeeded / sizeof(DWORD);
                    for (DWORD i = 0; i < count; ++i) {
                        const DWORD pid = pids[i];
                        if (pid == 0) { continue; }
                        ProcessIdentity id{};
                        id.pid = pid;
                        auto pathRes = GetProcessPath(pid);
                        if (pathRes) { id.path = std::move(pathRes.value()); }
                        bool anyContinue = false;
                        for (auto *cb : callbacks) {
                            if (cb == nullptr) { continue; }
                            (void)cb->Callback(id);
                            anyContinue |= cb->ToBeContinued();
                        }
                        if (!anyContinue) { break; }
                    }
                    return 0;
                }
            } // namespace process

            namespace path {
                inline Result<std::string> GetCurrentPath() {
                    return process::GetProcessPath(::GetCurrentProcessId());
                }

                inline Result<std::string> GetCurrentDir() {
                    auto p = GetCurrentPath();
                    if (!p) {
                        return Err(p.error());
                    }
                    const auto &s = p.value();
                    const auto n = s.rfind('\\');
                    if (n == std::string::npos) {
                        return Err(cpl::Error(Error::NoData, "[X] GetCurrentDir no separator" CPL_FILE_AND_LINE));
                    }
                    return s.substr(0, n);
                }

                inline Int32Result CreateDirectoryRecursive(const std::string &path) {
                    if (path.empty()) {
                        return ERROR_EMPTY;
                    }
                    std::string current = path;
                    std::replace(current.begin(), current.end(), '/', '\\');
                    size_t pos = 0;
                    while ((pos = current.find_first_of('\\', pos + 1)) != std::string::npos) {
                        const std::string sub = current.substr(0, pos);
                        const DWORD attr = GetFileAttributesA(sub.data());
                        if (attr == INVALID_FILE_ATTRIBUTES) {
                            if (!CreateDirectoryA(sub.data(), nullptr)) {
                                const DWORD e = GetLastError();
                                if (e != ERROR_ALREADY_EXISTS) {
                                    return static_cast<int32_t>(e);
                                }
                            }
                        } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                            return ERROR_FILE_EXISTS;
                        }
                    }
                    if (!CreateDirectoryA(current.data(), nullptr)) {
                        const DWORD e = GetLastError();
                        if (e != ERROR_ALREADY_EXISTS) {
                            return static_cast<int32_t>(e);
                        }
                    }
                    return ERROR_SUCCESS;
                }
            } // namespace path

            namespace session {
                inline Result<DWORD> GetCurrentSessionId() {
                    const auto &api = api::API::Instance();
                    if (!api.Kernel32.ProcessIdToSessionId) {
                        return Err(Win32Error(ERROR_API_UNAVAILABLE, "ProcessIdToSessionId"));
                    }
                    DWORD sid = 0xFFFFFFFF;
                    if (!api.Kernel32.ProcessIdToSessionId(GetCurrentProcessId(), &sid)) {
                        return Err(Win32Error(GetLastError(), "ProcessIdToSessionId"));
                    }
                    return sid;
                }

                inline Int32Result ExecuteCommandInCurrentSession(const std::string &cmd) {
                    DWORD sessionId = 0;
                    {
                        const auto r = GetCurrentSessionId();
                        if (!r) { return Err(r.error()); }
                        sessionId = r.value();
                    }
                    const auto &api = api::API::Instance();
                    HANDLE hToken = nullptr;
                    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                        return Err(Win32Error(GetLastError(), "OpenProcessToken"));
                    }
                    const auto closeToken = cpl::base::MakeDefer([&]() {
                        if (hToken != nullptr) { CloseHandle(hToken); }
                    });
                    HANDLE hDup = nullptr;
                    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation,
                                          TokenPrimary, &hDup)) {
                        return Err(Win32Error(GetLastError(), "DuplicateTokenEx"));
                    }
                    const auto closeDup = cpl::base::MakeDefer([&]() {
                        if (hDup != nullptr) { CloseHandle(hDup); }
                    });
                    STARTUPINFOA si{};
                    si.cb = sizeof(si);
                    PROCESS_INFORMATION pi{};
                    std::string mutableCmd = cmd;
                    LPVOID env = nullptr;
                    if (api.UserEnv.CreateEnvironmentBlock) {
                        api.UserEnv.CreateEnvironmentBlock(&env, hDup, FALSE);
                    }
                    const auto freeEnv = cpl::base::MakeDefer([&]() {
                        if (env != nullptr && api.UserEnv.DestroyEnvironmentBlock) {
                            api.UserEnv.DestroyEnvironmentBlock(env);
                        }
                    });
                    BOOL ok = CreateProcessAsUserA(
                        hDup, nullptr, const_cast<LPSTR>(mutableCmd.data()), nullptr, nullptr, FALSE,
                        env != nullptr ? CREATE_UNICODE_ENVIRONMENT : 0, env, nullptr, &si, &pi);
                    if (!ok) {
                        // Fallback: plain CreateProcessA in the current session.
                        ok = CreateProcessA(nullptr, const_cast<LPSTR>(mutableCmd.data()), nullptr, nullptr,
                                            FALSE, 0, env, nullptr, &si, &pi);
                        if (!ok) {
                            return Err(Win32Error(GetLastError(), "CreateProcessAsUserA"));
                        }
                    }
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    (void)sessionId;
                    return ERROR_SUCCESS;
                }
            } // namespace session

            // -----------------------------------------------------------------------
            // Top-level probes (no sub-namespace)
            // -----------------------------------------------------------------------

            inline Result<bool> IsAdministrator() {
                BOOL isAdmin = FALSE;
                SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
                PSID adminGroup = nullptr;
                if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
                    return Err(Win32Error(GetLastError(), "AllocateAndInitializeSid"));
                }
                const auto freeSid = cpl::base::MakeDefer([&]() {
                        if (adminGroup != nullptr) { FreeSid(adminGroup); }
                    });
                if (!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
                    return Err(Win32Error(GetLastError(), "CheckTokenMembership"));
                }
                return isAdmin != FALSE;
            }

            inline Result<bool> IsLikelyRunningAsService() {
                // Heuristic: a service runs in session 0 and typically with a
                // machine-account user name ("MACHINE$").
                DWORD sid = 0;
                {
                    const auto r = session::GetCurrentSessionId();
                    if (!r) { return Err(r.error()); }
                    sid = r.value();
                }
                char user[256] = {};
                DWORD size = sizeof(user);
                if (!GetUserNameA(user, &size)) {
                    return Err(Win32Error(GetLastError(), "GetUserNameA"));
                }
                const bool isSession0 = (sid == 0);
                const bool isMachineAccount = (size > 0 && user[size - 1] == '$');
                return isSession0 || isMachineAccount;
            }

            inline std::unordered_map<int, std::string> GetComputerNames() {
                std::unordered_map<int, std::string> names;
                const int formats[] = {
                    ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsDomain,
                    ComputerNameDnsFullyQualified, ComputerNamePhysicalNetBIOS,
                    ComputerNamePhysicalDnsHostname, ComputerNamePhysicalDnsDomain,
                    ComputerNamePhysicalDnsFullyQualified,
                };
                for (const auto fmt : formats) {
                    char buffer[MAX_PATH << 2] = {};
                    DWORD n = sizeof(buffer);
                    if (GetComputerNameExA(static_cast<COMPUTER_NAME_FORMAT>(fmt), buffer, &n)) {
                        names[fmt] = std::string(buffer);
                    } else {
                        names[fmt] = std::string();
                    }
                }
                return names;
            }

            inline Result<std::string> GetCurrentUser() {
                char user[256] = {};
                DWORD size = sizeof(user);
                if (!GetUserNameA(user, &size)) {
                    return Err(Win32Error(GetLastError(), "GetUserNameA"));
                }
                return std::string(user);
            }

            inline Result<std::unique_ptr<RTL_OSVERSIONINFOW> > GetWindowsVersion() {
                const auto &api = api::API::Instance();
                if (!api.NtDLL.RtlGetVersion) {
                    return Err(Win32Error(ERROR_API_UNAVAILABLE, "RtlGetVersion"));
                }
                auto info = std::unique_ptr<RTL_OSVERSIONINFOW>(new RTL_OSVERSIONINFOW{});
                info->dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
                if (api.NtDLL.RtlGetVersion(info.get()) != 0) {
                    return Err(Win32Error(GetLastError(), "RtlGetVersion"));
                }
                return info;
            }

            inline Result<std::tuple<size_t, size_t> > GetScreenSize() {
                const auto cx = GetSystemMetrics(SM_CXSCREEN);
                const auto cy = GetSystemMetrics(SM_CYSCREEN);
                if (cx <= 0 || cy <= 0) {
                    return Err(Win32Error(GetLastError(), "GetSystemMetrics"));
                }
                return std::tuple<size_t, size_t>(static_cast<size_t>(cx), static_cast<size_t>(cy));
            }

            // 16-byte machine GUID from the registry
            // (HKLM\Software\Microsoft\Cryptography\MachineGuid).
            inline Result<Stream> GetSystemGUID() {
                HKEY hKey = nullptr;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                                  KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
                    return Err(Win32Error(GetLastError(), "RegOpenKeyExA"));
                }
                const auto closeKey = cpl::base::MakeDefer([&]() {
                        if (hKey != nullptr) { RegCloseKey(hKey); }
                    });
                char value[64] = {};
                DWORD valueSize = sizeof(value);
                DWORD type = 0;
                if (RegQueryValueExA(hKey, "MachineGuid", nullptr, &type,
                                     reinterpret_cast<LPBYTE>(value), &valueSize) != ERROR_SUCCESS) {
                    return Err(Win32Error(GetLastError(), "RegQueryValueExA"));
                }
                // The GUID is a 36-char string "xxxxxxxx-xxxx-..."; fold it to 16 bytes.
                const std::string guid(value, valueSize ? valueSize - 1 : 0);
                Stream out(16, 0);
                const std::string hex = cpl::strings::ReplaceAll(guid, "-", "");
                for (size_t i = 0; i < 16 && i * 2 + 1 < hex.size(); ++i) {
                    const auto hi = hex[i * 2];
                    const auto lo = hex[i * 2 + 1];
                    auto hexVal = [](const char c) -> int {
                        if (c >= '0' && c <= '9') { return c - '0'; }
                        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
                        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
                        return 0;
                    };
                    out[i] = static_cast<uint8_t>((hexVal(hi) << 4) | hexVal(lo));
                }
                return out;
            }

            // 16-byte hardware UUID derived from the system volume serial.
            inline Result<Stream> GetHardwareUUID() {
                char sysDir[MAX_PATH] = {};
                if (GetSystemDirectoryA(sysDir, sizeof(sysDir)) == 0) {
                    return Err(Win32Error(GetLastError(), "GetSystemDirectoryA"));
                }
                // Drive letter is the first 2 chars ("C:").
                char root[] = {sysDir[0], ':', '\\', 0};
                DWORD serial = 0;
                if (!GetVolumeInformationA(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
                    return Err(Win32Error(GetLastError(), "GetVolumeInformationA"));
                }
                Stream out(16, 0);
                // Spread the 32-bit serial across 16 bytes deterministically.
                for (size_t i = 0; i < 16; ++i) {
                    out[i] = static_cast<uint8_t>((serial >> ((i % 4) * 8)) ^ (i * 0x5Bu));
                }
                return out;
            }

            inline Result<std::string> GetUserSID() {
                HANDLE hToken = nullptr;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                    return Err(Win32Error(GetLastError(), "OpenProcessToken"));
                }
                const auto closeToken = cpl::base::MakeDefer([&]() {
                        if (hToken != nullptr) { CloseHandle(hToken); }
                    });
                DWORD len = 0;
                GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
                if (len == 0) {
                    return Err(Win32Error(GetLastError(), "GetTokenInformation(size)"));
                }
                std::vector<uint8_t> buf(len);
                if (!GetTokenInformation(hToken, TokenUser, buf.data(), len, &len)) {
                    return Err(Win32Error(GetLastError(), "GetTokenInformation"));
                }
                const auto *tu = reinterpret_cast<TOKEN_USER *>(buf.data());
                char *sidStr = nullptr;
                if (!ConvertSidToStringSidA(tu->User.Sid, &sidStr) || sidStr == nullptr) {
                    return Err(Win32Error(GetLastError(), "ConvertSidToStringSidA"));
                }
                const auto freeSid = cpl::base::MakeDefer([&]() {
                        if (sidStr != nullptr) { LocalFree(sidStr); }
                    });
                return std::string(sidStr);
            }

            inline const char *GetSystemTempPath() {
                static char buffer[MAX_PATH] = {};
                if (buffer[0] == 0) {
                    if (GetTempPathA(sizeof(buffer), buffer) == 0) {
                        std::strncpy(buffer, "C:\\Windows\\Temp\\", sizeof(buffer) - 1);
                    }
                }
                return buffer;
            }

            // Run-only-once via a named mutex. scope=0 → per-user, scope=1 → global.
            inline Int32Result RunOnlyOnce(const int scope, const char *name) {
                std::string mutexName = (scope == 1 ? "Global\\" : "Local\\");
                mutexName += "cpl-";
                mutexName += (name != nullptr ? name : "default");
                HANDLE hMutex = CreateMutexA(nullptr, FALSE, mutexName.data());
                if (hMutex == nullptr) {
                    return Err(Win32Error(GetLastError(), "CreateMutexA"));
                }
                const DWORD r = WaitForSingleObject(hMutex, 0);
                if (r == WAIT_OBJECT_0) {
                    return ERROR_SUCCESS; // acquired; keep the mutex alive
                }
                if (r == WAIT_TIMEOUT) {
                    CloseHandle(hMutex);
                    return ERROR_ALREADY_EXISTS;
                }
                CloseHandle(hMutex);
                return Err(Win32Error(GetLastError(), "WaitForSingleObject"));
            }
        } // namespace utility
    } // namespace sys
} // namespace cpl

#endif // CPL_WIN32_UTILITY_HPP_SYS_RESULT_API
