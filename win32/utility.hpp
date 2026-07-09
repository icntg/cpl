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
#include <algorithm>
#include <unordered_map>

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

                // Signature of the single-arg Nt* process control routines
                // (Suspend/Resume). NtTerminateProcess takes a second UINT exit
                // code, so it is wrapped via a lambda to fit this shape.
                typedef BOOL(WINAPI *Win32ProcessAPI)(HANDLE hProcess);

                // Callback that matches a process by (case-insensitive) path and
                // applies a callable to its handle (NtTerminate/NtSuspend/NtResume).
                // EnumerateProcesses feeds it ProcessIdentity instances whose .path
                // has already been resolved, so no extra OpenProcess-for-path is
                // needed — fixing a latent bug in the historical version which
                // passed a HANDLE to GetProcessPath (which expects a pid).
                template <typename Fn>
                class CallbackForBoolWIN32ProcessAPIByPathT final
                    : public base::callback::ICallback<ProcessIdentity &, Int32Result> {
                    std::string lowerTarget{};
                    Fn function;

                public:
                    std::vector<BOOL> results;

                    CallbackForBoolWIN32ProcessAPIByPathT(
                        const std::string &targetPath,
                        Fn function,
                        const base::callback::Identity &identity = "CallbackForBoolWIN32ProcessAPIByPath")
                        : ICallback(identity), function(function) {
                        lowerTarget = targetPath;
                        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                                       ::tolower);
                    }

                    Int32Result Callback(ProcessIdentity &id) override {
                        // Match by path (case-insensitive). EnumerateProcesses
                        // already filled id.path; skip processes we couldn't resolve.
                        if (id.path.empty()) {
                            return ERROR_SUCCESS;
                        }
                        std::string lowerCurrent = id.path;
                        std::transform(lowerCurrent.begin(), lowerCurrent.end(),
                                       lowerCurrent.begin(), ::tolower);
                        if (lowerCurrent != lowerTarget) {
                            return ERROR_SUCCESS; // not a target, keep scanning
                        }

                        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id.pid);
                        if (hProcess == nullptr) {
                            // Access denied (e.g. system process) — not fatal.
                            return ERROR_SUCCESS;
                        }
                        const auto defer = cpl::base::MakeDefer([&]() {
                            CloseHandle(hProcess);
                        });
                        const BOOL r = this->function(hProcess);
                        results.push_back(r);
                        return ERROR_SUCCESS;
                    }

                    bool ToBeContinued() override { return true; }
                };

                // Terminate all processes whose image path matches `processName`.
                // NtTerminateProcess(HANDLE, UINT) is wrapped to single-arg shape.
                inline Int32Result TerminateProcesses(const std::string &processName) {
                    const auto &api = api::API::Instance();
                    if (!api.NtDLL.NtTerminateProcess) {
                        return Err(Error(Error::UnavailableAPI,
                                         "[X] TerminateProcesses NtTerminateProcess unavailable" CPL_FILE_AND_LINE));
                    }
                    auto fn = api.NtDLL.NtTerminateProcess;
                    auto wrapper = [fn](HANDLE h) -> BOOL { return fn(h, 0); };
                    CallbackForBoolWIN32ProcessAPIByPathT<decltype(wrapper)> cb(
                        processName, wrapper, "TerminateProcesses");
                    std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> cbs{&cb};
                    return EnumerateProcesses(cbs);
                }

                inline Int32Result SuspendProcesses(const std::string &processName) {
                    const auto &api = api::API::Instance();
                    if (!api.NtDLL.NtSuspendProcess) {
                        return Err(Error(Error::UnavailableAPI,
                                         "[X] SuspendProcesses NtSuspendProcess unavailable" CPL_FILE_AND_LINE));
                    }
                    CallbackForBoolWIN32ProcessAPIByPathT<api::NtDLL::NtSuspendProcess> cb(
                        processName, api.NtDLL.NtSuspendProcess, "SuspendProcesses");
                    std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> cbs{&cb};
                    return EnumerateProcesses(cbs);
                }

                inline Int32Result ResumeProcesses(const std::string &processName) {
                    const auto &api = api::API::Instance();
                    if (!api.NtDLL.NtResumeProcess) {
                        return Err(Error(Error::UnavailableAPI,
                                         "[X] ResumeProcesses NtResumeProcess unavailable" CPL_FILE_AND_LINE));
                    }
                    CallbackForBoolWIN32ProcessAPIByPathT<api::NtDLL::NtResumeProcess> cb(
                        processName, api.NtDLL.NtResumeProcess, "ResumeProcesses");
                    std::vector<base::callback::ICallback<ProcessIdentity &, Int32Result> *> cbs{&cb};
                    return EnumerateProcesses(cbs);
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

                // System directory paths used by trick (TaskManager locks
                // Taskmgr.exe, CtrlAltDel suspends winlogon.exe, etc.). These
                // return std::string by value — no static-buffer aliasing, so
                // they are thread-safe and don't share state across calls.
                inline std::string GetSystemPath() {
                    char buffer[MAX_PATH] = {};
                    GetSystemDirectoryA(buffer, MAX_PATH);
                    return std::string(buffer);
                }

                inline std::string GetWindowsPath() {
                    char buffer[MAX_PATH] = {};
                    GetWindowsDirectoryA(buffer, MAX_PATH);
                    return std::string(buffer);
                }

                inline std::string GetExplorerPath() {
                    return GetWindowsPath() + "\\explorer.exe";
                }

                inline std::string GetWinLogoPath() {
                    return GetSystemPath() + "\\winlogon.exe";
                }

                inline std::string GetTaskMgrPath() {
                    return GetSystemPath() + "\\Taskmgr.exe";
                }
            } // namespace path

            // ----------------------------------------------------------------
            // trick — violation-blocking safety primitives.
            //
            // When ifw detects an unauthorized outbound connection it pops a
            // full-screen warning and must lock the console (disable keyboard,
            // block Task Manager, raise privileges to kill escaping processes).
            // These four functions are the building blocks; they are real,
            // stateful, and potentially console-locking — callers must always
            // restore state (Keyboard(TRUE)/TaskManager(TRUE)/CtrlAltDel(TRUE))
            // on the exit path. PrivilegeUp() is reversible implicitly (the
            // process keeps the debug privilege until it exits).
            // ----------------------------------------------------------------
            namespace trick {
                // Enable SE_DEBUG_NAME on the current process token. Required so
                // that SuspendProcesses/ResumeProcesses/TerminateProcesses can
                // open winlogon.exe / taskmgr.exe (which run under SYSTEM).
                inline Int32Result PrivilegeUp() {
                    HANDLE hToken = nullptr;
                    const auto defer = cpl::base::MakeDefer([&]() {
                        if (hToken != nullptr) { CloseHandle(hToken); }
                    });
                    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
                        return Err(Win32Error(GetLastError(), "OpenProcessToken"));
                    }
                    LUID luid{};
                    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
                        return Err(Win32Error(GetLastError(), "LookupPrivilegeValueA"));
                    }
                    TOKEN_PRIVILEGES tkp{};
                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[0].Luid = luid;
                    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr)) {
                        return Err(Win32Error(GetLastError(), "AdjustTokenPrivileges"));
                    }
                    return ERROR_SUCCESS;
                }

                // Low-level keyboard hook: blocks every key except the unlock
                // gesture (left mouse button + 'W'). Cannot block Ctrl+Alt+Del
                // (handled by winlogon, see CtrlAltDel for the workaround).
                static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wEvent, LPARAM lpKbStruct) {
                    const auto *kb = reinterpret_cast<LPKBDLLHOOKSTRUCT>(lpKbStruct);
                    LRESULT result;
                    if (kb->vkCode == VK_LBUTTON || kb->vkCode == 0x57 /* 'W' */) {
                        result = 0; // allow the unlock gesture through
                    } else {
                        result = 1; // swallow everything else
                    }
                    return result;
                }

                // enable=FALSE installs the global WH_KEYBOARD_LL hook;
                // enable=TRUE removes it. Idempotent (no-op if already in state).
                inline Int32Result Keyboard(const BOOL enable) {
                    static HHOOK hKeyboard = nullptr;
                    if (!enable && hKeyboard == nullptr) {
                        hKeyboard = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc,
                                                      GetModuleHandleA(nullptr), 0);
                        if (hKeyboard == nullptr) {
                            return Err(Win32Error(GetLastError(), "SetWindowsHookExA"));
                        }
                    } else if (enable && hKeyboard != nullptr) {
                        if (!UnhookWindowsHookEx(hKeyboard)) {
                            return Err(Win32Error(GetLastError(), "UnhookWindowsHookEx"));
                        }
                        hKeyboard = nullptr;
                    }
                    return ERROR_SUCCESS;
                }

                // enable=FALSE kills any running taskmgr.exe and then opens
                // Taskmgr.exe exclusively (share mode 0) so it cannot be relaunched.
                // enable=TRUE releases the exclusive handle.
                inline Int32Result TaskManager(const BOOL enable) {
                    if (!enable) {
                        // Kill any currently running Task Manager.
                        (void) process::TerminateProcesses(path::GetTaskMgrPath());
                    }
                    static HANDLE hTaskMgr = INVALID_HANDLE_VALUE;
                    if (hTaskMgr != INVALID_HANDLE_VALUE && enable) {
                        CloseHandle(hTaskMgr);
                        hTaskMgr = INVALID_HANDLE_VALUE;
                    }
                    if (hTaskMgr == INVALID_HANDLE_VALUE && !enable) {
                        hTaskMgr = CreateFileA(
                            path::GetTaskMgrPath().c_str(),
                            0, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hTaskMgr == INVALID_HANDLE_VALUE) {
                            return Err(Win32Error(GetLastError(), "CreateFileA(Taskmgr.exe)"));
                        }
                    }
                    return ERROR_SUCCESS;
                }

                // enable=FALSE suspends winlogon.exe so Ctrl+Alt+Del appears
                // unresponsive (the SAS sequence is handled by winlogon).
                // enable=TRUE resumes it. Not a true SAS block — winlogon is
                // merely stalled for the duration.
                inline Int32Result CtrlAltDel(const BOOL enable) {
                    if (enable) {
                        return process::ResumeProcesses(path::GetWinLogoPath());
                    }
                    return process::SuspendProcesses(path::GetWinLogoPath());
                }
            } // namespace trick

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

                using SessionIdentity = DWORD;

                // Launch `cmd` in the security context of `hToken` (a primary
                // token duplicated from a target-session user). Core helper for
                // the multi-session launchers below. The caller owns hToken.
                static Int32Result executeCommandWithToken(const std::string &cmd, HANDLE hToken) {
                    const auto &api = api::API::Instance();
                    HANDLE hDup = nullptr;
                    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation,
                                          TokenPrimary, &hDup)) {
                        return Err(Win32Error(GetLastError(), "DuplicateTokenEx"));
                    }
                    const auto closeDup = cpl::base::MakeDefer([&]() {
                        if (hDup != nullptr) { CloseHandle(hDup); }
                    });
                    LPVOID env = nullptr;
                    if (api.UserEnv.CreateEnvironmentBlock) {
                        api.UserEnv.CreateEnvironmentBlock(&env, hDup, FALSE);
                    }
                    const auto freeEnv = cpl::base::MakeDefer([&]() {
                        if (env != nullptr && api.UserEnv.DestroyEnvironmentBlock) {
                            api.UserEnv.DestroyEnvironmentBlock(env);
                        }
                    });
                    STARTUPINFOA si{};
                    si.cb = sizeof(si);
                    si.lpDesktop = const_cast<LPSTR>("winsta0\\default");
                    PROCESS_INFORMATION pi{};
                    std::string mutableCmd = cmd;
                    const BOOL ok = CreateProcessAsUserA(
                        hDup, nullptr, const_cast<LPSTR>(mutableCmd.data()), nullptr, nullptr, FALSE,
                        env != nullptr ? CREATE_UNICODE_ENVIRONMENT : 0, env, nullptr, &si, &pi);
                    if (!ok) {
                        return Err(Win32Error(GetLastError(), "CreateProcessAsUserA"));
                    }
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return ERROR_SUCCESS;
                }

                // Launch `cmd` in the session that owns process `pid`. Opens
                // the process, duplicates its token, and delegates to
                // executeCommandWithToken.
                static Int32Result executeCommandInSessionFromProcessId(const std::string &cmd, DWORD pid) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if (hProcess == nullptr) {
                        return Err(Win32Error(GetLastError(), "OpenProcess"));
                    }
                    const auto defer = cpl::base::MakeDefer([&]() { CloseHandle(hProcess); });
                    HANDLE hToken = nullptr;
                    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                        return Err(Win32Error(GetLastError(), "OpenProcessToken"));
                    }
                    const auto closeToken = cpl::base::MakeDefer([&]() { CloseHandle(hToken); });
                    return executeCommandWithToken(cmd, hToken);
                }

                // Enumerate explorer.exe processes, mapping each active session
                // id to the first explorer pid found in that session. Used by
                // ExecuteCommandsInActiveSessions to reach every logged-in user.
                class CallbackFindActiveSessionsWithExplorer final
                    : public base::callback::ICallback<process::ProcessIdentity &, Int32Result> {
                    std::string targetPath{};
                    DWORD currentSession{0xFFFFFFFFu};

                public:
                    std::unordered_map<DWORD, DWORD> sessionIdToFirstPid;

                    explicit CallbackFindActiveSessionsWithExplorer(const std::string &explorerPath)
                        : ICallback("CallbackFindActiveSessionsWithExplorer") {
                        targetPath = explorerPath;
                        std::transform(targetPath.begin(), targetPath.end(), targetPath.begin(), ::tolower);
                        const auto cur = GetCurrentSessionId();
                        if (cur) { currentSession = cur.value(); }
                    }

                    Int32Result Callback(process::ProcessIdentity &id) override {
                        const auto &api = api::API::Instance();
                        if (!api.Kernel32.ProcessIdToSessionId) {
                            return Err(Win32Error(ERROR_API_UNAVAILABLE, "ProcessIdToSessionId"));
                        }
                        if (id.path.empty()) {
                            return ERROR_SUCCESS;
                        }
                        std::string p = id.path;
                        std::transform(p.begin(), p.end(), p.begin(), ::tolower);
                        if (p != targetPath) {
                            return ERROR_SUCCESS;
                        }
                        SessionIdentity sid = 0xFFFFFFFFu;
                        if (!api.Kernel32.ProcessIdToSessionId(id.pid, &sid)) {
                            return ERROR_SUCCESS; // skip, not fatal
                        }
                        // Record the first pid per session.
                        if (sessionIdToFirstPid.find(sid) == sessionIdToFirstPid.end()) {
                            sessionIdToFirstPid[sid] = id.pid;
                        }
                        return ERROR_SUCCESS;
                    }

                    bool ToBeContinued() override { return true; }
                };

                // For each active session (discovered via explorer.exe), launch
                // `cmd` in that session's user context. exceptCurrentSession
                // skips the caller's own session (used when ifw wants to act on
                // *other* users). windowsMajorVersion is reserved for
                // version-specific launch logic (Vista+ needs WTSQueryUserToken,
                // older falls back to explorer-token).
                inline Int32Result ExecuteCommandsInActiveSessions(
                    const std::string &cmd,
                    const BOOL exceptCurrentSession,
                    const DWORD windowsMajorVersion,
                    const std::string &processName = path::GetExplorerPath()) {
                    (void)windowsMajorVersion;
                    CallbackFindActiveSessionsWithExplorer cb(processName);
                    std::vector<base::callback::ICallback<process::ProcessIdentity &, Int32Result> *> cbs{&cb};
                    const auto r = process::EnumerateProcesses(cbs);
                    if (!r) {
                        return r;
                    }
                    DWORD currentSession = 0xFFFFFFFFu;
                    {
                        const auto cur = GetCurrentSessionId();
                        if (cur) { currentSession = cur.value(); }
                    }
                    Int32Result last = static_cast<int32_t>(ERROR_SUCCESS);
                    for (const auto &kv : cb.sessionIdToFirstPid) {
                        if (exceptCurrentSession && kv.first == currentSession) {
                            continue;
                        }
                        last = executeCommandInSessionFromProcessId(cmd, kv.second);
                    }
                    return last;
                }

                // Launch `cmd` in the active console session (the one physically
                // logged in at the machine). Falls back to the current session
                // if WTSGetActiveConsoleSessionId is unavailable (pre-Vista).
                inline Int32Result executeCommandInActiveConsoleSession(const std::string &cmd) {
                    const auto &api = api::API::Instance();
                    if (!api.Kernel32.WTSGetActiveConsoleSessionId) {
                        return ExecuteCommandInCurrentSession(cmd);
                    }
                    const DWORD sid = api.Kernel32.WTSGetActiveConsoleSessionId();
                    if (sid == 0xFFFFFFFFu) {
                        return ExecuteCommandInCurrentSession(cmd);
                    }
                    // Locate an explorer pid in that session to borrow its token.
                    CallbackFindActiveSessionsWithExplorer cb(path::GetExplorerPath());
                    std::vector<base::callback::ICallback<process::ProcessIdentity &, Int32Result> *> cbs{&cb};
                    (void) process::EnumerateProcesses(cbs);
                    const auto it = cb.sessionIdToFirstPid.find(sid);
                    if (it != cb.sessionIdToFirstPid.end()) {
                        return executeCommandInSessionFromProcessId(cmd, it->second);
                    }
                    // No explorer in the console session — fall back to current.
                    return ExecuteCommandInCurrentSession(cmd);
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
