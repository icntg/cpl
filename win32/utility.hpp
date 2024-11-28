#ifndef CPL_UTILITY_HPP_SUNSET_GRANITE_VIBRANT_PIONEER_MYSTIC_FORTIFY_LUMINOUS_ENIGMA
#define CPL_UTILITY_HPP_SUNSET_GRANITE_VIBRANT_PIONEER_MYSTIC_FORTIFY_LUMINOUS_ENIGMA

#include <string>
#include <cstdint>
#include <windows.h>
#include <tchar.h>

#include "api.hpp"
#include "../utility/base.hpp"
#include "../utility/strings.hpp"
#include "../../ccl/vendor/logger/log.h"


using namespace std;

namespace cpl {
    namespace win32 {
        namespace utility {
            namespace file {
                inline int64_t GetFileSize(const string &filename) {
                    struct stat st{};
                    FILE *fp = nullptr;
                    int result = stat(filename.data(), &st); // stat 只支持绝对路径，只支持纯英文路径。
                    if (ERROR_SUCCESS == result) {
                        return st.st_size;
                    }
                    result = fopen_s(&fp, filename.data(), "rb");
                    if (ERROR_SUCCESS != result || nullptr == fp) {
                        return -1;
                    }
                    fseek(fp, 0, SEEK_END);
                    const int64_t size = ftell(fp);
                    fclose(fp);
                    return size;
                }

                class FileMappingContext final : public base::IContext {
                protected:
                    string filename{};

                    int32_t Load() override {
                        int retCode = ERROR_SUCCESS;

                        MappedFileSize = GetFileSize(filename);
                        FileHandle = CreateFile(
                            filename.data(),
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr
                        );
                        if (INVALID_HANDLE_VALUE == FileHandle) {
                            const auto e = GetLastError();
                            log_fatal("CreateFile failed: [0x%lu]%s", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        MappingHandle = CreateFileMapping(
                            FileHandle,
                            nullptr,
                            PAGE_READONLY,
                            0,
                            0,
                            nullptr
                        );
                        if (nullptr == MappingHandle) {
                            const auto e = GetLastError();
                            log_fatal("CreateFileMapping failed: [0x%lx]%s", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        MappedFileAddress = MapViewOfFile(
                            MappingHandle,
                            FILE_MAP_READ,
                            0,
                            0,
                            0
                        );
                        if (nullptr == MappedFileAddress) {
                            const DWORD e = GetLastError();
                            log_fatal("MapViewOfFile failed: [0x%lx]%s", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        goto __FREE__;

                    __ERROR__:
                        retCode |= Unload();
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        INT32 retCode = ERROR_SUCCESS;
                        if (nullptr != MappedFileAddress) {
                            const BOOL unmapResult = UnmapViewOfFile(MappedFileAddress);
                            if (!unmapResult) {
                                const auto e = GetLastError();
                                retCode = static_cast<INT32>(e);
                                log_error("UnmapViewOfFile failed: [0x%lx]%s", e, FormatError(e).data());
                                goto __ERROR__;
                            }
                            MappedFileSize = 0;
                        }
                        if (nullptr != MappingHandle) {
                            CloseHandle(MappingHandle);
                            MappingHandle = nullptr;
                        }
                        if (INVALID_HANDLE_VALUE != FileHandle) {
                            CloseHandle(FileHandle);
                            FileHandle = INVALID_HANDLE_VALUE;
                        }
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                public:
                    HANDLE FileHandle = INVALID_HANDLE_VALUE;
                    HANDLE MappingHandle = nullptr;
                    void *MappedFileAddress = nullptr;
                    size_t MappedFileSize = 0;

                    explicit FileMappingContext(const string &filename) {
                        this->filename = filename;
                        const INT32 retCode = Load();
                        if (ERROR_SUCCESS != retCode) {
                            log_error("[x] failed to map file");
                            // throw runtime_error("failed to map file");
                        }
                    }

                    ~FileMappingContext() override {
                        const INT32 retCode = Unload();
                        if (ERROR_SUCCESS != retCode) {
                            log_error("[x] failed to ummap file");
                            // throw runtime_error("failed to ummap file");
                        }
                    }
                };
            }

            namespace path {
                inline const string &GetWindowsPath() {
                    static TCHAR buffer[MAX_PATH << 2]{};
                    GetWindowsDirectory(buffer, sizeof(buffer));
                    return buffer;
                }

                inline const string &GetSystemPath() {
                    static TCHAR buffer[MAX_PATH << 2]{};
                    GetSystemDirectory(buffer, sizeof(buffer));
                    return buffer;
                }

                inline const string &GetExplorerPath() {
                    static string buffer{};
                    buffer.append(GetWindowsPath());
                    buffer.append("\\explorer.exe");
                    return buffer;
                }

                inline const string &GetWinLogoPath() {
                    static string buffer{};
                    buffer.append(GetSystemPath());
                    buffer.append("\\winlogon.exe");
                    return buffer;
                }

                inline const string &GetTaskMgrPath() {
                    static string buffer{};
                    buffer.append(GetSystemPath());
                    buffer.append("\\Taskmgr.exe");
                    return buffer;
                }
            }

            namespace sys {
                namespace reg {
                }

                inline INT32 GetComputerNames(
                    string * NetBIOS = nullptr,
                    string * DNSHostname = nullptr,
                    string * DNSDomain = nullptr,
                    string * DNSFullyQualified = nullptr,
                    string * PhysicalNetBIOS = nullptr,
                    string * PhysicalDNSHostname = nullptr,
                    string * PhysicalDNSDomain = nullptr,
                    string * PhysicalDNSFullyQualified = nullptr,
                    string * ComputerNameMax = nullptr
                ) {
                    INT32 retCode = ERROR_SUCCESS;
#ifndef CN
#define CN(name, var) { \
    if (nullptr != (var)) \
    { \
        TCHAR buffer[MAX_PATH << 2]{}; \
        DWORD nbytes = sizeof(buffer); \
        bzero(buffer, sizeof(buffer)); \
        const BOOL bRet = GetComputerNameEx((name), buffer, &nbytes); \
        if (!bRet) \
        { \
            const DWORD e = GetLastError(); \
            retCode |= static_cast<INT32>(e); \
            log_error("[x] GetComputerNameEx (%s) failed [0x%lx]: %s", #name, e, FormatError(e).data()); \
        } \
        *(var) = string(buffer); \
    } \
}
                    CN(COMPUTER_NAME_FORMAT::ComputerNameNetBIOS, NetBIOS);
                    CN(COMPUTER_NAME_FORMAT::ComputerNameDnsHostname, DNSHostname);
                    CN(COMPUTER_NAME_FORMAT::ComputerNameDnsDomain, DNSDomain);
                    CN(COMPUTER_NAME_FORMAT::ComputerNameDnsFullyQualified, DNSFullyQualified);
                    CN(COMPUTER_NAME_FORMAT::ComputerNamePhysicalNetBIOS, PhysicalNetBIOS);
                    CN(COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsHostname, PhysicalDNSHostname);
                    CN(COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsDomain, PhysicalDNSDomain);
                    CN(COMPUTER_NAME_FORMAT::ComputerNamePhysicalDnsFullyQualified, PhysicalDNSFullyQualified);
                    CN(COMPUTER_NAME_FORMAT::ComputerNameMax, ComputerNameMax);

#undef CN
#endif

                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }

                inline INT32 GetCurrentUser(_Out_ string &user, _Out_opt_ DWORD *runningMode = nullptr) {
                    int32_t retCode = ERROR_SUCCESS;
                    BOOL bRet = FALSE;
                    DWORD dwRet = 0;
                    DWORD bufferSize = BUFSIZ << 2;
                    TCHAR buffer1[BUFSIZ << 2]{}, buffer2[BUFSIZ << 2]{};
                    bzero(buffer1, sizeof(buffer1));
                    bzero(buffer2, sizeof(buffer2));
                    bRet = GetUserName(buffer1, &bufferSize);
                    if (!bRet) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        log_error("[x] GetUserName failed [0x%lx]: %s", e, FormatError(e).data());
                    }
                    /* 服务形式启动的话，获取的是"主机名$"的名称。 */
                    dwRet = GetEnvironmentVariable(_T("USERNAME"), buffer2, bufferSize);
                    // 注意，这里成功的话返回的是实际数据长度，失败时才返回0
                    if (0 == dwRet) {
                        const DWORD e = GetLastError();
                        retCode |= static_cast<INT32>(e);
                        log_error("[x] GetEnvironmentVariable failed [0x%lx]: %s", e, FormatError(e).data());
                    }
                    if (ERROR_SUCCESS != retCode) {
                        // 如果都获取失败，则报错。
                        goto __ERROR__;
                    }
                    log_trace("u1=['%s'] u2=['%s']", buffer1, buffer2);
                    if (0 == _tcscmp(buffer1, buffer2)) {
                        // 如果两者一致，说明是以普通方式启动。选择其中一个返回即可。
                        user = buffer1; {
                            log_trace("running in normal mode");
                            if (nullptr != runningMode) {
                                *runningMode = 0;
                            }
                        }
                    } else {
                        // 如果两者不一致，说明以服务方式启动，对两者做一个拼接。
                        {
                            log_trace("running in service mode");
                            if (nullptr != runningMode) {
                                *runningMode = 1;
                            }
                            const string username = buffer1;
                            const string hostname = buffer2;
                            user = hostname + "\\\\" + username;
                        }
                    }
                    goto __FREE__;

                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }

                inline INT32 GetLogFilePath(_Out_ string &path) {
                    INT32 retCode = ERROR_SUCCESS;

                    TCHAR buffer[MAX_PATH << 2u]{};
                    bzero(buffer, sizeof(buffer));
                    string user{};
                    string tempPath{};

                    const DWORD dwVal = GetTempPath(sizeof(buffer), buffer);
                    if (dwVal == 0) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        log_error("[x] GetTempPath failed [0x%lx]: %s", e, FormatError(e).data());
                        tempPath = _T("c:\\windows\\temp\\");
                    } else {
                        tempPath = string(buffer);
                    }

                    retCode = GetCurrentUser(user);
                    if (ERROR_SUCCESS != retCode) {
                        user = string("unknown");
                    }
                    // 替换 user 中可能出现的 [\\] 字符
                    const auto idx = user.find("\\\\");
                    if (string::npos != idx) {
                        user.replace(user.find("\\\\"), 2, "-");
                    }
                    path = tempPath + "_ifw-" + user + ".log";
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }

                //*********************************************************
                //Function:            LogEvent
                //Description:            记录服务事件
                //Calls:
                //Called By:
                //Table Accessed:
                //Table Updated:
                //Input:
                //Output:
                //Return:
                //Others:
                //History:
                //            <author>niying <time>2006-8-10        <version>        <desc>
                //*********************************************************
                inline size_t LogEvent(const string &serviceName, LPCTSTR pFormat, ...) {
                    size_t ret{};
                    string msg{};
                    HANDLE hEventSource{};
                    LPTSTR lpszStrings[1];
                    va_list pArg;

                    va_start(pArg, pFormat);
                    ret = strings::VFormat(msg, pFormat, pArg);
                    va_end(pArg);

                    lpszStrings[0] = const_cast<LPTSTR>(msg.data());

                    hEventSource = RegisterEventSource(nullptr, serviceName.data());
                    if (hEventSource != nullptr) {
                        ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, nullptr, 1, 0,
                                    const_cast<LPCTSTR *>(&lpszStrings[0]), nullptr);
                        DeregisterEventSource(hEventSource);
                    }
                    return ret;
                }

                inline INT32 GetScreenSize(_Out_ size_t &width, _Out_ size_t &height) {
                    INT32 retCode = ERROR_SUCCESS;
                    DWORD cxPhysical = 0, cyPhysical = 0, cxLogical = 0, cyLogical = 0;
                    double horizontalScale = 0, verticalScale = 0;
                    MONITORINFOEX miEx{};
                    HMONITOR hMonitor{};
                    DEVMODE dm{};

                    // 获取窗口当前显示的监视器
                    HWND__ *hWnd = GetDesktopWindow(); //根据需要可以替换成自己程序的句柄
                    if (nullptr == hWnd) {
                        const DWORD e = GetLastError();
                        log_error("GetDesktopWindow failed: [0x%x]%s", e, FormatError(e).data());
                        retCode = static_cast<INT32>(e);
                        goto __ERROR__;
                    }
                    hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
                    if (nullptr == hMonitor) {
                        const DWORD e = GetLastError();
                        log_error("MonitorFromWindow failed: [0x%x]%s", e, FormatError(e).data());
                        retCode = static_cast<INT32>(e);
                        goto __ERROR__;
                    }

                    // 获取监视器逻辑宽度与高度

                    miEx.cbSize = sizeof(miEx);
                    GetMonitorInfo(hMonitor, &miEx);
                    cxLogical = miEx.rcMonitor.right - miEx.rcMonitor.left;
                    cyLogical = miEx.rcMonitor.bottom - miEx.rcMonitor.top;

                    // 获取监视器物理宽度与高度

                    dm.dmSize = sizeof(dm);
                    dm.dmDriverExtra = 0;
                    EnumDisplaySettings(miEx.szDevice, ENUM_CURRENT_SETTINGS, &dm);
                    cxPhysical = dm.dmPelsWidth;
                    cyPhysical = dm.dmPelsHeight;

                    //缩放比例计算
                    horizontalScale = static_cast<double>(cxPhysical) / static_cast<double>(cxLogical);
                    verticalScale = static_cast<double>(cyPhysical) / static_cast<double>(cyLogical);

                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:

                    log_trace(
                        "screen with = %d, height = %d, hScale = %f, vScale = %f",
                        cxLogical,
                        cyLogical,
                        horizontalScale,
                        verticalScale
                    );
                    width = cxLogical;
                    height = cyLogical;

                    return retCode;
                }

                namespace process {
                    // typedef BOOL (WINAPI *CallbackFunction)(HANDLE hProcess);

                    inline BOOL IsInstanceAlreadyInRunning() {
                        BOOL result = FALSE;

                        string mutexName{};

                        HANDLE hMutex{}; {
                            string username;
                            DWORD runningMode{};
                            result = GetCurrentUser(username, &runningMode);
                            if (ERROR_SUCCESS != result) {
                                log_error("[x] Core$$$GetUsername failed: [0x%lx]");
                                goto __ERROR__;
                            }
                            mutexName = "ifw-" + username;
                        }

                        // 尝试获取
                        hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, mutexName.data());
                        if (nullptr == hMutex) {
                            // 如果没有，说明是第一个，那就创建一个MUTEX
                            hMutex = CreateMutex(nullptr, FALSE, mutexName.data());
                            if (nullptr == hMutex) {
                                DWORD e = GetLastError();
                                log_error("[x] CreateMutex failed: [0x%lx]%s", e, FormatError(e).data());
                                result = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        } else {
                            // 如果有，说明已经有了，不准多开
                            log_error("[x] ifw is already running");
                            result = TRUE;
                            goto __ERROR__;
                        }
                        // 获取模块目录和文件名。
                        // 检测模块目录和安装目录是否相同。
                        goto __FREE__;

                    __ERROR__:
                        if (hMutex != nullptr) {
                            ReleaseMutex(hMutex);
                            hMutex = nullptr;
                        }
                    __FREE__:

                        return result;
                    }

                    inline INT32 GetPrevInstance() {
                        // todo
                        return ERROR_EMPTY;
                    }

                    inline INT32 GetParentPID(_In_ const DWORD pid, _Out_ DWORD &ppid) {
                        const auto &api = api::API::Instance();
                        INT32 retCode = ERROR_SUCCESS;
                        HANDLE hProcess = nullptr;
                        NTSTATUS ntStatus = 0;
                        PROCESS_BASIC_INFORMATION processBasicInformation;

                        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                        if (nullptr == hProcess) {
                            const DWORD e = GetLastError();
                            retCode = static_cast<INT32>(e);
                            log_error("[x] OpenProcess failed [0x%lx]: %s", e, FormatError(e).data());
                            goto __ERROR__;
                        }
                        bzero(&processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION));
                        ntStatus = api.NtDll.NtQueryInformationProcess(
                            hProcess,
                            ProcessBasicInformation,
                            &processBasicInformation,
                            sizeof(PROCESS_BASIC_INFORMATION),
                            nullptr
                        );
                        // if (!NT_SUCCESS(ntStatus))
                        if (ntStatus < 0) {
                            retCode = ntStatus;
                            log_error("[x] NtQueryInformationProcess failed [0x%lx]", ntStatus);
                            goto __ERROR__;
                        }
                        // *ppid = (DWORD)processBasicInformation.Reserved3;
                        memmove(&ppid, processBasicInformation.Reserved3, sizeof(DWORD));
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        if (nullptr != hProcess) {
                            CloseHandle(hProcess);
                            ZeroMemory(&hProcess, sizeof(HANDLE));
                        }
                        return retCode;
                    }

                    /* 可以沿用 handler */
                    inline int32_t GetProcessPathByHandle(_In_ HANDLE hProcess, _Out_ string &path) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.PsAPI.GetModuleFileNameExA) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        int32_t result = ERROR_SUCCESS;
                        TCHAR buffer[MAX_PATH << 1u] = {};

                        const DWORD dwRet = api.PsAPI.GetModuleFileNameExA(hProcess, nullptr, buffer, sizeof(buffer));
                        if (0 == dwRet) {
                            const auto e = GetLastError();
                            log_trace("[x] GetModuleFileNameExA failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        path = string(buffer);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return result;
                    }

                    inline int32_t GetProcessPathById(_In_ const DWORD dwProcessId, _Out_ string &path) {
                        int32_t result = ERROR_SUCCESS;

                        const auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                                          PROCESS_VM_READ,
                                                          FALSE, dwProcessId);
                        if (nullptr == hProcess) {
                            const auto e = GetLastError();
                            log_trace("OpenProcess [%lu] failed: [0x%lx]%s", dwProcessId, e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        result = GetProcessPathByHandle(hProcess, path);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        if (nullptr != hProcess) {
                            CloseHandle(hProcess);
                        }
                        return result;
                    }


                    class Process {
                    public:
                        DWORD ProcessId{0};
                    };

                    class ProcessEx : public Process {
                    public:
                        DWORD SessionId{0xffffffffu};
                        BOOL ExecutedInThisSession{FALSE};
                        int32_t CallbackResult{ERROR_SUCCESS};
                    };

                    inline int32_t EnumerateProcesses(
                        _In_ vector<base::callback::ICallback<DWORD> *> &Callbacks
                    ) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.PsAPI.EnumProcesses ||
                            nullptr == api.PsAPI.GetModuleFileNameExA
                        ) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        int32_t retCode = ERROR_SUCCESS;
                        DWORD *pProcBuf = nullptr;
                        DWORD cbNeeded; {
                            BOOL bRet = FALSE;
                            DWORD cb = 1024 * sizeof(DWORD);
                            pProcBuf = static_cast<DWORD *>(calloc(1, cb));
                            if (nullptr == pProcBuf) {
                                retCode = ERROR_NOT_ENOUGH_MEMORY;
                                log_error("[x] calloc failed: ERROR_NOT_ENOUGH_MEMORY");
                                goto __ERROR__;
                            }
                            for (;;) {
                                bRet = api.PsAPI.EnumProcesses(pProcBuf, cb, &cbNeeded);
                                if (!bRet) {
                                    DWORD e = GetLastError();
                                    log_error("[x] EnumProcess failed: [0x%lx]%s", e, FormatError(e).data());
                                    retCode = static_cast<int32_t>(e);
                                    goto __ERROR__;
                                }
                                if (cbNeeded >= cb) {
                                    cb = cbNeeded << 1u; // 为防止进程增加，扩大一倍再调整空间。
                                    void *p = realloc(pProcBuf, cb);
                                    if (nullptr == p) {
                                        // 如果这里realloc失败，直接赋值给pProcBuf的话，会导致pProcBuf原内存泄露。
                                        retCode = ERROR_NOT_ENOUGH_MEMORY;
                                        log_error("[x] realloc failed: ERROR_NOT_ENOUGH_MEMORY");
                                        goto __ERROR__;
                                    }
                                    pProcBuf = static_cast<DWORD *>(p);
                                } else {
                                    break;
                                }
                            }
                        } {
                            const DWORD cProcesses = cbNeeded / sizeof(DWORD);
                            for (size_t i = 0; i < cProcesses; i++) {
                                if (pProcBuf[i] != 0) {
                                    const DWORD pid = pProcBuf[i];
                                    bool toBeContinued = false;
                                    for (auto &callback: Callbacks) {
                                        if (nullptr == callback) {
                                            continue;
                                        }
                                        toBeContinued |= callback->ToBeContinued();
                                        if (callback->ToBeContinued()) {
                                            const auto iRet = callback->Callback(pid);
                                        }
                                    }
                                    if (!toBeContinued) {
                                        // 如果所有callback都不需要继续时，就直接退出。
                                        goto __FREE__;
                                    }
                                }
                            }
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        if (nullptr != pProcBuf) {
                            free(pProcBuf);
                            pProcBuf = nullptr;
                        }
                        return retCode;
                    }

                    typedef BOOL(WINAPI *Win32ProcessAPI)(HANDLE hProcess);

                    class CallbackForBoolWIN32ProcessAPIByPath final : public base::callback::ICallback<DWORD> {
                    protected:
                        string path{};
                        Win32ProcessAPI callbackFunction{nullptr};

                    public:
                        vector<BOOL> results;

                        CallbackForBoolWIN32ProcessAPIByPath(
                            _In_ const string &targetProcessPath,
                            _Out_ const Win32ProcessAPI &callbackFunction
                        ) {
                            this->path = targetProcessPath;
                            // this->callbackFunction = callbackFunction;
                            memmove(&this->callbackFunction, &callbackFunction, sizeof(PVOID));
                            // this->FilterType = filterType;
                            filterType = base::callback::FilterType::ALL;
                        }

                        int32_t Callback(_In_ const DWORD processId) override {
                            int32_t retCode = ERROR_SUCCESS;
                            BOOL result{};
                            string currentProcessPath{};
                            retCode = GetProcessPathById(processId, currentProcessPath);
                            if (ERROR_SUCCESS != retCode) {
                                return retCode;
                            }
                            retCode = _tcsicmp(currentProcessPath.data(), path.data());
                            if (0 != retCode) {
                                return retCode;
                            }
                            const auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
                            if (nullptr == hProcess) {
                                goto __ERROR__;
                            }
                            result = callbackFunction(hProcess);
                            results.push_back(result);
                            goto __FREE__;
                        __ERROR__:
                            PASS;
                        __FREE__:
                            if (nullptr != hProcess) {
                                CloseHandle(hProcess);
                            }
                            return retCode;
                        }

                        bool ToBeContinued() override {
                            return true;
                        }
                    };

                    class CallbackFindFirstProcessIdByPath final : public base::callback::ICallback<DWORD> {
                    protected:
                        string targetProcessPath{};

                    public:
                        vector<DWORD> results{};

                        explicit CallbackFindFirstProcessIdByPath(const string &targetProcessPath) {
                            this->targetProcessPath = targetProcessPath;
                            this->filterType = base::callback::FilterType::ANY;
                        }

                        int32_t Callback(const DWORD processId) override {
                            int32_t retCode = ERROR_SUCCESS;
                            string path{};
                            retCode = GetProcessPathById(processId, path);
                            if (ERROR_SUCCESS != retCode) {
                                return retCode;
                            }
                            if (path == targetProcessPath) {
                                results.push_back(processId);
                                return ERROR_SUCCESS;
                            }
                            return ERROR_NOT_FOUND;
                        }

                        bool ToBeContinued() override {
                            return results.empty();
                        }
                    };

                    static BOOL WINAPI NtTerminateProcessWrapper(HANDLE hProcess) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.NtDll.NtTerminateProcess) {
                            return FALSE;
                        }
                        return api.NtDll.NtTerminateProcess(hProcess, 0);
                    }

                    inline int32_t TerminateProcesses(_In_ const string &processName) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.NtDll.NtTerminateProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        CallbackForBoolWIN32ProcessAPIByPath callback(processName, NtTerminateProcessWrapper);
                        auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                        return EnumerateProcesses(callbacks);
                    }

                    inline int32_t SuspendProcesses(_In_ const string &processName) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.NtDll.NtSuspendProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        CallbackForBoolWIN32ProcessAPIByPath callback(processName, api.NtDll.NtSuspendProcess);
                        auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                        return EnumerateProcesses(callbacks);
                    }

                    inline int32_t ResumeProcesses(_In_ const string &processName) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.NtDll.NtResumeProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        CallbackForBoolWIN32ProcessAPIByPath callback(processName, api.NtDll.NtResumeProcess);
                        auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                        return EnumerateProcesses(callbacks);
                    }

                    inline int32_t ExecuteInSessionsNot0(_In_ const string &cmd) {
                        /*
                         * 枚举当前的 explorer.exe 进程
                         * 获取进程所属的用户
                         * 获取对应的令牌
        BOOL CreateProcessAsUserA(
          [in, optional]      HANDLE                hToken,
          [in, optional]      LPCSTR                lpApplicationName,
          [in, out, optional] LPSTR                 lpCommandLine,
          [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
          [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
          [in]                BOOL                  bInheritHandles,
          [in]                DWORD                 dwCreationFlags,
          [in, optional]      LPVOID                lpEnvironment,
          [in, optional]      LPCSTR                lpCurrentDirectory,
          [in]                LPSTARTUPINFOA        lpStartupInfo,
          [out]               LPPROCESS_INFORMATION lpProcessInformation
        );
                         */
                        int32_t retCode = ERROR_SUCCESS;
                        // todo 寻找非当前用户的 explorer.exe
                        // 寻找第一个explorer.exe
                        const string &explorer = path::GetExplorerPath();
                        auto callback = CallbackFindFirstProcessIdByPath(explorer);
                        auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                        retCode = EnumerateProcesses(callbacks);
                        if (ERROR_SUCCESS != retCode) {
                            log_error("xxx"); // todo
                            goto __ERROR__;
                        }
                        if (callback.results.empty()) {
                            retCode = ERROR_NOT_FOUND;
                            log_error("xxx"); // todo
                            goto __ERROR__;
                        }
                        const auto pid = callback.results[0];
                        // OpenProcessToken();
                        // CreateProcessAsUser();
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:

                        return ERROR_EMPTY;
                    }
                }

                namespace path {
                    inline INT32 GetCurrentPath(_Out_ string &path) {
                        return process::GetProcessPathById(GetCurrentProcessId(), path);
                    }

                    inline string GetCurrentPath() {
                        string path;
                        GetCurrentPath(path);
                        return path;
                    }

                    inline string GetCurrentDir() {
                        const auto p = GetCurrentPath();
                        const auto n = p.rfind('\\');
                        if (n != string::npos) {
                            return p.substr(0, n);
                        }
                        return "";
                    }
                }

                namespace trick {
                    inline INT32 PrivilegeUp() {
                        int32_t result = ERROR_SUCCESS;
                        HANDLE hToken = nullptr;
                        LUID luId;
                        TOKEN_PRIVILEGES tkp;

                        BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
                        if (!bRet) {
                            DWORD e = GetLastError();
                            log_error("[x] OpenProcessToken failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        bRet = LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luId);
                        if (!bRet) {
                            DWORD e = GetLastError();
                            log_error("[x] LookupPrivilegeValue failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        tkp.PrivilegeCount = 1;
                        tkp.Privileges[0].Luid = luId;
                        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                        bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr);
                        if (!bRet) {
                            DWORD e = GetLastError();
                            log_error("[x] AdjustTokenPrivileges failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        log_trace("[$] Utility$$$PrivilegeUp success");

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        if (nullptr != hToken) {
                            CloseHandle(hToken);
                            hToken = nullptr;
                        }

                        return result;
                    }

                    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wEvent, LPARAM lpKBDLLHookStructParam) {
                        const auto lpHookSt = reinterpret_cast<LPKBDLLHOOKSTRUCT>(lpKBDLLHookStructParam);

                        LRESULT result;

                        if (lpHookSt->vkCode == (VK_LBUTTON | 0x57)) {
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
                        log_trace("KeyboardProc Event [%s], vkCode [%lu], result [%d]", szEvent, lpHookSt->vkCode,
                                  result);
#endif

                        return result;
                    }

                    inline INT32 Keyboard(const BOOL enable) {
                        // 全局钩子
                        static HHOOK hKeyBoard = nullptr;
                        if (!enable) {
                            if (nullptr == hKeyBoard) {
                                hKeyBoard = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandle(nullptr), 0);
                            }
                        } else {
                            if (nullptr != hKeyBoard) {
                                UnhookWindowsHookEx(hKeyBoard);
                                hKeyBoard = nullptr;
                            }
                        }
                        UINT64 retCode{};
                        memmove(&retCode, &hKeyBoard, sizeof(HHOOK));
                        return static_cast<INT32>(retCode);
                    }

                    inline INT32 TaskManager(const BOOL enable) {
                        const auto &api = api::API::Instance();
                        if (nullptr == api.NtDll.NtTerminateProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }
                        // 两种方法
                        // 1. 直接执行命令 taskkill.exe /f /im taskmgr.exe
                        // 2. 遍历进程后发送关闭的消息
                        int32_t result = ERROR_SUCCESS; {
                            const auto &tm_path = utility::path::GetTaskMgrPath();
                            // 关闭已开启的 【任务管理器】
                            result = process::TerminateProcesses(tm_path);
                            if (ERROR_SUCCESS != result) {
                                log_error("[x] TerminateProcesses failed");
                            }
                        } {
                            static auto hTaskMgr = INVALID_HANDLE_VALUE;
                            if (INVALID_HANDLE_VALUE != hTaskMgr && enable) {
                                CloseHandle(hTaskMgr);
                                hTaskMgr = INVALID_HANDLE_VALUE;
                                log_trace("[x] taskmgr.exe file handle closed");
                                goto __FREE__;
                            }
                            if (INVALID_HANDLE_VALUE == hTaskMgr && !enable) {
                                // 以独占方式打开 taskmgr.exe，防止被运行。
                                hTaskMgr = CreateFile(
                                    utility::path::GetTaskMgrPath().data(),
                                    0,
                                    0,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr
                                );
                                if (INVALID_HANDLE_VALUE == hTaskMgr) {
                                    DWORD e = GetLastError();
                                    log_error("[x] CreateFile failed: [0x%lx]%s", e, FormatError(e).data());
                                    result = static_cast<int32_t>(e);
                                    goto __ERROR__;
                                }
                                log_trace("[^] taskmgr.exe file handle opened");
                            }
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:

                        return result;
                    }

                    inline INT32 CtrlAltDel(const BOOL enable) {
                        // 参考 https://blog.csdn.net/qq_23313467/article/details/107957442
                        int32_t result = ERROR_SUCCESS;
                        if (enable) {
                            result = process::ResumeProcesses(utility::path::GetWinLogoPath());
                        } else {
                            result = process::SuspendProcesses(utility::path::GetWinLogoPath());
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return result;
                    }
                }
            }
        }
    }
}

#endif //CPL_UTILITY_HPP_SUNSET_GRANITE_VIBRANT_PIONEER_MYSTIC_FORTIFY_LUMINOUS_ENIGMA
