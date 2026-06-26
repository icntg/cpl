#ifndef CPL_UTILITY_HPP_SUNSET_GRANITE_VIBRANT_PIONEER_MYSTIC_FORTIFY_LUMINOUS_ENIGMA
#define CPL_UTILITY_HPP_SUNSET_GRANITE_VIBRANT_PIONEER_MYSTIC_FORTIFY_LUMINOUS_ENIGMA

#include <string>
#include <unordered_map>
#include <cstdint>
#include <utility>
#include <windows.h>
#include <tchar.h>

#include "api.hpp"
#include "../utility/base.hpp"
#include "../utility/strings.hpp"
#include "../vendor/emilk/loguru/loguru.hpp"


using namespace std;
using namespace cpl::base::callback;

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

                inline int32_t ReadFile(_In_ const string &filename, _Out_ string &content) {
                    int32_t retCode = ERROR_SUCCESS;
                    FILE *fp{};
                    content.clear();
                    // 打开文件
                    {
                        const auto r0 = fopen_s(&fp, filename.data(), "rb");
                        if (r0 != 0 || fp == nullptr) {
                            LOG_F(ERROR, "[x] fopen_s [%s] failed: %ld", filename.data(), static_cast<long>(r0));
                            retCode = r0;
                            goto __ERROR__;
                        }
                    }
                    // 读取整个文件
                    {
                        // 获取文件大小
                        const auto r0 = fseek(fp, 0, SEEK_END);
                        const auto fileSize = ftell(fp);
                        if (fileSize == -1L) {
                            // 处理 fseek 或 ftell 失败的情况
                            LOG_F(ERROR, "[x] ftell failed");
                            retCode = r0 | fileSize;
                            goto __ERROR__;
                        }
                        fseek(fp, 0, SEEK_SET);
                        // 为读取预留空间，并额外分配一个字节用于存储可能的空字符
                        content.resize(static_cast<size_t>(fileSize) + 1);
                        // 使用 fread_s 读取文件内容
                        const auto bytesRead = fread_s(&content[0], content.size(), 1, fileSize, fp);
                        if (bytesRead != static_cast<size_t>(fileSize)) {
                            LOG_F(ERROR, "[x] fread_s failed");
                            retCode = static_cast<int32_t>(fileSize ^ bytesRead);
                            goto __ERROR__;
                        }
                        content.resize(bytesRead); // 调整字符串大小以匹配实际读取的字节数
                    }
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    if (nullptr != fp) {
                        fclose(fp);
                    }
                    return retCode;
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
                            LOG_F(ERROR, "[x] CreateFile [%s] failed: [0x%lu] %s", filename.data(), e,
                                      FormatError(e).data());
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
                            LOG_F(ERROR, "CreateFileMapping failed: [0x%lx]%s", e, FormatError(e).data());
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
                            LOG_F(ERROR, "MapViewOfFile failed: [0x%lx]%s", e, FormatError(e).data());
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
                                LOG_F(ERROR, "UnmapViewOfFile failed: [0x%lx]%s", e, FormatError(e).data());
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

                    bool IsLoaded() override {
                        return true;
                    }

                    explicit FileMappingContext(const string &filename) {
                        this->filename = filename;
                        const INT32 retCode = Load();
                        if (ERROR_SUCCESS != retCode) {
                            LOG_F(ERROR, "[x] failed to map file");
                            // throw runtime_error("failed to map file");
                        }
                    }

                    ~FileMappingContext() override {
                        const INT32 retCode = Unload();
                        if (ERROR_SUCCESS != retCode) {
                            LOG_F(ERROR, "[x] failed to ummap file");
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
                    static const auto ret = string(buffer);
                    return ret;
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

                inline INT32 GetWindowsVersion(
                    _Out_ DWORD *dwMajorVersion,
                    _Out_ DWORD *dwMinorVersion = nullptr,
                    _Out_ DWORD *dwBuildNumber = nullptr
                ) {
                    const auto& api = api::GetInstance();
                    RTL_OSVERSIONINFOW osvi = {0};
                    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
                    const auto r0 = api->NtDll.RtlGetVersion(&osvi);
                    if (nullptr != dwMajorVersion) {
                        *dwMajorVersion = osvi.dwMajorVersion;
                    }
                    if (nullptr != dwMinorVersion) {
                        *dwMinorVersion = osvi.dwMinorVersion;
                    }
                    if (nullptr != dwBuildNumber) {
                        *dwBuildNumber = osvi.dwBuildNumber;
                    }
                    return static_cast<INT32>(r0);
                }

                inline DWORD GetWindowsMajorVersion() {
                    DWORD dwMajorVersion{};
                    GetWindowsVersion(&dwMajorVersion, nullptr, nullptr);
                    return dwMajorVersion;
                }

                inline INT32 GetComputerNames(
                    string *NetBIOS = nullptr,
                    string *DNSHostname = nullptr,
                    string *DNSDomain = nullptr,
                    string *DNSFullyQualified = nullptr,
                    string *PhysicalNetBIOS = nullptr,
                    string *PhysicalDNSHostname = nullptr,
                    string *PhysicalDNSDomain = nullptr,
                    string *PhysicalDNSFullyQualified = nullptr,
                    string *ComputerNameMax = nullptr
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
LOG_F(ERROR, "[x] GetComputerNameEx (%s) failed [0x%lx]: %s", #name, e, FormatError(e).data()); \
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
                    string user1{}, user2{};
                    int32_t r1{}, r2{};
                    // 使用GetUserNameA
                    {
                        string username{};
                        DWORD size = BUFSIZ << 2u;
                        username.reserve(size);
                        username.resize(size);
                        const auto r00 = GetUserNameA(&username[0], &size);
                        if (!r00) {
                            const DWORD e = GetLastError();
                            r1 = static_cast<INT32>(e);
                            LOG_F(ERROR, "[x] GetUserName failed [0x%lx]: %s", e, FormatError(e).data());
                        }
                        username.resize(size);
                        LOG_F(INFO, "[+] Username by GetUserNameA: %s", username.data());
                        user1 = username;
                    }
                    // 使用环境变量
                    // 服务形式启动的话，获取的是"主机名$"的名称。
                    {
                        string username{};
                        constexpr auto size = BUFSIZ << 2u;
                        username.reserve(size);
                        username.resize(size);
                        const auto r00 = GetEnvironmentVariableA("USERNAME", &username[0], size);
                        if (0 == r00) {
                            const DWORD e = GetLastError();
                            r2 = static_cast<INT32>(e);
                            LOG_F(ERROR, "[x] GetEnvironmentVariable(USERNAME) failed [0x%lx]: %s", e,
                                      FormatError(e).data());
                        }
                        username.resize(r00);
                        LOG_F(INFO, "[+] Username from EnvironmentVariable: %s", username.data());
                        user2 = username;
                    }
                    if (r1 != ERROR_SUCCESS && r2 != ERROR_SUCCESS) {
                        LOG_F(ERROR, "[x] GetCurrentUser failed %ld, %ld", r1, r2);
                        retCode = r1 | r2;
                        goto __ERROR__;
                    } else if (r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS) {
                        if (user1 == user2) {
                            // 如果两者一致，说明是以普通方式启动。选择其中一个返回即可。
                            user = user1;
                            LOG_F(MAX, "running in normal mode");
                            if (nullptr != runningMode) {
                                *runningMode = 0;
                            }
                        } else {
                            // 如果两者不一致，说明以服务方式启动，对两者做一个拼接。
                            const auto hostname = user2;
                            const auto username = user1;
                            user = hostname + "\\\\" + username;
                        }
                    } else if (r1 == ERROR_SUCCESS) {
                        user = user1;
                    } else {
                        user = user2;
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
                        LOG_F(ERROR, "[x] GetTempPath failed [0x%lx]: %s", e, FormatError(e).data());
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
                        LOG_F(ERROR, "GetDesktopWindow failed: [0x%x]%s", e, FormatError(e).data());
                        retCode = static_cast<INT32>(e);
                        goto __ERROR__;
                    }
                    hMonitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
                    if (nullptr == hMonitor) {
                        const DWORD e = GetLastError();
                        LOG_F(ERROR, "MonitorFromWindow failed: [0x%x]%s", e, FormatError(e).data());
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

                    LOG_F(MAX,
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
                                LOG_F(ERROR, "[x] Core$$$GetUsername failed: [0x%lx]");
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
                                LOG_F(ERROR, "[x] CreateMutex failed: [0x%lx]%s", e, FormatError(e).data());
                                result = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        } else {
                            // 如果有，说明已经有了，不准多开
                            LOG_F(ERROR, "[x] ifw is already running");
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
                        const auto &api = api::GetInstance();
                        INT32 retCode = ERROR_SUCCESS;
                        HANDLE hProcess = nullptr;
                        NTSTATUS ntStatus = 0;
                        PROCESS_BASIC_INFORMATION processBasicInformation;

                        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                        if (nullptr == hProcess) {
                            const DWORD e = GetLastError();
                            retCode = static_cast<INT32>(e);
                            LOG_F(ERROR, "[x] OpenProcess failed [0x%lx]: %s", e, FormatError(e).data());
                            goto __ERROR__;
                        }
                        bzero(&processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION));
                        ntStatus = api->NtDll.NtQueryInformationProcess(
                            hProcess,
                            ProcessBasicInformation,
                            &processBasicInformation,
                            sizeof(PROCESS_BASIC_INFORMATION),
                            nullptr
                        );
                        // if (!NT_SUCCESS(ntStatus))
                        if (ntStatus < 0) {
                            retCode = ntStatus;
                            LOG_F(ERROR, "[x] NtQueryInformationProcess failed [0x%lx]", ntStatus);
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
                        const auto &api = api::GetInstance();
                        if (nullptr == api->PsAPI.GetModuleFileNameExA && nullptr == api->Kernel32.
                            QueryFullProcessImageNameA) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        int32_t result = ERROR_SUCCESS;
                        TCHAR buffer[MAX_PATH << 1u] = {};

                        // QueryFullProcessImageName 是Vista及以上才支持的API，优先调用该API
                        if (nullptr != api->Kernel32.QueryFullProcessImageNameA) {
                            DWORD bufferSize = sizeof(buffer);
                            const auto r00 = api->Kernel32.QueryFullProcessImageNameA(hProcess, 0, buffer, &bufferSize);
                            if (0 == r00) {
                                const auto e = GetLastError();
                                LOG_F(MAX, "[x] QueryFullProcessImageNameA failed: [0x%lx]%s", e, FormatError(e).data());
                                result = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        }
                        // 如果QueryFullProcessImageName不可用，则调用传统的GetModuleFileNameExA（x64/x86体系结构可能会影响）
                        else {
                            const auto dwRet = api->PsAPI.
                                    GetModuleFileNameExA(hProcess, nullptr, buffer, sizeof(buffer));
                            if (0 == dwRet) {
                                const auto e = GetLastError();
                                LOG_F(MAX, "[x] GetModuleFileNameExA failed: [0x%lx]%s", e, FormatError(e).data());
                                result = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
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
                            LOG_F(MAX, "OpenProcess [%lu] failed: [0x%lx]%s", dwProcessId, e, FormatError(e).data());
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

<<<<<<< HEAD
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
=======

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
                        _In_ const vector<ICallback<DWORD> *> &Callbacks
                    ) {
                        const auto &api = api::GetInstance();
                        if (nullptr == api->PsAPI.EnumProcesses ||
                            nullptr == api->PsAPI.GetModuleFileNameExA
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
                                LOG_F(ERROR, "[x] calloc failed: ERROR_NOT_ENOUGH_MEMORY");
                                goto __ERROR__;
                            }
                            for (;;) {
                                bRet = api->PsAPI.EnumProcesses(pProcBuf, cb, &cbNeeded);
                                if (!bRet) {
                                    DWORD e = GetLastError();
                                    LOG_F(ERROR, "[x] EnumProcess failed: [0x%lx]%s", e, FormatError(e).data());
                                    retCode = static_cast<int32_t>(e);
                                    goto __ERROR__;
                                }
                                if (cbNeeded >= cb) {
                                    cb = cbNeeded << 1u; // 为防止进程增加，扩大一倍再调整空间。
                                    void *p = realloc(pProcBuf, cb);
                                    if (nullptr == p) {
                                        // 如果这里realloc失败，直接赋值给pProcBuf的话，会导致pProcBuf原内存泄露。
                                        retCode = ERROR_NOT_ENOUGH_MEMORY;
                                        LOG_F(ERROR, "[x] realloc failed: ERROR_NOT_ENOUGH_MEMORY");
                                        goto __ERROR__;
                                    }
                                    pProcBuf = static_cast<DWORD *>(p);
                                } else {
                                    break;
                                }
                            }
                        }
                        //
                        {
                            const DWORD cProcesses = cbNeeded / sizeof(DWORD);
                            for (size_t i = 0; i < cProcesses; i++) {
                                if (pProcBuf[i] != 0) {
                                    const DWORD pid = pProcBuf[i];
                                    bool allToBeContinued = false;
                                    for (const auto &callback: Callbacks) {
                                        if (nullptr == callback) {
                                            continue;
                                        }
                                        const auto r00 = callback->Callback(pid);
                                        if (ERROR_SUCCESS != r00) {
                                            PASS; // 这个结果不应该影响Enum函数。
                                        }
                                        allToBeContinued |= callback->ToBeContinued();
                                    }
                                    if (!allToBeContinued) {
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

                    typedef BOOL (WINAPI *Win32ProcessAPI)(HANDLE hProcess);

                    class CallbackForBoolWIN32ProcessAPIByPath final : public ICallback<DWORD> {
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
                            filterType = FilterType::ALL;
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
                        const auto &api = api::GetInstance();
                        if (nullptr == api->NtDll.NtTerminateProcess) {
                            return FALSE;
                        }
                        return api->NtDll.NtTerminateProcess(hProcess, 0);
                    }

                    inline int32_t TerminateProcesses(_In_ const string &processName) {
                        const auto &api = api::GetInstance();
                        if (nullptr == api->NtDll.NtTerminateProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        CallbackForBoolWIN32ProcessAPIByPath callback(processName, NtTerminateProcessWrapper);
                        auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                        return EnumerateProcesses(callbacks);
                    }

                    inline int32_t SuspendProcesses(_In_ const string &processName) {
                        const auto &api = api::GetInstance();
                        if (nullptr == api->NtDll.NtSuspendProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        CallbackForBoolWIN32ProcessAPIByPath callback(processName, api->NtDll.NtSuspendProcess);
                        auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                        return EnumerateProcesses(callbacks);
                    }

                    inline int32_t ResumeProcesses(_In_ const string &processName) {
                        const auto &api = api::GetInstance();
                        if (nullptr == api->NtDll.NtResumeProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }

                        CallbackForBoolWIN32ProcessAPIByPath callback(processName, api->NtDll.NtResumeProcess);
                        auto callbacks = vector<ICallback<DWORD> *>() = {&callback};
                        return EnumerateProcesses(callbacks);
                    }
                }

                namespace session {
                    inline INT32 GetSessionIdByHWND(_In_ HWND hwnd, _Out_ DWORD &sessionId) {
                        const auto &api = api::GetInstance();
                        DWORD processId{};
                        INT32 retCode{};
                        const auto threadId = GetWindowThreadProcessId(hwnd, &processId);
                        if (0 == threadId) {
                            const auto e = GetLastError();
                            LOG_F(ERROR, "[x] GetWindowThreadProcessId failed 0x%lx:%s", e, FormatError(e).data());
                            goto __ERROR__;
                        }
                        retCode = static_cast<INT32>(threadId);
                        const auto r01 = api->Kernel32.ProcessIdToSessionId(processId, &sessionId);
                        if (!r01) {
                            const auto e = GetLastError();
                            LOG_F(ERROR, "[x] ProcessIdToSessionId failed 0x%lx:%s", e, FormatError(e).data());
                            goto __ERROR__;
                        }
                        retCode |= static_cast<INT32>(r01);
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    inline DWORD GetCurrentSessionId() {
                        const auto &api = api::GetInstance();
                        DWORD sessionId = 0xffffffff;
                        if (nullptr == api->Kernel32.ProcessIdToSessionId) {
                            LOG_F(MAX, "[x] api.Kernel32.ProcessIdToSessionId == nullptr");
                            goto __ERROR__;
                        }
                        const auto r0 = api->Kernel32.ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
                        if (!r0) {
                            const auto e = GetLastError();
                            LOG_F(ERROR, "[x] ProcessIdToSessionId failed 0x%lx:%s", e, FormatError(e).data());
                            goto __ERROR__;
                        }
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return sessionId;
                    }

                    inline INT32 ExecuteCommandInCurrentSession(_In_ const string &cmd) {
                        INT32 retCode = ERROR_SUCCESS;
                        PROCESS_INFORMATION pi{};
                        STARTUPINFOA si = {sizeof(si)};
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
                            const auto e = GetLastError();
                            LOG_F(ERROR, "[x] CreateProcess failed 0x%lx:%s", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        goto __FREE__;

                    __ERROR__:
                        PASS;
                    __FREE__:
>>>>>>> dev-merge
                        if (nullptr != pi.hThread) {
                            CloseHandle(pi.hThread);
                            pi.hThread = nullptr;
                        }
                        if (nullptr != pi.hProcess) {
                            CloseHandle(pi.hProcess);
                            pi.hProcess = nullptr;
                        }
<<<<<<< HEAD
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
=======
                        // system,WinExec， ShellExecute，CreateProcess
                        return retCode;
                        // CreateProcessA()
                    }

                    inline INT32 ExecuteCommandInCurrentSession(_In_ const wstring &cmd) {
                        INT32 retCode = ERROR_SUCCESS;
                        PROCESS_INFORMATION pi{};
                        STARTUPINFOW si = {sizeof(si)};
                        // 创建进程
                        const auto r0 = CreateProcessW(
                            nullptr, // 不指定模块名称，使用命令行
                            const_cast<LPWSTR>(cmd.data()), // 命令行字符串
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
                            const auto e = GetLastError();
                            LOG_F(ERROR, "[x] CreateProcess failed 0x%lx:%s", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        goto __FREE__;

                    __ERROR__:
                        PASS;
                    __FREE__:
                        if (nullptr != pi.hThread) {
                            CloseHandle(pi.hThread);
                            pi.hThread = nullptr;
                        }
                        if (nullptr != pi.hProcess) {
                            CloseHandle(pi.hProcess);
                            pi.hProcess = nullptr;
                        }
                        // system,WinExec， ShellExecute，CreateProcess
                        return retCode;
                        // CreateProcessA()
                    }

                    inline INT32 ExecuteCommandInSession(_In_ const string &cmd, _In_ const DWORD sessionId) {
                        INT32 retCode = ERROR_SUCCESS;
                        const auto &api = api::GetInstance();
                        HANDLE hToken{}, hNewToken{};
                        STARTUPINFOA si = {sizeof(si)};
                        si.lpDesktop = const_cast<LPSTR>("winsta0\\default");
                        PROCESS_INFORMATION pi{};

                        if (nullptr == api->WtsApi32.WTSQueryUserToken) {
                            retCode = ERROR_API_UNAVAILABLE;
                            goto __ERROR__;
                        }
                        //
                        {
                            const auto r0 = api->WtsApi32.WTSQueryUserToken(sessionId, &hToken);
                            if (!r0) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] WTSQueryUserToken failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
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
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] DuplicateTokenEx failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
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
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] CreateProcessAsUserA failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
>>>>>>> dev-merge
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
<<<<<<< HEAD
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
=======
                        }
                        if (nullptr != hToken) {
                            CloseHandle(hToken);
                        }
                        return retCode;
                    }

                    inline INT32 ExecuteCommandInSession(_In_ const wstring &cmd, _In_ const DWORD sessionId) {
                        INT32 retCode = ERROR_SUCCESS;
                        const auto &api = api::GetInstance();
                        HANDLE hToken{}, hNewToken{};
                        STARTUPINFOW si = {sizeof(si)};
                        si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
                        PROCESS_INFORMATION pi{};
                        if (nullptr == api->WtsApi32.WTSQueryUserToken) {
                            retCode = ERROR_API_UNAVAILABLE;
                            goto __ERROR__;
                        }
                        //
                        {
                            const auto r0 = api->WtsApi32.WTSQueryUserToken(sessionId, &hToken);
                            if (!r0) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] WTSQueryUserToken failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
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
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] DuplicateTokenEx failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        }
                        //
                        {
                            const auto r0 = CreateProcessAsUserW(
                                hNewToken,
                                nullptr,
                                const_cast<LPWSTR>(cmd.data()),
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
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] CreateProcessAsUserW failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
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
                        return retCode;
                    }

                    inline INT32 ExecuteCommandInActiveConsoleSession(_In_ const string &cmd) {
                        const auto &api = api::GetInstance();
                        if (nullptr == api->Kernel32.WTSGetActiveConsoleSessionId) {
                            return ERROR_API_UNAVAILABLE;
                        }
                        const auto sessionId = api->Kernel32.WTSGetActiveConsoleSessionId();
                        if (sessionId != 0xFFFFFFFF) {
                            return ExecuteCommandInSession(cmd, sessionId);
                        }
                        return ERROR_NOT_FOUND;
                    }

                    inline INT32 ExecuteCommandInActiveConsoleSession(_In_ const wstring &cmd) {
                        const auto &api = api::GetInstance();
                        if (nullptr == api->Kernel32.WTSGetActiveConsoleSessionId) {
                            return ERROR_API_UNAVAILABLE;
                        }
                        const auto sessionId = api->Kernel32.WTSGetActiveConsoleSessionId();
                        if (sessionId != 0xFFFFFFFF) {
                            return ExecuteCommandInSession(cmd, sessionId);
                        }
                        return ERROR_NOT_FOUND;
                    }

                    inline INT32
                    ExecuteCommandInSessionFromProcessHandle(_In_ const string &cmd, _In_ const HANDLE hProcess) {
                        INT32 retCode = ERROR_SUCCESS;
                        HANDLE hToken{}, hNewToken{};
                        STARTUPINFOA si = {sizeof(si)};
                        PROCESS_INFORMATION pi{}; {
                            const auto r0 = OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken);
                            if (!r0) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] OpenProcessToken failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        } {
                            const auto r0 = DuplicateTokenEx(
                                hToken,
                                MAXIMUM_ALLOWED,
                                nullptr,
                                SecurityIdentification,
                                TokenPrimary,
                                &hNewToken);
                            if (!r0) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] DuplicateTokenEx failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        } {
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
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[x] CreateProcessAsUserA failed 0x%lx:%s", e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
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
                        return retCode;
                    }

                    inline INT32 ExecuteCommandInSessionFromProcessId(
                        _In_ const string &cmd, _In_ const DWORD processId) {
                        INT32 retCode = ERROR_SUCCESS;
                        const HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
                        if (hProcess == nullptr) {
                            const auto e = GetLastError();
                            LOG_F(ERROR, "[x] OpenProcessToken failed 0x%lx:%s", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        retCode = ExecuteCommandInSessionFromProcessHandle(cmd, hProcess);
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        if (nullptr != hProcess) {
                            CloseHandle(hProcess);
                        }
                        return retCode;
                    }

                    /**
                     * 遍历系统进程，查找符合进程名字的ProcessId
                     * 获取进程Session，并保存到sessions中。回调完成后，可使用GetSessions获取这些Session。
                     */
                    class CallbackRunCommandInSessionByTargetProcessId final : public ICallback<DWORD> {
                    protected:
                        // SessionId, RunCommandResult
                        unordered_map<DWORD, INT32> map{};
                        string cmd{};
                        string targetProcessName{};
                        bool exceptCurrentSession{true};
                        DWORD currentSessionId{};

                    public:
                        explicit CallbackRunCommandInSessionByTargetProcessId(
                            string cmd,
                            string process_name = "C:\\Windows\\explorer.exe",
                            const bool exceptCurrentSession = TRUE
                        ): cmd(std::move(cmd)),
                           targetProcessName(std::move(process_name)),
                           exceptCurrentSession(exceptCurrentSession) {
                            Lower(this->targetProcessName);
                            currentSessionId = GetCurrentSessionId();
                        }

                        int32_t Callback(const DWORD processId) override {
                            const auto &api = api::GetInstance();
                            int32_t retCode = ERROR_SUCCESS;
                            string currentPath{};
                            DWORD sessionId{};
                            // 比较进程信息是否与目标进程名称相同
                            {
                                const auto r0 = process::GetProcessPathById(processId, currentPath);
                                if (r0 != ERROR_SUCCESS) {
                                    retCode = r0;
                                    goto __ERROR__;
                                }
                                Lower(currentPath);
                                LOG_F(MAX, "[#] currentPath = %s, targetPath = %s", currentPath.data(),
                                          targetProcessName.data());
                                if (currentPath != targetProcessName) {
                                    retCode = ERROR_NOT_FOUND;
                                    goto __ERROR__;
                                }
                                LOG_F(MAX, "[#] found target process [%lu] %s", processId, currentPath.data());
                            }
                            //GetSession?
                            {
                                const auto r1 = api->Kernel32.ProcessIdToSessionId(processId, &sessionId);
                                if (!r1) {
                                    const auto e = GetLastError();
                                    retCode = static_cast<int32_t>(e);
                                    LOG_F(ERROR, "[x] ProcessIdToSessionId failed 0x%lx:%s", e, FormatError(e).data());
                                    goto __ERROR__;
                                }
                            }
                            // 检查是否排除自身
                            {
                                if (exceptCurrentSession && sessionId == currentSessionId) {
                                    retCode = ERROR_NOT_OWNER;
                                    goto __FREE__;
                                }
                            }
                            // 检查该session是否已经运行
                            {
                                if (map.find(sessionId) == map.end() || map.at(sessionId) != ERROR_SUCCESS) {
                                    INT32 r00 = ERROR_SUCCESS;
                                    if (sessionId == currentSessionId) {
                                        r00 = ExecuteCommandInCurrentSession(cmd);
                                    } else {
                                        r00 = ExecuteCommandInSession(this->cmd, sessionId);
                                    }
                                    map[sessionId] = r00;
                                    // map.insert({ sessionId, r00 });
                                    //map.at(sessionId) = r00;
                                    if (r00 != ERROR_SUCCESS) {
                                        retCode = r00;
                                        LOG_F(ERROR,
                                            "[x] ExecuteCommand [%s] InSession [%lu] FromProcessId [%lu] failed: %ld",
                                            cmd.data(), sessionId, processId, r00);
                                        goto __ERROR__;
                                    }
                                }
                            }
                            goto __FREE__;
                        __ERROR__:
                            PASS;
                        __FREE__:
                            this->resultList.push_back(retCode);
                            return retCode;
                        }

                        bool ToBeContinued() override {
                            return true;
                        }

                        unordered_map<DWORD, INT32> &GetSessionWithExecuteResult() {
                            return this->map;
                        }
                    };

                    inline INT32 ExecuteCommandsInSessionsFromProcessName(
                        _In_ const string &cmd,
                        _In_ const BOOL exceptCurrentSession = TRUE,
                        _In_ const string &processName = "C:\\Windows\\explorer.exe"
                    ) {
                        INT32 retCode = ERROR_SUCCESS;
                        auto callback = CallbackRunCommandInSessionByTargetProcessId(
                            cmd, processName, exceptCurrentSession);
                        auto callbacks = vector<ICallback<DWORD> *>{&callback};
                        // todo
                        const auto r00 = process::EnumerateProcesses(callbacks);
                        if (r00 != ERROR_SUCCESS) {
                            PASS; // 这个结果没什么影响。。。
                        }
                        // callback
                        const auto sessionWithExecuteResult = callback.GetSessionWithExecuteResult();
                        for (auto it = sessionWithExecuteResult.begin(); it != sessionWithExecuteResult.end(); ++it) {
                            const auto sessionId = it->first;
                            const auto result = it->second;
                            LOG_F(INFO, "[!] execute [%s] in session [%lu] result [%ld]", cmd.data(), sessionId, result);
                            retCode |= result;
                        }
                        return retCode;
                    }

                    //             inline int32_t ExecuteInSessionsNot0(_In_ const string &cmd) {
                    //                 /*
                    //                  * 枚举当前的 explorer.exe 进程
                    //                  * 获取进程所属的用户
                    //                  * 获取对应的令牌
                    // BOOL CreateProcessAsUserA(
                    //   [in, optional]      HANDLE                hToken,
                    //   [in, optional]      LPCSTR                lpApplicationName,
                    //   [in, out, optional] LPSTR                 lpCommandLine,
                    //   [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
                    //   [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
                    //   [in]                BOOL                  bInheritHandles,
                    //   [in]                DWORD                 dwCreationFlags,
                    //   [in, optional]      LPVOID                lpEnvironment,
                    //   [in, optional]      LPCSTR                lpCurrentDirectory,
                    //   [in]                LPSTARTUPINFOA        lpStartupInfo,
                    //   [out]               LPPROCESS_INFORMATION lpProcessInformation
                    // );
                    //                  */
                    //                 int32_t retCode = ERROR_SUCCESS;
                    //                 // todo 寻找非当前用户的 explorer.exe
                    //                 // 寻找第一个explorer.exe
                    //                 const string &explorer = path::GetExplorerPath();
                    //                 auto callback = CallbackFindFirstProcessIdByPath(explorer);
                    //                 auto callbacks = vector<base::callback::ICallback<DWORD> *>() = {&callback};
                    //                 retCode = EnumerateProcesses(callbacks);
                    //                 if (ERROR_SUCCESS != retCode) {
                    //                     log_error("[x] EnumerateProcesses failed");
                    //                     goto __ERROR__;
                    //                 }
                    //                 if (callback.results.empty()) {
                    //                     retCode = ERROR_NOT_FOUND;
                    //                     log_error("[x] cannot find any explorer.exe processes.");
                    //                     goto __ERROR__;
                    //                 } {
                    //                     HANDLE myToken{};
                    //                     const auto r0 = OpenProcessToken(GetCurrentProcess(),
                    //                                                      TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &myToken);
                    //                     if (!r0) {
                    //                         const auto e = GetLastError();
                    //                         log_error("[x] OpenProcessToken failed 0x%lx:%s", e, FormatError(e).data());
                    //                         retCode = static_cast<int32_t>(e);
                    //                         goto __ERROR__;
                    //                     }
                    //                     for (const auto pid: callback.results) {
                    //                         // 每个窗口都弹窗？
                    //                     }
                    //                 }
                    //
                    //                 const auto pid = callback.results[0];
                    //                 // OpenProcessToken();
                    //                 // CreateProcessAsUser();
                    //                 goto __FREE__;
                    //             __ERROR__:
                    //                 PASS;
                    //             __FREE__:
                    //
                    //                 return ERROR_EMPTY;
                    //             }
                }


                // INT32 executeCommand(_In_ const string &cmd) {
                //     INT32 retCode = ERROR_SUCCESS;
                //     const auto &api = api::API::Instance();
                //     PROCESS_INFORMATION pi{};
                //     if (nullptr == api.Wtsapi32.WTSQueryUserToken) {
                //         // 可能是WindowsXP，没有Session的概念，服务和桌面跑在同一个Session下
                //         // 直接调用CreateProcessA
                //         STARTUPINFOA si = {sizeof(si)};
                //         // 创建进程
                //         const auto r0 = CreateProcessA(
                //             nullptr, // 不指定模块名称，使用命令行
                //             const_cast<LPSTR>(cmd.data()), // 命令行字符串
                //             nullptr, // 默认进程属性
                //             nullptr, // 默认线程属性
                //             FALSE, // 不继承句柄
                //             0, // 无创建标志
                //             nullptr, // 使用父进程的环境变量
                //             nullptr, // 使用父进程的当前目录
                //             &si, // 指向 STARTUPINFO 结构
                //             &pi // 接收 PROCESS_INFORMATION 结构
                //         );
                //         if (!r0) {
                //             const auto e = GetLastError();
                //             log_error("[x] CreateProcess failed 0x%lx:%s", e, FormatError(e).data());
                //             retCode = static_cast<int32_t>(e);
                //             goto __ERROR__;
                //         }
                //     } else {
                //         // Vista及以后的系统，服务运行在Session 0下，无法直接创建桌面窗口。
                //     }
                //     goto __FREE__;
                //
                // __ERROR__:
                //     PASS;
                // __FREE__:
                //     if (nullptr != pi.hThread) {
                //         CloseHandle(pi.hThread);
                //         pi.hThread = nullptr;
                //     }
                //     if (nullptr != pi.hProcess) {
                //         CloseHandle(pi.hProcess);
                //         pi.hProcess = nullptr;
                //     }
                //     // system,WinExec， ShellExecute，CreateProcess
                //     return ERROR_SUCCESS;
                //     // CreateProcessA()
                // }

                // static int32_t executeCommandWithSessionOfProcess(
                //     _In_ const string &cmd, _In_ const DWORD processId) {
                // }
                //
                // static int32_t executeCommandWithSessionOfProcess(
                //     _In_ const string &cmd, _In_ const HANDLE hProcess) {
                //     DWORD sessionId = 0;
                // }
                //
                // class CallbackEachSessionRun final : public ICallback<DWORD> {
                // protected:
                //     unordered_set<DWORD> sessionsUsed{};
                //     string cmd{};
                //
                // public:
                //     explicit CallbackEachSessionRun(const string &cmd)
                //         : cmd(cmd) {
                //     }
                //
                //     int32_t Callback(const DWORD processId) override {
                //         // 检测是否是explorer
                //         // 获取sessionId
                //         // 检查该session是否已经启动过。
                //         // 如果没有启动过，启动程序，并将sessionId加入sessionsUsed
                //     }
                //
                //     bool ToBeContinued() override {
                //         return true;
                //     }
                // };


                namespace path {
                    inline INT32 GetCurrentPath(_Out_ string &path) {
                        return sys::process::GetProcessPathById(GetCurrentProcessId(), path);
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

                    inline INT32 CreateDirectoryRecursive(_In_ const wstring &path) {
                        INT32 retCode = ERROR_SUCCESS;
                        if (path.empty()) {
                            retCode = ERROR_INVALID_PARAMETER;
                            goto __ERROR__;
                        }

                        // 使用栈来存储需要创建的目录路径
                        {
                            vector<wstring> dirsToCreate{};
                            dirsToCreate.push_back(path);

                            wstring currentPath{};

                            while (!dirsToCreate.empty()) {
                                currentPath = dirsToCreate.back();
                                dirsToCreate.pop_back();

                                const DWORD fileAttributes = GetFileAttributesW(currentPath.c_str());
                                if (fileAttributes != INVALID_FILE_ATTRIBUTES) {
                                    if (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                                        continue; // 目录已存在，继续下一个
                                    } else {
                                        retCode = ERROR_PATH_NOT_FOUND;
                                        goto __ERROR__; // 路径存在但不是目录
                                    }
                                }
                                // 查找父目录
                                const size_t pos = currentPath.find_last_of(L"\\/");
                                wstring parentPath;
                                if (pos != wstring::npos) {
                                    parentPath = currentPath.substr(0, pos);
                                    // 如果父目录尚未创建，先压入栈
                                    if (GetFileAttributesW(parentPath.data()) == INVALID_FILE_ATTRIBUTES) {
                                        dirsToCreate.push_back(parentPath);
                                    }
                                }

                                // 尝试创建当前目录
                                if (!CreateDirectoryW(currentPath.data(), nullptr)) {
                                    const auto e = GetLastError();
                                    if (e != ERROR_ALREADY_EXISTS && e != ERROR_PATH_NOT_FOUND) {
                                        retCode = static_cast<INT32>(e);
                                        goto __ERROR__;
                                    }
                                }
                            }
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    inline INT32 CreateDirectoryRecursive(_In_ const string &path) {
                        INT32 retCode = ERROR_SUCCESS;
                        size_t pos = 0;
                        string currentPath;

                        // 处理路径分隔符
                        currentPath = path;
                        // 如果存在非windows路径分隔符/，替换为 【\\】
                        replace(currentPath.begin(), currentPath.end(), '/', '\\');

                        // 逐级创建目录
                        while ((pos = currentPath.find_first_of('\\', pos + 1)) != string::npos) {
                            string subPath = currentPath.substr(0, pos);

                            // 检查目录是否存在
                            const DWORD attr = GetFileAttributesA(subPath.data());
                            if (attr == INVALID_FILE_ATTRIBUTES) {
                                // 目录不存在，创建
                                if (!CreateDirectoryA(subPath.data(), nullptr)) {
                                    const auto e = GetLastError();
                                    if (e != ERROR_ALREADY_EXISTS) {
                                        LOG_F(ERROR, "[x] CreateDirectory failed for %s: [0x%lx]%s",
                                                  subPath.data(), e, FormatError(e).data());
                                        retCode = static_cast<int32_t>(e);
                                        goto __ERROR__;
                                    }
                                }
                            } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                                // 路径存在但不是目录
                                retCode = ERROR_FILE_EXISTS;
                                LOG_F(ERROR, "[x] Path exists but is not a directory: %s", subPath.data());
                                goto __ERROR__;
                            }
                        }

                        // 创建最后一级目录
                        if (!CreateDirectoryA(currentPath.data(), nullptr)) {
                            const auto e = GetLastError();
                            if (e != ERROR_ALREADY_EXISTS) {
                                LOG_F(ERROR, "[x] CreateDirectory failed for %s: [0x%lx]%s",
                                          currentPath.data(), e, FormatError(e).data());
                                retCode = static_cast<int32_t>(e);
                                goto __ERROR__;
                            }
                        }
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
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
                            LOG_F(ERROR, "[x] OpenProcessToken failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        bRet = LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luId);
                        if (!bRet) {
                            DWORD e = GetLastError();
                            LOG_F(ERROR, "[x] LookupPrivilegeValue failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        tkp.PrivilegeCount = 1;
                        tkp.Privileges[0].Luid = luId;
                        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                        bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr);
                        if (!bRet) {
                            DWORD e = GetLastError();
                            LOG_F(ERROR, "[x] AdjustTokenPrivileges failed: [0x%lx]%s", e, FormatError(e).data());
                            result = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        LOG_F(ERROR, "[$] Utility$$$PrivilegeUp success");

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
                        LOG_F(MAX, "KeyboardProc Event [%s], vkCode [%lu], result [%d]", szEvent, lpHookSt->vkCode,
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
                        const auto &api = api::GetInstance();
                        if (nullptr == api->NtDll.NtTerminateProcess) {
                            return ERROR_API_UNAVAILABLE;
                        }
                        // 两种方法
                        // 1. 直接执行命令 taskkill.exe /f /im taskmgr.exe
                        // 2. 遍历进程后发送关闭的消息
                        int32_t result = ERROR_SUCCESS; {
                            const auto &tm_path = utility::path::GetTaskMgrPath();
                            // 关闭已开启的 【任务管理器】
                            result = sys::process::TerminateProcesses(tm_path);
                            if (ERROR_SUCCESS != result) {
                                LOG_F(ERROR, "[x] TerminateProcesses failed");
                            }
                        } {
                            static auto hTaskMgr = INVALID_HANDLE_VALUE;
                            if (INVALID_HANDLE_VALUE != hTaskMgr && enable) {
                                CloseHandle(hTaskMgr);
                                hTaskMgr = INVALID_HANDLE_VALUE;
                                LOG_F(MAX, "[x] taskmgr.exe file handle closed");
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
                                    LOG_F(ERROR, "[x] CreateFile failed: [0x%lx]%s", e, FormatError(e).data());
                                    result = static_cast<int32_t>(e);
                                    goto __ERROR__;
                                }
                                LOG_F(MAX, "[^] taskmgr.exe file handle opened");
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
                            result = sys::process::ResumeProcesses(utility::path::GetWinLogoPath());
                        } else {
                            result = sys::process::SuspendProcesses(utility::path::GetWinLogoPath());
                        }

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return result;
                    }
>>>>>>> dev-merge
                }
            }
        }
    }
}
<<<<<<< HEAD
=======

#endif //CPL_UTILITY_HPP_SUNSET_GRANITE_VIBRANT_PIONEER_MYSTIC_FORTIFY_LUMINOUS_ENIGMA
>>>>>>> dev-merge
