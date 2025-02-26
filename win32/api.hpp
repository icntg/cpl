#ifndef CPL_WIN32_API_HPP_SILVER_TREASURE_WONDROUS_HARMONY_FUTURE_GLANCE_MYSTERY_VIBRANT
#define CPL_WIN32_API_HPP_SILVER_TREASURE_WONDROUS_HARMONY_FUTURE_GLANCE_MYSTERY_VIBRANT

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <tchar.h>

#include <cstdio>
#include <string>
#include <wininet.h>

#include "../utility/base.hpp"

using namespace std;

#ifndef PA
#define PA(fnMem, fnDef, fnDll, dynMod, exitOnErr) { \
    fnMem = (fnDef) GetProcAddress ((dynMod) -> hModule, (#fnDll)); \
    if (nullptr == fnMem) { \
        const DWORD e = GetLastError(); \
        retCode = static_cast<INT32>(e); \
        fprintf(stderr, "[x] GetProcAddress <%s> in <%s> failed [0x%lx]: %s\n", (#fnDll), (dynMod) -> szDllName.data(), e, FormatError(e).data()); \
        if (exitOnErr) { goto __ERROR__; } \
    } else { \
        fprintf(stdout, "[!] GetProcAddress <%s> in <%s>@<%p> successfully\n", (#fnDll), (dynMod) -> szDllName.data(), fnMem); \
    } \
}

namespace cpl {
    namespace win32 {
        inline string FormatError(const DWORD errorCode) {
            static TCHAR buffer[BUFSIZ << 2u]{};
            memset(buffer, 0, sizeof(buffer));
            FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM,
                nullptr,
                errorCode,
                0,
                buffer,
                BUFSIZ << 2,
                nullptr
            );
            const size_t n = _tcslen(buffer);
            if (n >= 2 && buffer[n - 2] == _T('\r') && buffer[n - 1] == _T('\n')) {
                buffer[n - 2] = _T('\0');
            }
            return buffer;
        }

        namespace api {
            class DynamicModule : public base::IContext {
            public:
                string szDllName{};
                HMODULE hModule = nullptr;

                int32_t Load() override {
                    INT32 retCode = ERROR_SUCCESS;
                    hModule = LoadLibrary(szDllName.data());
                    if (nullptr == hModule) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        fprintf(stderr, "[x] LoadLibrary <%s> failed [0x%x]: %s\n", szDllName.data(), e, FormatError(e).data());
                        goto __ERROR__;
                    }
                    fprintf(stdout, "[!] LoadLibrary <%s> successfully\n", szDllName.data());
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }

                int32_t Unload() override {
                    INT32 retCode = ERROR_SUCCESS;
                    if (nullptr != hModule) {
                        const BOOL bRet = FreeLibrary(hModule);
                        if (!bRet) {
                            const DWORD e = GetLastError();
                            retCode = static_cast<INT32>(e);
                            fprintf(stderr, "[x] FreeLibrary <%s> failed [0x%x]: %s\n", szDllName.data(), e, FormatError(e).data());
                        }
                        hModule = nullptr;
                    }
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }
            };

            namespace crypto {
                typedef BOOL (WINAPI *CryptGenRandom)(
                    HCRYPTPROV hProv,
                    DWORD dwLen,
                    BYTE *pbBuffer
                );

                typedef BOOL (WINAPI *CryptAcquireContextA)(
                    HCRYPTPROV *phProv,
                    LPCSTR szContainer,
                    LPCSTR szProvider,
                    DWORD dwProvType,
                    DWORD dwFlags
                );

                typedef BOOL (WINAPI *CryptReleaseContext)(
                    HCRYPTPROV hProv,
                    DWORD dwFlags
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("advapi32.DLL");
                    CryptGenRandom CryptGenRandom{};
                    CryptAcquireContextA CryptAcquireContextA{};
                    CryptReleaseContext CryptReleaseContext{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();
                        PA(CryptGenRandom, crypto::CryptGenRandom, CryptGenRandom, this, false);
                        PA(CryptAcquireContextA, crypto::CryptAcquireContextA, CryptAcquireContextA, this, false);
                        PA(CryptReleaseContext, crypto::CryptReleaseContext, CryptReleaseContext, this, false);
                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        CryptGenRandom = nullptr;
                        CryptAcquireContextA = nullptr;
                        CryptReleaseContext = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace ws32 {
                typedef int (WINAPI *WSAStartup)(
                    _In_ WORD wVersionRequested,
                    _Out_ LPWSADATA lpWSAData
                );

                typedef int (WINAPI *WSACleanup)();

                typedef int (WINAPI *WSAGetLastError)();

                typedef SOCKET (WINAPI *socket)(
                    _In_ int af,
                    _In_ int type,
                    _In_ int protocol
                );

                typedef u_short (WINAPI *htons)(
                    _In_ u_short hostshort
                );

                typedef unsigned long (WINAPI *inet_addr)(
                    const char *cp
                );

                typedef int (WINAPI *sendto)(
                    _In_ SOCKET s,
                    _In_ const char *buf,
                    _In_ int len,
                    _In_ int flags,
                    _In_ const sockaddr *to,
                    _In_ int tolen
                );

                typedef int (WINAPI *closesocket)(_In_ SOCKET s);

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("Ws2_32.dll");
                    WSAStartup WSAStartup{};
                    WSACleanup WSACleanup{};
                    WSAGetLastError WSAGetLastError{};
                    socket socket{};
                    htons htons{};
                    inet_addr inet_addr{};
                    sendto sendto{};
                    closesocket closesocket{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(WSAStartup, ws32::WSAStartup, WSAStartup, this, true);
                        PA(WSACleanup, ws32::WSACleanup, WSACleanup, this, true);
                        PA(WSAGetLastError, ws32::WSAGetLastError, WSAGetLastError, this, true);
                        PA(socket, ws32::socket, socket, this, true);
                        PA(closesocket, ws32::closesocket, closesocket, this, true);
                        PA(htons, ws32::htons, htons, this, true);
                        PA(inet_addr, ws32::inet_addr, inet_addr, this, true);
                        PA(sendto, ws32::sendto, sendto, this, true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        WSAStartup = nullptr;
                        WSACleanup = nullptr;
                        WSAGetLastError = nullptr;
                        socket = nullptr;
                        closesocket = nullptr;
                        htons = nullptr;
                        inet_addr = nullptr;
                        sendto = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace inet {
                typedef HINTERNET (WINAPI *InternetOpenA)(
                    LPCSTR lpszAgent,
                    DWORD dwAccessType,
                    LPCSTR lpszProxy,
                    LPCSTR lpszProxyBypass,
                    DWORD dwFlags
                );

                typedef HINTERNET (WINAPI *InternetConnectA)(
                    HINTERNET hInternet,
                    LPCSTR lpszServerName,
                    INTERNET_PORT nServerPort,
                    LPCSTR lpszUserName,
                    LPCSTR lpszPassword,
                    DWORD dwService,
                    DWORD dwFlags,
                    DWORD_PTR dwContext
                );

                typedef HINTERNET (WINAPI *HttpOpenRequestA)(
                    HINTERNET hConnect,
                    LPCSTR lpszVerb,
                    LPCSTR lpszObjectName,
                    LPCSTR lpszVersion,
                    LPCSTR lpszReferrer,
                    LPCSTR *lplpszAcceptTypes,
                    DWORD dwFlags,
                    DWORD_PTR dwContext
                );

                typedef BOOL (WINAPI *HttpSendRequestA)(
                    HINTERNET hRequest,
                    LPCSTR lpszHeaders,
                    DWORD dwHeadersLength,
                    LPVOID lpOptional,
                    DWORD dwOptionalLength
                );

                typedef BOOL (WINAPI *InternetReadFile)(
                    _In_ HINTERNET hFile,
                    _Out_ LPVOID lpBuffer,
                    _In_ DWORD dwNumberOfBytesToRead,
                    _Out_ LPDWORD lpdwNumberOfBytesRead
                );

                typedef BOOL (WINAPI *InternetCloseHandle)(
                    HINTERNET hInternet
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("wininet.DLL");

                    InternetOpenA InternetOpenA{};
                    InternetConnectA InternetConnectA{};
                    HttpOpenRequestA HttpOpenRequestA{};
                    HttpSendRequestA HttpSendRequestA{};
                    InternetReadFile InternetReadFile{};
                    InternetCloseHandle InternetCloseHandle{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(InternetOpenA, inet::InternetOpenA, InternetOpenA, this, true);
                        PA(InternetConnectA, inet::InternetConnectA, InternetConnectA, this, true);
                        PA(HttpOpenRequestA, inet::HttpOpenRequestA, HttpOpenRequestA, this, true);
                        PA(HttpSendRequestA, inet::HttpSendRequestA, HttpSendRequestA, this, true);
                        PA(InternetReadFile, inet::InternetReadFile, InternetReadFile, this, true);
                        PA(InternetCloseHandle, inet::InternetCloseHandle, InternetCloseHandle, this, true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        InternetOpenA = nullptr;
                        InternetConnectA = nullptr;
                        HttpOpenRequestA = nullptr;
                        HttpSendRequestA = nullptr;
                        InternetReadFile = nullptr;
                        InternetCloseHandle = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace ipv4 {
                typedef ULONG (WINAPI *GetAdaptersInfo)(
                    PIP_ADAPTER_INFO AdapterInfo, PULONG
                    SizePointer);

                typedef DWORD (WINAPI *GetIpForwardTable)(
                    PMIB_IPFORWARDTABLE pIpForwardTable,
                    PULONG
                    pdwSize,
                    BOOL bOrder
                );

                typedef DWORD (WINAPI *DeleteIpForwardEntry)(
                    PMIB_IPFORWARDROW pRoute
                );

                typedef DWORD (WINAPI *CreateIpForwardEntry)(
                    PMIB_IPFORWARDROW pRoute
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("IPHLPAPI.DLL");

                    GetAdaptersInfo GetAdaptersInfo{};
                    GetIpForwardTable GetIpForwardTable{};
                    DeleteIpForwardEntry DeleteIpForwardEntry{};
                    CreateIpForwardEntry CreateIpForwardEntry{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(GetAdaptersInfo, ipv4::GetAdaptersInfo, GetAdaptersInfo, this, true);
                        PA(GetIpForwardTable, ipv4::GetIpForwardTable, GetIpForwardTable, this, true);
                        PA(CreateIpForwardEntry, ipv4::CreateIpForwardEntry, CreateIpForwardEntry, this, true);
                        PA(DeleteIpForwardEntry, ipv4::DeleteIpForwardEntry, DeleteIpForwardEntry, this, true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        GetAdaptersInfo = nullptr;
                        GetIpForwardTable = nullptr;
                        CreateIpForwardEntry = nullptr;
                        DeleteIpForwardEntry = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace ipv6 {
#ifndef AF_INET6
#define AF_INET6        23
#endif // !#define AF_INET6        23

                typedef struct sockaddr_in6 {
                    ADDRESS_FAMILY sin6_family; // AF_INET6.
                    USHORT sin6_port; // Transport level port number.
                    ULONG sin6_flowinfo; // IPv6 flow information.
                    IN6_ADDR sin6_addr; // IPv6 address.
                    union {
                        ULONG sin6_scope_id; // Set of interfaces for a scope.
                        SCOPE_ID sin6_scope_struct;
                    };
                } SOCKADDR_IN6;

                typedef union ST_SOCKADDR_INET {
                    SOCKADDR_IN Ipv4;
                    SOCKADDR_IN6 Ipv6;
                    ADDRESS_FAMILY si_family;
                } SOCKADDR_INET, *PSOCKADDR_INET;

                typedef struct ST_IP_ADDRESS_PREFIX {
                    SOCKADDR_INET Prefix;
                    UINT8 PrefixLength;
                } IP_ADDRESS_PREFIX, *PIP_ADDRESS_PREFIX;

                typedef struct ST_MIB_IPFORWARD_ROW2 {
                    //
                    // Key Structure.
                    //
                    NET_LUID InterfaceLuid;
                    NET_IFINDEX InterfaceIndex;
                    IP_ADDRESS_PREFIX DestinationPrefix;
                    SOCKADDR_INET NextHop;

                    //
                    // Read-Write Fields.
                    //
                    UCHAR SitePrefixLength;
                    ULONG ValidLifetime;
                    ULONG PreferredLifetime;
                    ULONG Metric;
                    NL_ROUTE_PROTOCOL Protocol;

                    BOOLEAN Loopback;
                    BOOLEAN AutoconfigureAddress;
                    BOOLEAN Publish;
                    BOOLEAN Immortal;

                    //
                    // Read-Only Fields.
                    //
                    ULONG Age;
                    NL_ROUTE_ORIGIN Origin;
                } MIB_IPFORWARD_ROW2, *PMIB_IPFORWARD_ROW2;

                typedef struct ST_MIB_IPFORWARD_TABLE2 {
                    ULONG NumEntries;
                    MIB_IPFORWARD_ROW2 Table[ANY_SIZE];
                } MIB_IPFORWARD_TABLE2, *PMIB_IPFORWARD_TABLE2;

                typedef DWORD (WINAPI *GetIpForwardTable2)(
                    ADDRESS_FAMILY Family,
                    PMIB_IPFORWARD_TABLE2 *Table
                );

                typedef DWORD (WINAPI *DeleteIpForwardEntry2)(
                    const MIB_IPFORWARD_ROW2 *Row
                );

                typedef VOID (WINAPI *FreeMibTable)(
                    PVOID Memory
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("IPHLPAPI.DLL");

                    GetIpForwardTable2 GetIpForwardTable2{};
                    DeleteIpForwardEntry2 DeleteIpForwardEntry2{};
                    FreeMibTable FreeMibTable{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(GetIpForwardTable2, ipv6::GetIpForwardTable2, GetIpForwardTable2, this, false);
                        PA(DeleteIpForwardEntry2, ipv6::DeleteIpForwardEntry2, DeleteIpForwardEntry2, this, false);
                        PA(FreeMibTable, ipv6::FreeMibTable, FreeMibTable, this, false);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        GetIpForwardTable2 = nullptr;
                        DeleteIpForwardEntry2 = nullptr;
                        FreeMibTable = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace psapi {
                typedef DWORD (WINAPI *GetModuleFileNameExA)(
                    _In_ HANDLE hProcess,
                    _In_opt_ HMODULE hModule,
                    _Out_ LPSTR lpFilename,
                    _In_ DWORD nSize
                );

                typedef BOOL (WINAPI *EnumProcesses)(
                    _Out_ DWORD *lpidProcess,
                    _In_ DWORD cb,
                    _Out_ LPDWORD lpcbNeeded
                );

                typedef BOOL (WINAPI *EnumProcessModules)(
                    _In_ HANDLE hProcess,
                    _Out_ HMODULE *lphModule,
                    _In_ DWORD cb,
                    _Out_ LPDWORD lpcbNeeded
                );

                typedef BOOL (WINAPI *EnumProcessModulesEx)(
                    _In_ HANDLE hProcess,
                    _Out_ HMODULE *lphModule,
                    _In_ DWORD cb,
                    _Out_ LPDWORD lpcbNeeded,
                    _In_ DWORD dwFilterFlag
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("Psapi.DLL");

                    GetModuleFileNameExA GetModuleFileNameExA{};
                    EnumProcesses EnumProcesses{};
                    EnumProcessModules EnumProcessModules{};
                    EnumProcessModulesEx EnumProcessModulesEx{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(GetModuleFileNameExA, psapi::GetModuleFileNameExA, GetModuleFileNameExA, this, true);
                        PA(EnumProcesses, psapi::EnumProcesses, EnumProcesses, this, true);
                        PA(EnumProcessModules, psapi::EnumProcessModules, EnumProcessModules, this, true);
                        PA(EnumProcessModulesEx, psapi::EnumProcessModulesEx, EnumProcessModulesEx, this, true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        EnumProcessModulesEx = nullptr;
                        EnumProcessModules = nullptr;
                        EnumProcesses = nullptr;
                        GetModuleFileNameExA = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace ntdll {
                typedef BOOL (WINAPI *NtSuspendProcess)(HANDLE hProcess);

                typedef BOOL (WINAPI *NtResumeProcess)(HANDLE hProcess);

                typedef BOOL (WINAPI *NtTerminateProcess)(HANDLE hProcess, UINT);

                typedef __kernel_entry NTSTATUS (WINAPI *NtQueryInformationProcess)(
                    _In_ HANDLE ProcessHandle,
                    _In_ PROCESSINFOCLASS ProcessInformationClass,
                    _Out_ PVOID ProcessInformation,
                    _In_ ULONG ProcessInformationLength,
                    _Out_opt_ PULONG ReturnLength
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("ntdll.DLL");

                    NtSuspendProcess NtSuspendProcess{};
                    NtResumeProcess NtResumeProcess{};
                    NtTerminateProcess NtTerminateProcess{};
                    NtQueryInformationProcess NtQueryInformationProcess{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(NtSuspendProcess, ntdll::NtSuspendProcess, NtSuspendProcess, this, true);
                        PA(NtResumeProcess, ntdll::NtResumeProcess, NtResumeProcess, this, true);
                        PA(NtTerminateProcess, ntdll::NtTerminateProcess, NtTerminateProcess, this, true);
                        PA(NtQueryInformationProcess, ntdll::NtQueryInformationProcess, NtQueryInformationProcess, this,
                           true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        NtSuspendProcess = nullptr;
                        NtResumeProcess = nullptr;
                        NtTerminateProcess = nullptr;
                        NtQueryInformationProcess = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace userenv {
                typedef BOOL (WINAPI *CreateEnvironmentBlock)(
                    _Out_ LPVOID *lpEnvironment,
                    _In_opt_ HANDLE hToken,
                    _In_ BOOL bInherit
                );

                typedef BOOL (WINAPI *DestroyEnvironmentBlock)(
                    _In_ LPVOID lpEnvironment
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("Userenv.DLL");

                    CreateEnvironmentBlock CreateEnvironmentBlock{};
                    DestroyEnvironmentBlock DestroyEnvironmentBlock{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(CreateEnvironmentBlock, userenv::CreateEnvironmentBlock, CreateEnvironmentBlock, this, true);
                        PA(DestroyEnvironmentBlock, userenv::DestroyEnvironmentBlock, DestroyEnvironmentBlock, this,
                           true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        CreateEnvironmentBlock = nullptr;
                        DestroyEnvironmentBlock = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            /**
             * 主要是关于锁这一类的API，目前没用到。
             */
            namespace kernel32 {
                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("Kernel32.DLL");

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace user32 {
                typedef LRESULT (WINAPI *SendMessageTimeoutA)(
                    _In_ HWND hWnd,
                    _In_ UINT Msg,
                    _In_ WPARAM wParam,
                    _In_ LPARAM lParam,
                    _In_ UINT fuFlags,
                    _In_ UINT uTimeout,
                    _Out_opt_ PDWORD_PTR lpdwResult
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("User32.dll");

                    SendMessageTimeoutA SendMessageTimeoutA{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();
                        PA(SendMessageTimeoutA, user32::SendMessageTimeoutA, SendMessageTimeoutA, this, true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        SendMessageTimeoutA = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            class API final : public base::ISingletonContext<API> {
                friend class base::ISingletonContext<API>;

            public:
                crypto::DynamicModule Crypto;
                ws32::DynamicModule WS32;
                inet::DynamicModule INet;
                ipv4::DynamicModule IPv4;
                ipv6::DynamicModule IPv6;
                psapi::DynamicModule PsAPI;
                ntdll::DynamicModule NtDll;
                userenv::DynamicModule UserEnv;
                kernel32::DynamicModule Kernel32;
                user32::DynamicModule User32;

                int32_t Load() override {
                    INT32 retCode = ERROR_SUCCESS;
                    if (nullptr == Crypto.hModule) {
                        retCode |= Crypto.Load();
                    }
                    if (nullptr == WS32.hModule) {
                        retCode |= WS32.Load();
                    }
                    if (nullptr == INet.hModule) {
                        retCode |= INet.Load();
                    }
                    if (nullptr == IPv4.hModule) {
                        retCode |= IPv4.Load();
                    }
                    if (nullptr == IPv6.hModule) {
                        retCode |= IPv6.Load();
                    }
                    if (nullptr == PsAPI.hModule) {
                        retCode |= PsAPI.Load();
                    }
                    if (nullptr == NtDll.hModule) {
                        retCode |= NtDll.Load();
                    }
                    if (nullptr == UserEnv.hModule) {
                        retCode |= UserEnv.Load();
                    }
                    if (nullptr == Kernel32.hModule) {
                        retCode |= Kernel32.Load();
                    }
                    if (nullptr == User32.hModule) {
                        retCode |= User32.Load();
                    }

                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }

                int32_t Unload() override {
                    INT32 retCode = ERROR_SUCCESS;

                    retCode |= User32.Unload();
                    retCode |= Kernel32.Unload();
                    retCode |= UserEnv.Unload();
                    retCode |= NtDll.Unload();
                    retCode |= PsAPI.Unload();
                    retCode |= IPv6.Unload();
                    retCode |= IPv4.Unload();
                    retCode |= INet.Unload();
                    retCode |= WS32.Unload();
                    retCode |= Crypto.Unload();

                    return retCode;
                }

                //        /**
                //        * 重载Instance，自动加载
                //        */
                //        static API& Instance(PCRITICAL_SECTION pCriticalSection = nullptr) {
                //            auto& instance = Singleton<API>::Instance();
                //            if (nullptr == instance.Kernel32.hModule) {
                //                if (nullptr != pCriticalSection)
                //                {
                //                    EnterCriticalSection(pCriticalSection);
                //                }
                //                if (nullptr == instance.Kernel32.hModule) {
                //                    instance.Load();
                //                }
                //                if (nullptr != pCriticalSection)
                //                {
                //                    LeaveCriticalSection(pCriticalSection);
                //                }
                //            }
                //            return instance;
                //        }
            };
        }
    }
}

#undef PA
#endif

#endif //CPL_WIN32_API_HPP_SILVER_TREASURE_WONDROUS_HARMONY_FUTURE_GLANCE_MYSTERY_VIBRANT
