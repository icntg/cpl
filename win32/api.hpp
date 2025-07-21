#ifndef CPL_WIN32_API_HPP_SILVER_TREASURE_WONDROUS_HARMONY_FUTURE_GLANCE_MYSTERY_VIBRANT
#define CPL_WIN32_API_HPP_SILVER_TREASURE_WONDROUS_HARMONY_FUTURE_GLANCE_MYSTERY_VIBRANT

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <tchar.h>

#include <cstdio>
#include <string>
#include <vector>

#include "../utility/base.hpp"
#include "../utility/strings.hpp"
#include "../utility/net.hpp"
#include "../vendor/nlohmann/json/json.hpp"

using namespace std;
using namespace cpl::net::ipv4;
using namespace cpl::strings;

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

        namespace api {
            class DynamicModule : public base::IContext {
            public:
                string szDllName{};
                HMODULE hModule = nullptr;

                bool IsLoaded() override {
                    return hModule != nullptr;
                }

                int32_t Load() override {
                    INT32 retCode = ERROR_SUCCESS;
                    hModule = LoadLibrary(szDllName.data());
                    if (nullptr == hModule) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        fprintf(stderr, "[x] LoadLibrary <%s> failed [0x%x]: %s\n", szDllName.data(), e,
                                FormatError(e).data());
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
                            fprintf(stderr, "[x] FreeLibrary <%s> failed [0x%x]: %s\n", szDllName.data(), e,
                                    FormatError(e).data());
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

            namespace wincrypt {


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

                typedef BOOL (WINAPI *CryptGenRandom)(
                    HCRYPTPROV hProv,
                    DWORD dwLen,
                    BYTE *pbBuffer
                );

                typedef BOOL (WINAPI *CryptImportKey)(
                    _In_ HCRYPTPROV hProv,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwDataLen,
                    _In_ HCRYPTKEY hPubKey,
                    _In_ DWORD dwFlags,
                    _Out_ HCRYPTKEY *phKey
                );

                // CryptDestroyKey
                typedef BOOL (WINAPI *CryptDestroyKey)(
                    _In_ HCRYPTKEY hKey
                );

                typedef BOOL (WINAPI *CryptSetKeyParam)(
                    _In_ HCRYPTKEY hKey,
                    _In_ DWORD dwParam,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwFlags
                );

                typedef BOOL (WINAPI *CryptEncrypt)(
                    _In_ HCRYPTKEY hKey,
                    _In_ HCRYPTHASH hHash,
                    _In_ BOOL Final,
                    _In_ DWORD dwFlags,
                    _Inout_ BYTE *pbData,
                    _Inout_ DWORD *pdwDataLen,
                    _In_ DWORD dwBufLen
                );

                typedef BOOL (WINAPI *CryptDecrypt)(
                    _In_ HCRYPTKEY hKey,
                    _In_ HCRYPTHASH hHash,
                    _In_ BOOL Final,
                    _In_ DWORD dwFlags,
                    _Inout_ BYTE *pbData,
                    _Inout_ DWORD *pdwDataLen
                );

                // CryptCreateHash
                typedef BOOL (WINAPI *CryptCreateHash)(
                    _In_ HCRYPTPROV hProv,
                    _In_ ALG_ID Algid,
                    _In_ HCRYPTKEY hKey,
                    _In_ DWORD dwFlags,
                    _Out_ HCRYPTHASH *phHash
                );

                // CryptDestroyHash
                typedef BOOL (WINAPI *CryptDestroyHash)(
                    _In_ HCRYPTHASH hHash
                );

                // CryptSetHashParam
                typedef BOOL (WINAPI *CryptSetHashParam)(
                    _In_ HCRYPTHASH hHash,
                    _In_ DWORD dwParam,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwFlags
                );

                // CryptGetHashParam
                typedef BOOL (WINAPI *CryptGetHashParam)(
                    _In_ HCRYPTHASH hHash,
                    _In_ DWORD dwParam,
                    _Out_ BYTE *pbData,
                    _Inout_ DWORD *pdwDataLen,
                    _In_ DWORD dwFlags
                );

                // CryptHashData
                typedef BOOL (WINAPI *CryptHashData)(
                    _In_ HCRYPTHASH hHash,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwDataLen,
                    _In_ DWORD dwFlags
                );

                typedef BOOL (WINAPI *CryptBinaryToStringA)(
                    _In_ const BYTE *pbBinary,
                    _In_ DWORD cbBinary,
                    _In_ DWORD dwFlags,
                    _Out_opt_ LPSTR pszString,
                    _Inout_ DWORD *pcchString
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("advapi32.DLL");
                    CryptGenRandom CryptGenRandom{};
                    CryptAcquireContextA CryptAcquireContextA{};
                    CryptReleaseContext CryptReleaseContext{};
                    CryptImportKey CryptImportKey{};
                    CryptSetKeyParam CryptSetKeyParam{};
                    CryptEncrypt CryptEncrypt{};
                    CryptDecrypt CryptDecrypt{};
                    CryptDestroyKey CryptDestroyKey{};
                    CryptCreateHash CryptCreateHash{};
                    CryptDestroyHash CryptDestroyHash{};
                    CryptSetHashParam CryptSetHashParam{};
                    CryptGetHashParam CryptGetHashParam{};
                    CryptHashData CryptHashData{};
                    CryptBinaryToStringA CryptBinaryToStringA{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();
                        PA(CryptGenRandom, wincrypt::CryptGenRandom, CryptGenRandom, this, false);
                        PA(CryptAcquireContextA, wincrypt::CryptAcquireContextA, CryptAcquireContextA, this, false);
                        PA(CryptReleaseContext, wincrypt::CryptReleaseContext, CryptReleaseContext, this, false);
                        PA(CryptImportKey, wincrypt::CryptImportKey, CryptImportKey, this, false);
                        PA(CryptSetKeyParam, wincrypt::CryptSetKeyParam, CryptSetKeyParam, this, false);
                        PA(CryptEncrypt, wincrypt::CryptEncrypt, CryptEncrypt, this, false);
                        PA(CryptDecrypt, wincrypt::CryptDecrypt, CryptDecrypt, this, false);
                        PA(CryptDestroyKey, wincrypt::CryptDestroyKey, CryptDestroyKey, this, false);
                        PA(CryptCreateHash, wincrypt::CryptCreateHash, CryptCreateHash, this, false);
                        PA(CryptDestroyHash, wincrypt::CryptDestroyHash, CryptDestroyHash, this, false);
                        PA(CryptSetHashParam, wincrypt::CryptSetHashParam, CryptSetHashParam, this, false);
                        PA(CryptGetHashParam, wincrypt::CryptGetHashParam, CryptGetHashParam, this, false);
                        PA(CryptHashData, wincrypt::CryptHashData, CryptHashData, this, false);
                        PA(CryptBinaryToStringA, wincrypt::CryptBinaryToStringA, CryptBinaryToStringA, this, false);
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
                        CryptImportKey = nullptr;
                        CryptSetKeyParam = nullptr;
                        CryptEncrypt = nullptr;
                        CryptDecrypt = nullptr;
                        CryptDestroyKey = nullptr;
                        CryptCreateHash = nullptr;
                        CryptDestroyHash = nullptr;
                        CryptSetHashParam = nullptr;
                        CryptGetHashParam = nullptr;
                        CryptHashData = nullptr;
                        CryptBinaryToStringA = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace bcrypt {
                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("Bcrypt.dll");
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

                typedef NTSYSAPI NTSTATUS (WINAPI *RtlGetVersion)(
                    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("ntdll.DLL");

                    NtSuspendProcess NtSuspendProcess{};
                    NtResumeProcess NtResumeProcess{};
                    NtTerminateProcess NtTerminateProcess{};
                    NtQueryInformationProcess NtQueryInformationProcess{};
                    RtlGetVersion RtlGetVersion{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(NtSuspendProcess, ntdll::NtSuspendProcess, NtSuspendProcess, this, true);
                        PA(NtResumeProcess, ntdll::NtResumeProcess, NtResumeProcess, this, true);
                        PA(NtTerminateProcess, ntdll::NtTerminateProcess, NtTerminateProcess, this, true);
                        PA(NtQueryInformationProcess, ntdll::NtQueryInformationProcess, NtQueryInformationProcess, this,
                           true);
                        PA(RtlGetVersion, ntdll::RtlGetVersion, RtlGetVersion, this, true);


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
                        RtlGetVersion = nullptr;
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
                typedef BOOL (WINAPI *ProcessIdToSessionId)(
                    _In_ DWORD dwProcessId,
                    _Out_ DWORD *pSessionId
                );

                typedef DWORD (WINAPI *WTSGetActiveConsoleSessionId)();

                typedef BOOL (WINAPI *QueryFullProcessImageNameA)(
                    _In_ HANDLE hProcess,
                    _In_ DWORD dwFlags,
                    _Out_ LPSTR lpExeName,
                    _Inout_ PDWORD lpdwSize
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = _T("Kernel32.DLL");

                    ProcessIdToSessionId ProcessIdToSessionId{};
                    WTSGetActiveConsoleSessionId WTSGetActiveConsoleSessionId{};
                    QueryFullProcessImageNameA QueryFullProcessImageNameA{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(ProcessIdToSessionId, kernel32::ProcessIdToSessionId, ProcessIdToSessionId, this, false);
                        PA(WTSGetActiveConsoleSessionId, kernel32::WTSGetActiveConsoleSessionId,
                           WTSGetActiveConsoleSessionId, this, false);
                        PA(QueryFullProcessImageNameA, kernel32::QueryFullProcessImageNameA, QueryFullProcessImageNameA,
                           this, false);

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

            namespace wtsapi32 {
                typedef BOOL (WINAPI *WTSQueryUserToken)(
                    _In_ ULONG SessionId,
                    _Out_ PHANDLE phToken
                );

                class DynamicModule final : public api::DynamicModule {
                public:
                    const string szDllName = "Wtsapi32.dll";
                    WTSQueryUserToken WTSQueryUserToken{};

                    int32_t Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= api::DynamicModule::Load();

                        PA(WTSQueryUserToken, wtsapi32::WTSQueryUserToken, WTSQueryUserToken, this, false);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    int32_t Unload() override {
                        WTSQueryUserToken = nullptr;
                        return api::DynamicModule::Unload();
                    }
                };
            }

            namespace openssl {
            }

            class API final : public base::IContext {
            public:
                wincrypt::DynamicModule WinCrypt;
                ws32::DynamicModule WS32;
                inet::DynamicModule INet;
                ipv4::DynamicModule IPv4;
                ipv6::DynamicModule IPv6;
                psapi::DynamicModule PsAPI;
                ntdll::DynamicModule NtDll;
                userenv::DynamicModule UserEnv;
                kernel32::DynamicModule Kernel32;
                user32::DynamicModule User32;
                wtsapi32::DynamicModule WtsApi32;

            protected:
                vector<DynamicModule *> modules{
                    &WinCrypt,
                    &WS32,
                    &INet,
                    &IPv4,
                    &IPv6,
                    &PsAPI,
                    &NtDll,
                    &UserEnv,
                    &Kernel32,
                    &User32,
                    &WtsApi32,
                };

            public:
                bool IsLoaded() override {
                    for (const auto &mod: this->modules) {
                        if (!mod->IsLoaded()) {
                            return false;
                        }
                    }
                    return true;
                }

                int32_t Load() override {
                    INT32 retCode = ERROR_SUCCESS;
                    for (const auto &mod: this->modules) {
                        if (!mod->IsLoaded()) {
                            retCode |= mod->Load();
                        }
                    }
                    return retCode;
                }

                int32_t Unload() override {
                    INT32 retCode = ERROR_SUCCESS;
                    for (const auto &mod: this->modules) {
                        if (mod->IsLoaded()) {
                            retCode |= mod->Unload();
                        }
                    }
                    return retCode;
                }

                explicit API(BOOL autoLoad = TRUE) {
                    if (autoLoad) {
                        this->Load();
                    }
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

            inline API *GetInstance() {
                static API Instance(TRUE); // 自动加载。基础组件就不用智能指针了。
                return &Instance;
            }
        }
#undef PA
#endif
        namespace display {
            inline string Dump(const void *ptr, size_t size) {
                string buffer{};
                const auto pc = static_cast<const char *>(ptr);
                Base64Encode(buffer, string(pc, size));
                return buffer;
            }
        }

        namespace entity {
            class IpAddrString final : public ISerializeJson {
            public:
                BOOL $IsNull = FALSE;
                string IpAddress{};
                string IpMask{};
                DWORD Context{};

                IpAddrString() = default;

                explicit IpAddrString(const char *ip_address, const char *ip_mask, DWORD context)
                    : IpAddress(ip_address),
                      IpMask(ip_mask),
                      Context(context) {
                }

                explicit IpAddrString(const IP_ADDR_STRING *s) {
                    if (nullptr == s) {
                        this->$IsNull = TRUE;
                    } else {
                        IpAddress = s->IpAddress.String;
                        IpMask = s->IpMask.String;
                        Context = s->Context;
                    }
                }

                bool operator==(const IpAddrString &other) const {
                    return IpAddress == other.IpAddress && IpMask == other.IpMask && Context == other.Context;
                }

                bool operator!=(const IpAddrString &other) const {
                    return IpAddress != other.IpAddress || IpMask != other.IpMask || Context != other.Context;
                }

                string ToJson() override {
                    vector<string> v{};
                    string s{};
                    s = Format(R"("IpAddress":"%s")", IpAddress.data());
                    v.push_back(s);
                    s = Format(R"("IpMask":"%s")", IpMask.data());
                    v.push_back(s);
                    s = Format(R"("Context":%lu)", Context);
                    v.push_back(s);
                    return "{" + Join(v, ",") + "}";
                }

                int32_t FromJson(const string &s) override {
                    try {
                        auto j = nlohmann::json::parse(s);
                        IpAddress = j.at("IpAddress").get<string>();
                        IpMask = j.at("IpMask").get<string>();
                        Context = j.at("Context").get<DWORD>();
                        return ERROR_SUCCESS;
                    } catch (const std::exception &e) {
                        return ERROR_INVALID_DATA;
                    }
                }
            };

            class Adapter final : public ISerializeJson {
            public:
                DWORD ComboIndex{};
                string AdapterName{};
                string Description{};
                string PhysicalAddress{};
                DWORD Index{};
                UINT Type{};
                UINT DhcpEnabled{};
                IpAddrString CurrentIpAddress{"", "", 0};
                vector<IpAddrString> IpAddressList{};
                vector<IpAddrString> GatewayList{};
                vector<IpAddrString> DhcpServer{};
                BOOL HaveWins{};
                vector<IpAddrString> PrimaryWinsServer{};
                vector<IpAddrString> SecondaryWinsServer{};
                time_t LeaseObtained{};
                time_t LeaseExpires{};

                Adapter() = default;

                explicit Adapter(const IP_ADAPTER_INFO *a) {
                    ComboIndex = a->ComboIndex;
                    AdapterName = a->AdapterName;
                    Description = a->Description; {
                        const char *dst{};
                        const auto *src = a->Address;
                        memcpy(&dst, &src, sizeof(PVOID));
                        PhysicalAddress = string(dst, a->AddressLength);
                    }
                    Index = a->Index;
                    Type = a->Type;
                    DhcpEnabled = a->DhcpEnabled;
                    CurrentIpAddress = IpAddrString(a->CurrentIpAddress);
                    for (auto p = &a->IpAddressList; nullptr != p; p = p->Next) {
                        IpAddressList.emplace_back(p);
                    }
                    for (auto p = &a->GatewayList; nullptr != p; p = p->Next) {
                        GatewayList.emplace_back(p);
                    }
                    for (auto p = &a->DhcpServer; nullptr != p; p = p->Next) {
                        DhcpServer.emplace_back(p);
                    }
                    HaveWins = a->HaveWins;
                    for (auto p = &a->PrimaryWinsServer; nullptr != p; p = p->Next) {
                        PrimaryWinsServer.emplace_back(p);
                    }
                    for (auto p = &a->SecondaryWinsServer; nullptr != p; p = p->Next) {
                        SecondaryWinsServer.emplace_back(p);
                    }
                    LeaseObtained = a->LeaseObtained;
                    LeaseExpires = a->LeaseExpires;
                }

                Adapter(const Adapter &a) {
                    ComboIndex = a.ComboIndex;
                    AdapterName = a.AdapterName;
                    Description = a.Description; {
                        const char *dst{};
                        const auto *src = a.PhysicalAddress.data();
                        memcpy(&dst, &src, sizeof(PVOID));
                        PhysicalAddress = string(dst, a.PhysicalAddress.length());
                    }
                    Index = a.Index;
                    Type = a.Type;
                    DhcpEnabled = a.DhcpEnabled;
                    CurrentIpAddress = IpAddrString(a.CurrentIpAddress);
                    for (const auto &item: a.IpAddressList) {
                        IpAddressList.emplace_back(item);
                    }
                    for (const auto &item: a.GatewayList) {
                        GatewayList.emplace_back(item);
                    }
                    for (const auto &item: a.DhcpServer) {
                        DhcpServer.emplace_back(item);
                    }
                    HaveWins = a.HaveWins;
                    for (const auto &item: a.PrimaryWinsServer) {
                        PrimaryWinsServer.emplace_back(item);
                    }
                    for (const auto &item: a.SecondaryWinsServer) {
                        SecondaryWinsServer.emplace_back(item);
                    }
                    LeaseObtained = a.LeaseObtained;
                    LeaseExpires = a.LeaseExpires;
                }

                enum class CompareResult {
                    SAME_ADAPTER,
                    DIFF_INDEX,
                    DIFF_TYPE,
                    DIFF_DHCP,
                    DIFF_NAME,
                    DIFF_DESC,
                    DIFF_MAC_ADDR,
                    DIFF_IP_ADDR,
                };

                CompareResult Compare(const Adapter &a) const {
                    if (this->Index != a.Index) {
                        return CompareResult::DIFF_INDEX;
                    }
                    if (this->Type != a.Type) {
                        return CompareResult::DIFF_TYPE;
                    }
                    if (this->DhcpEnabled != a.DhcpEnabled) {
                        return CompareResult::DIFF_DHCP;
                    }
                    if (this->AdapterName != a.AdapterName) {
                        return CompareResult::DIFF_NAME;
                    }
                    if (this->Description != a.Description) {
                        return CompareResult::DIFF_DESC;
                    }
                    if (this->PhysicalAddress.length() != a.PhysicalAddress.length()) {
                        return CompareResult::DIFF_MAC_ADDR;
                    }
                    if (0 != memcmp(this->PhysicalAddress.data(), a.PhysicalAddress.data(),
                                    this->PhysicalAddress.length())) {
                        return CompareResult::DIFF_MAC_ADDR;
                    }
                    if (this->IpAddressList.size() != a.IpAddressList.size()) {
                        return CompareResult::DIFF_IP_ADDR;
                    }
                    for (auto i = 0; i < this->IpAddressList.size(); i++) {
                        if (this->IpAddressList[i] != a.IpAddressList[i]) {
                            return CompareResult::DIFF_IP_ADDR;
                        }
                    }
                    return CompareResult::SAME_ADAPTER;
                }

                string ToJson() override {
                    vector<string> v{};
                    string s{};
                    s = Format(R"("ComboIndex":%lu)", ComboIndex);
                    v.push_back(s);
                    s = Format(R"("AdapterName":"%s")", AdapterName.data());
                    v.push_back(s);
                    s = Format(R"("Description":"%s")", Description.data());
                    v.push_back(s);
                    s = Format(R"("PhysicalAddress":"%s")", Hex(PhysicalAddress).data());
                    v.push_back(s);
                    s = Format(R"("Index":%lu)", Index);
                    v.push_back(s);
                    s = Format(R"("Type":%lu)", Type);
                    v.push_back(s);
                    s = Format(R"("DhcpEnabled":%lu)", DhcpEnabled);
                    v.push_back(s);
                    s = Format(R"("CurrentIpAddress":%s)", CurrentIpAddress.ToJson().data());
                    v.push_back(s); {
                        vector<string> vv{};
                        vv.reserve(IpAddressList.size());
                        for (auto item: IpAddressList) {
                            vv.push_back(item.ToJson());
                        }
                        s = Format(R"("IpAddressList":[%s])", Join(vv, ",").data());
                        v.push_back(s);
                    } {
                        vector<string> vv{};
                        vv.reserve(GatewayList.size());
                        for (auto item: GatewayList) {
                            vv.push_back(item.ToJson());
                        }
                        s = Format(R"("GatewayList":[%s])", Join(vv, ",").data());
                        v.push_back(s);
                    } {
                        vector<string> vv{};
                        vv.reserve(DhcpServer.size());
                        for (auto item: DhcpServer) {
                            vv.push_back(item.ToJson());
                        }
                        s = Format(R"("DhcpServer":[%s])", Join(vv, ",").data());
                        v.push_back(s);
                    }
                    s = Format(R"("HaveWins":%d)", HaveWins);
                    v.push_back(s); {
                        vector<string> vv{};
                        vv.reserve(PrimaryWinsServer.size());
                        for (auto item: PrimaryWinsServer) {
                            vv.push_back(item.ToJson());
                        }
                        s = Format(R"("PrimaryWinsServer":[%s])", Join(vv, ",").data());
                        v.push_back(s);
                    } {
                        vector<string> vv{};
                        vv.reserve(SecondaryWinsServer.size());
                        for (auto item: SecondaryWinsServer) {
                            vv.push_back(item.ToJson());
                        }
                        s = Format(R"("SecondaryWinsServer":[%s])", Join(vv, ",").data());
                        v.push_back(s);
                    }
                    s = Format(R"("LeaseObtained":%lu)", LeaseObtained);
                    v.push_back(s);
                    s = Format(R"("LeaseExpires":%lu)", LeaseExpires);
                    v.push_back(s);

                    return "{" + Join(v, ",") + "}";
                }

                int32_t FromJson(const std::string &s) override {
                    try {
                        auto j = nlohmann::json::parse(s);
                        ComboIndex = j.at("ComboIndex").get<DWORD>();
                        AdapterName = j.at("AdapterName").get<string>();
                        Description = j.at("Description").get<string>();
                        PhysicalAddress = Unhex(j.at("PhysicalAddress").get<string>());
                        Index = j.at("Index").get<DWORD>();
                        Type = j.at("Type").get<UINT>();
                        DhcpEnabled = j.at("DhcpEnabled").get<UINT>();
                        CurrentIpAddress.FromJson(j.at("CurrentIpAddress").dump());

                        IpAddressList.clear();
                        for (const auto &item: j.at("IpAddressList")) {
                            IpAddrString ip;
                            ip.FromJson(item.dump());
                            IpAddressList.push_back(ip);
                        }

                        GatewayList.clear();
                        for (const auto &item: j.at("GatewayList")) {
                            IpAddrString ip;
                            ip.FromJson(item.dump());
                            GatewayList.push_back(ip);
                        }

                        DhcpServer.clear();
                        for (const auto &item: j.at("DhcpServer")) {
                            IpAddrString ip;
                            ip.FromJson(item.dump());
                            DhcpServer.push_back(ip);
                        }

                        HaveWins = j.at("HaveWins").get<BOOL>();

                        PrimaryWinsServer.clear();
                        for (const auto &item: j.at("PrimaryWinsServer")) {
                            IpAddrString ip;
                            ip.FromJson(item.dump());
                            PrimaryWinsServer.push_back(ip);
                        }

                        SecondaryWinsServer.clear();
                        for (const auto &item: j.at("SecondaryWinsServer")) {
                            IpAddrString ip;
                            ip.FromJson(item.dump());
                            SecondaryWinsServer.push_back(ip);
                        }

                        LeaseObtained = j.at("LeaseObtained").get<time_t>();
                        LeaseExpires = j.at("LeaseExpires").get<time_t>();

                        return ERROR_SUCCESS;
                    } catch (const std::exception &e) {
                        return ERROR_INVALID_DATA;
                    }
                }
            };

            class Adapters final : public ISerializeJson {
            protected:
                vector<Adapter> list{};
                //                unordered_map<DWORD, Adapter &> map{};

            public:
                explicit Adapters(const IP_ADAPTER_INFO *a) {
                    for (auto p = a; nullptr != p; p = p->Next) {
                        Adapter adapter(p);
                        list.emplace_back(adapter);
                        //                        map[p->Index] = adapter;
                    }
                }

                enum class CompareResult {
                    ERROR_LOAD,
                    NULLPTR,
                    SAME_BUFFER_SIZE,
                    SAME_ADAPTERS,
                    ADAPTERS_ADDED,
                    ADAPTERS_REMOVED,
                    ADAPTERS_DIFF,
                };

                CompareResult Compare(const Adapters &a) const {
                    if (this->list.size() > a.list.size()) {
                        return CompareResult::ADAPTERS_ADDED;
                    }
                    if (this->list.size() < a.list.size()) {
                        return CompareResult::ADAPTERS_REMOVED;
                    }
                    for (auto i = 0; i < this->list.size(); i++) {
                        const auto &a0 = list[i];
                        const auto &a1 = a.list[i];
                        if (a0.Compare(a1) != Adapter::CompareResult::SAME_ADAPTER) {
                            return CompareResult::ADAPTERS_DIFF;
                        }
                    }
                    return CompareResult::SAME_ADAPTERS;
                }

                string ToJson() override {
                    vector<string> v{};
                    v.reserve(this->list.size());
                    for (auto adapter: this->list) {
                        v.emplace_back(adapter.ToJson());
                    }
                    return "[" + Join(v, ",") + "]";
                }

                int32_t FromJson(const string &s) override {
                    return ERROR_EMPTY;
                }
            };

            class IpForwardRow final : public ISerializeJson {
            protected:
                MIB_IPFORWARDROW ipForwardRow{};
                bool transferIPv4 = false;

            public:
                IpForwardRow() = default;

                explicit IpForwardRow(const MIB_IPFORWARDROW *r, const bool transferIPv4 = false) {
                    memmove(&this->ipForwardRow, r, sizeof(MIB_IPFORWARDROW));
                    this->transferIPv4 = transferIPv4;
                }

                string ToJson() override {
                    vector<string> t{};
                    string s{};
                    const auto r = &this->ipForwardRow;
                    s = Format(R"("dwForwardDest":%lu)", r->dwForwardDest);
                    t.push_back(s);
                    if (transferIPv4) {
                        s = Format(R"("ForwardDest":"%s")",
                                   UINT32ToIPString(r->dwForwardDest, false).data());
                        t.push_back(s);
                    }
                    s = Format(R"("dwForwardMask":%lu)", r->dwForwardMask);
                    t.push_back(s);
                    if (transferIPv4) {
                        s = Format(R"("ForwardMask":"%s")",
                                   UINT32ToIPString(r->dwForwardMask, false).data());
                        t.push_back(s);
                    }
                    s = Format(R"("dwForwardPolicy":%lu)", r->dwForwardPolicy);
                    t.push_back(s);
                    s = Format(R"("dwForwardNextHop":%lu)", r->dwForwardNextHop);
                    t.push_back(s);
                    if (transferIPv4) {
                        s = Format(R"("ForwardNextHop":"%s")",
                                   UINT32ToIPString(r->dwForwardNextHop, false).data());
                        t.push_back(s);
                    }
                    s = Format(R"("dwForwardIfIndex":%lu)", r->dwForwardIfIndex);
                    t.push_back(s);
                    s = Format(R"("dwForwardType":%lu)", r->dwForwardType);
                    t.push_back(s);
                    s = Format(R"("dwForwardProto":%lu)", r->dwForwardProto);
                    t.push_back(s);
                    s = Format(R"("dwForwardAge":%lu)", r->dwForwardAge);
                    t.push_back(s);
                    s = Format(R"("dwForwardNextHopAS":%lu)", r->dwForwardNextHopAS);
                    t.push_back(s);
                    s = Format(R"("dwForwardMetric1":%lu)", r->dwForwardMetric1);
                    t.push_back(s);
                    s = Format(R"("dwForwardMetric2":%lu)", r->dwForwardMetric2);
                    t.push_back(s);
                    s = Format(R"("dwForwardMetric3":%lu)", r->dwForwardMetric3);
                    t.push_back(s);
                    s = Format(R"("dwForwardMetric4":%lu)", r->dwForwardMetric4);
                    t.push_back(s);
                    s = Format(R"("dwForwardMetric5":%lu)", r->dwForwardMetric5);
                    t.push_back(s);
                    string jr = string("{") + Join(t, ",") + "}";
                    return jr;
                }

                int32_t FromJson(const string &s) override {
                    return ERROR_EMPTY;
                }

                const MIB_IPFORWARDROW &GetRaw() const {
                    return this->ipForwardRow;
                }
            };

            class IpForwardTable final : public ISerializeJson {
            protected:
                MIB_IPFORWARDTABLE t{};
                vector<IpForwardRow> rows{};

            public:
                explicit IpForwardTable(const MIB_IPFORWARDTABLE *pt) {
                    t.dwNumEntries = pt->dwNumEntries;
                    for (auto i = 0; i < t.dwNumEntries; i++) {
                        const auto row = IpForwardRow(pt->table + i);
                        rows.push_back(row);
                    }
                }

                string ToJson() override {
                    vector<string> vr{};
                    for (auto &row: rows) {
                        const auto s = row.ToJson();
                        vr.push_back(s);
                    }
                    return string("[") + Join(vr, ",") + "]";
                }

                int32_t FromJson(const string &s) override {
                    return ERROR_EMPTY;
                }
            };

            class IpForwardRow2 final : public ISerializeJson {
            protected:
                api::ipv6::MIB_IPFORWARD_ROW2 raw{};
                bool transferIPv6 = false;

            public:
                explicit IpForwardRow2(
                    const api::ipv6::MIB_IPFORWARD_ROW2 *r,
                    const bool transferIPv6 = false
                ) : transferIPv6(transferIPv6) {
                    memmove(&this->raw, r, sizeof(api::ipv6::MIB_IPFORWARD_ROW2));
                }

                string ToJson() override {
                    vector<string> v{};
                    const auto r = &this->raw;
                    string s{}; {
                        const char *pc{};
                        const auto *p = &r->InterfaceLuid;
                        memmove(&pc, &p, sizeof(PVOID));
                        s = Format(R"("InterfaceLuid":"%s")",
                                   Hex(string(pc, sizeof(NET_LUID))).data());
                        v.push_back(s);
                    }
                    s = Format(R"("InterfaceIndex":%lu)", r->InterfaceIndex);
                    v.push_back(s); {
                        const char *pc{};
                        const auto *p = &r->DestinationPrefix;
                        memmove(&pc, &p, sizeof(PVOID));
                        s = Format(R"("DestinationPrefix":"%s")",
                                   Hex(string(pc, sizeof(api::ipv6::IP_ADDRESS_PREFIX))).data());
                        v.push_back(s);
                    } {
                        const char *pc{};
                        const auto *p = &r->NextHop;
                        memmove(&pc, &p, sizeof(PVOID));
                        s = Format(R"("NextHop":"%s")",
                                   Hex(string(pc, sizeof(api::ipv6::SOCKADDR_INET))).data());
                        v.push_back(s);
                    }
                    s = Format(R"("SitePrefixLength":%hhu)", r->SitePrefixLength);
                    v.push_back(s);
                    s = Format(R"("ValidLifetime":%lu)", r->ValidLifetime);
                    v.push_back(s);
                    s = Format(R"("PreferredLifetime":%lu)", r->PreferredLifetime);
                    v.push_back(s);
                    s = Format(R"("Metric":%lu)", r->Metric);
                    v.push_back(s); {
                        const char *pc{};
                        const auto *p = &r->Protocol;
                        memmove(&pc, &p, sizeof(PVOID));
                        s = Format(R"("Protocol":"%s")",
                                   Hex(string(pc, sizeof(NL_ROUTE_PROTOCOL))).data());
                        v.push_back(s);
                    }
                    s = Format(R"("Loopback":%hhu)", r->Loopback);
                    v.push_back(s);
                    s = Format(R"("AutoconfigureAddress":%hhu)", r->AutoconfigureAddress);
                    v.push_back(s);
                    s = Format(R"("Publish":%hhu)", r->Publish);
                    v.push_back(s);
                    s = Format(R"("Immortal":%hhu)", r->Immortal);
                    v.push_back(s);
                    s = Format(R"("Age":%lu)", r->Age);
                    v.push_back(s); {
                        const char *pc{};
                        const auto *p = &r->Protocol;
                        memmove(&pc, &p, sizeof(PVOID));
                        s = Format(R"("Origin":"%s")",
                                   Hex(string(pc, sizeof(NL_ROUTE_ORIGIN))).data());
                        v.push_back(s);
                    }
                    string buffer = string("{") + Join(v, ",") + "}";
                    return buffer;
                }

                const api::ipv6::MIB_IPFORWARD_ROW2 &GetRaw() const {
                    return this->raw;
                }

                int32_t FromJson(const string &s) override {
                    return ERROR_EMPTY;
                }
            };

            class IpForwardTable2 final : public ISerializeJson {
            protected:
                api::ipv6::MIB_IPFORWARD_TABLE2 ipForwardTable2{};
                vector<IpForwardRow2> rows{};
                bool transferIPv6 = false;

            public:
                explicit IpForwardTable2(
                    const api::ipv6::MIB_IPFORWARD_TABLE2 *t,
                    const bool transferIPv6
                ) : transferIPv6(transferIPv6) {
                    this->ipForwardTable2.NumEntries = t->NumEntries;
                    for (auto i = 0; i < this->ipForwardTable2.NumEntries; i++) {
                        const auto row = IpForwardRow2(t->Table + i);
                        rows.push_back(row);
                    }
                }

                string ToJson() override {
                    vector<string> v{};
                    v.reserve(rows.size());
                    for (auto row: rows) {
                        v.push_back(row.ToJson());
                    }
                    return string("[") + Join(v, ",") + "]";
                }

                int32_t FromJson(const string &s) override {
                    return ERROR_EMPTY;
                }
            };
        }
    }
}


#endif //CPL_WIN32_API_HPP_SILVER_TREASURE_WONDROUS_HARMONY_FUTURE_GLANCE_MYSTERY_VIBRANT
