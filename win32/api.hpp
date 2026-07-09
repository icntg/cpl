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
        // Bring the legacy Win32-native ISerializeJson into scope so the
        // hand-written entity classes below can derive from it unqualified.
        using cpl::base::ISerializeJson;

        // Unwrap an Int32Result into a raw int32_t code for the Win32-native
        // `retCode |= ...` idiom used throughout the hand-written part. A success
        // value yields 0 (ERROR_SUCCESS); an error yields its int32_t payload.
        inline int32_t RC(const cpl::Int32Result &r) {
            return r ? r.value() : static_cast<int32_t>(r.error().Code.i64);
        }

        // Native string-returning shims. The hand-written cpl::win32 part below
        // predates the Result<T> migration and expects Format/Hex/Unhex/Base64Encode
        // to return std::string / int32_t directly (Win32-native call style).
        // Defined in the enclosing cpl::win32 namespace so unqualified lookup
        // prefers these over the top-level cpl::strings::Format (Result<string>).
        inline string Format(const char *tpl, ...) {
            va_list args;
            va_start(args, tpl);
            auto r = cpl::strings::VFormat(tpl, args);
            va_end(args);
            return r ? r.value() : string();
        }

        inline string Hex(const string &in) {
            auto r = cpl::codec::Hex::Hexlify(
                reinterpret_cast<const uint8_t *>(in.data()), in.size());
            return r ? r.value() : string();
        }

        inline string Unhex(const string &hex) {
            auto r = cpl::codec::Hex::UnHexlify(hex);
            if (!r) { return string(); }
            return string(r.value().begin(), r.value().end());
        }

        inline int32_t Base64Encode(_Out_ string &dst, _In_ const string &src) {
            auto r = cpl::codec::Base64::Base64Encode(src.data(), src.size());
            if (!r) { return -1; }
            dst = std::move(r.value());
            return 0;
        }

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

                Int32Result Load() override {
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

                Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());
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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

                        PA(GetIpForwardTable2, ipv6::GetIpForwardTable2, GetIpForwardTable2, this, false);
                        PA(DeleteIpForwardEntry2, ipv6::DeleteIpForwardEntry2, DeleteIpForwardEntry2, this, false);
                        PA(FreeMibTable, ipv6::FreeMibTable, FreeMibTable, this, false);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

                        PA(CreateEnvironmentBlock, userenv::CreateEnvironmentBlock, CreateEnvironmentBlock, this, true);
                        PA(DestroyEnvironmentBlock, userenv::DestroyEnvironmentBlock, DestroyEnvironmentBlock, this,
                           true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

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

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());
                        PA(SendMessageTimeoutA, user32::SendMessageTimeoutA, SendMessageTimeoutA, this, true);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    Int32Result Unload() override {
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

                    Int32Result Load() override {
                        INT32 retCode = ERROR_SUCCESS;
                        api::DynamicModule::szDllName = this->szDllName;
                        retCode |= RC(api::DynamicModule::Load());

                        PA(WTSQueryUserToken, wtsapi32::WTSQueryUserToken, WTSQueryUserToken, this, false);

                        goto __FREE__;
                    __ERROR__:
                        PASS;
                    __FREE__:
                        return retCode;
                    }

                    Int32Result Unload() override {
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

                Int32Result Load() override {
                    INT32 retCode = ERROR_SUCCESS;
                    for (const auto &mod: this->modules) {
                        if (!mod->IsLoaded()) {
                            retCode |= RC(mod->Load());
                        }
                    }
                    return retCode;
                }

                Int32Result Unload() override {
                    INT32 retCode = ERROR_SUCCESS;
                    for (const auto &mod: this->modules) {
                        if (mod->IsLoaded()) {
                            retCode |= RC(mod->Unload());
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

//// this file was generated by api_gen.py. please DO NOT edit this file directly.
#pragma once

#include "sys.hpp"

namespace cpl {
namespace sys {
namespace api {
namespace Crypt32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        CryptBinaryToStringA CryptBinaryToStringA{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_CryptBinaryToStringA = api::DynamicModule::LoadFunction<::cpl::sys::api::Crypt32::CryptBinaryToStringA>("CryptBinaryToStringA", false);
                if (!ret_CryptBinaryToStringA) {
                } else {
                    any_loaded = true;
                    CryptBinaryToStringA = ret_CryptBinaryToStringA.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            CryptBinaryToStringA = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace AdvAPI32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() = default;
        ConvertStringSecurityDescriptorToSecurityDescriptorA ConvertStringSecurityDescriptorToSecurityDescriptorA{};
        ConvertSidToStringSidA ConvertSidToStringSidA{};
        ConvertStringSidToSidA ConvertStringSidToSidA{};
        RtlGenRandom RtlGenRandom{};
        CryptAcquireContextA CryptAcquireContextA{};
        CryptReleaseContext CryptReleaseContext{};
        CryptGenRandom CryptGenRandom{};
        CryptImportKey CryptImportKey{};
        CryptDestroyKey CryptDestroyKey{};
        CryptSetKeyParam CryptSetKeyParam{};
        CryptEncrypt CryptEncrypt{};
        CryptDecrypt CryptDecrypt{};
        CryptCreateHash CryptCreateHash{};
        CryptDestroyHash CryptDestroyHash{};
        CryptSetHashParam CryptSetHashParam{};
        CryptGetHashParam CryptGetHashParam{};
        CryptHashData CryptHashData{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_ConvertStringSecurityDescriptorToSecurityDescriptorA = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::ConvertStringSecurityDescriptorToSecurityDescriptorA>("ConvertStringSecurityDescriptorToSecurityDescriptorA");
                if (!ret_ConvertStringSecurityDescriptorToSecurityDescriptorA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    ConvertStringSecurityDescriptorToSecurityDescriptorA = ret_ConvertStringSecurityDescriptorToSecurityDescriptorA.value();
                }
                const auto ret_ConvertSidToStringSidA = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::ConvertSidToStringSidA>("ConvertSidToStringSidA");
                if (!ret_ConvertSidToStringSidA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    ConvertSidToStringSidA = ret_ConvertSidToStringSidA.value();
                }
                const auto ret_ConvertStringSidToSidA = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::ConvertStringSidToSidA>("ConvertStringSidToSidA");
                if (!ret_ConvertStringSidToSidA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    ConvertStringSidToSidA = ret_ConvertStringSidToSidA.value();
                }
                const auto ret_RtlGenRandom = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::RtlGenRandom>("RtlGenRandom", false);
                if (!ret_RtlGenRandom) {
                } else {
                    any_loaded = true;
                    RtlGenRandom = ret_RtlGenRandom.value();
                }
                const auto ret_CryptAcquireContextA = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptAcquireContextA>("CryptAcquireContextA", false);
                if (!ret_CryptAcquireContextA) {
                } else {
                    any_loaded = true;
                    CryptAcquireContextA = ret_CryptAcquireContextA.value();
                }
                const auto ret_CryptReleaseContext = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptReleaseContext>("CryptReleaseContext", false);
                if (!ret_CryptReleaseContext) {
                } else {
                    any_loaded = true;
                    CryptReleaseContext = ret_CryptReleaseContext.value();
                }
                const auto ret_CryptGenRandom = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptGenRandom>("CryptGenRandom", false);
                if (!ret_CryptGenRandom) {
                } else {
                    any_loaded = true;
                    CryptGenRandom = ret_CryptGenRandom.value();
                }
                const auto ret_CryptImportKey = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptImportKey>("CryptImportKey", false);
                if (!ret_CryptImportKey) {
                } else {
                    any_loaded = true;
                    CryptImportKey = ret_CryptImportKey.value();
                }
                const auto ret_CryptDestroyKey = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptDestroyKey>("CryptDestroyKey", false);
                if (!ret_CryptDestroyKey) {
                } else {
                    any_loaded = true;
                    CryptDestroyKey = ret_CryptDestroyKey.value();
                }
                const auto ret_CryptSetKeyParam = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptSetKeyParam>("CryptSetKeyParam", false);
                if (!ret_CryptSetKeyParam) {
                } else {
                    any_loaded = true;
                    CryptSetKeyParam = ret_CryptSetKeyParam.value();
                }
                const auto ret_CryptEncrypt = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptEncrypt>("CryptEncrypt", false);
                if (!ret_CryptEncrypt) {
                } else {
                    any_loaded = true;
                    CryptEncrypt = ret_CryptEncrypt.value();
                }
                const auto ret_CryptDecrypt = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptDecrypt>("CryptDecrypt", false);
                if (!ret_CryptDecrypt) {
                } else {
                    any_loaded = true;
                    CryptDecrypt = ret_CryptDecrypt.value();
                }
                const auto ret_CryptCreateHash = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptCreateHash>("CryptCreateHash", false);
                if (!ret_CryptCreateHash) {
                } else {
                    any_loaded = true;
                    CryptCreateHash = ret_CryptCreateHash.value();
                }
                const auto ret_CryptDestroyHash = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptDestroyHash>("CryptDestroyHash", false);
                if (!ret_CryptDestroyHash) {
                } else {
                    any_loaded = true;
                    CryptDestroyHash = ret_CryptDestroyHash.value();
                }
                const auto ret_CryptSetHashParam = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptSetHashParam>("CryptSetHashParam", false);
                if (!ret_CryptSetHashParam) {
                } else {
                    any_loaded = true;
                    CryptSetHashParam = ret_CryptSetHashParam.value();
                }
                const auto ret_CryptGetHashParam = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptGetHashParam>("CryptGetHashParam", false);
                if (!ret_CryptGetHashParam) {
                } else {
                    any_loaded = true;
                    CryptGetHashParam = ret_CryptGetHashParam.value();
                }
                const auto ret_CryptHashData = api::DynamicModule::LoadFunction<::cpl::sys::api::AdvAPI32::CryptHashData>("CryptHashData", false);
                if (!ret_CryptHashData) {
                } else {
                    any_loaded = true;
                    CryptHashData = ret_CryptHashData.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return Err(cpl::Error(cpl::Error::UnavailableAPI(), "load module or function failed"));
        }

        Int32Result Unload() override {
            ConvertStringSecurityDescriptorToSecurityDescriptorA = nullptr;
            ConvertSidToStringSidA = nullptr;
            ConvertStringSidToSidA = nullptr;
            RtlGenRandom = nullptr;
            CryptAcquireContextA = nullptr;
            CryptReleaseContext = nullptr;
            CryptGenRandom = nullptr;
            CryptImportKey = nullptr;
            CryptDestroyKey = nullptr;
            CryptSetKeyParam = nullptr;
            CryptEncrypt = nullptr;
            CryptDecrypt = nullptr;
            CryptCreateHash = nullptr;
            CryptDestroyHash = nullptr;
            CryptSetHashParam = nullptr;
            CryptGetHashParam = nullptr;
            CryptHashData = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace bcrypt {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        BCryptGenRandom BCryptGenRandom{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_BCryptGenRandom = api::DynamicModule::LoadFunction<::cpl::sys::api::bcrypt::BCryptGenRandom>("BCryptGenRandom", false);
                if (!ret_BCryptGenRandom) {
                } else {
                    any_loaded = true;
                    BCryptGenRandom = ret_BCryptGenRandom.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            BCryptGenRandom = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace Ws2_32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        WSAStartup WSAStartup{};
        WSACleanup WSACleanup{};
        WSAGetLastError WSAGetLastError{};
        socket socket{};
        htons htons{};
        inet_addr inet_addr{};
        sendto sendto{};
        closesocket closesocket{};
        setsockopt setsockopt{};
        bind bind{};
        recvfrom recvfrom{};
        ntohs ntohs{};
        ioctlsocket ioctlsocket{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_WSAStartup = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::WSAStartup>("WSAStartup");
                if (!ret_WSAStartup) {
                    ok = false;
                } else {
                    any_loaded = true;
                    WSAStartup = ret_WSAStartup.value();
                }
                const auto ret_WSACleanup = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::WSACleanup>("WSACleanup");
                if (!ret_WSACleanup) {
                    ok = false;
                } else {
                    any_loaded = true;
                    WSACleanup = ret_WSACleanup.value();
                }
                const auto ret_WSAGetLastError = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::WSAGetLastError>("WSAGetLastError");
                if (!ret_WSAGetLastError) {
                    ok = false;
                } else {
                    any_loaded = true;
                    WSAGetLastError = ret_WSAGetLastError.value();
                }
                const auto ret_socket = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::socket>("socket");
                if (!ret_socket) {
                    ok = false;
                } else {
                    any_loaded = true;
                    socket = ret_socket.value();
                }
                const auto ret_htons = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::htons>("htons");
                if (!ret_htons) {
                    ok = false;
                } else {
                    any_loaded = true;
                    htons = ret_htons.value();
                }
                const auto ret_inet_addr = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::inet_addr>("inet_addr");
                if (!ret_inet_addr) {
                    ok = false;
                } else {
                    any_loaded = true;
                    inet_addr = ret_inet_addr.value();
                }
                const auto ret_sendto = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::sendto>("sendto");
                if (!ret_sendto) {
                    ok = false;
                } else {
                    any_loaded = true;
                    sendto = ret_sendto.value();
                }
                const auto ret_closesocket = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::closesocket>("closesocket");
                if (!ret_closesocket) {
                    ok = false;
                } else {
                    any_loaded = true;
                    closesocket = ret_closesocket.value();
                }
                const auto ret_setsockopt = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::setsockopt>("setsockopt");
                if (!ret_setsockopt) {
                    ok = false;
                } else {
                    any_loaded = true;
                    setsockopt = ret_setsockopt.value();
                }
                const auto ret_bind = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::bind>("bind");
                if (!ret_bind) {
                    ok = false;
                } else {
                    any_loaded = true;
                    bind = ret_bind.value();
                }
                const auto ret_recvfrom = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::recvfrom>("recvfrom");
                if (!ret_recvfrom) {
                    ok = false;
                } else {
                    any_loaded = true;
                    recvfrom = ret_recvfrom.value();
                }
                const auto ret_ntohs = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::ntohs>("ntohs");
                if (!ret_ntohs) {
                    ok = false;
                } else {
                    any_loaded = true;
                    ntohs = ret_ntohs.value();
                }
                const auto ret_ioctlsocket = api::DynamicModule::LoadFunction<::cpl::sys::api::Ws2_32::ioctlsocket>("ioctlsocket");
                if (!ret_ioctlsocket) {
                    ok = false;
                } else {
                    any_loaded = true;
                    ioctlsocket = ret_ioctlsocket.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            WSAStartup = nullptr;
            WSACleanup = nullptr;
            WSAGetLastError = nullptr;
            socket = nullptr;
            htons = nullptr;
            inet_addr = nullptr;
            sendto = nullptr;
            closesocket = nullptr;
            setsockopt = nullptr;
            bind = nullptr;
            recvfrom = nullptr;
            ntohs = nullptr;
            ioctlsocket = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace WinINet {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() = default;
        InternetOpenA InternetOpenA{};
        InternetConnectA InternetConnectA{};
        HttpOpenRequestA HttpOpenRequestA{};
        HttpSendRequestA HttpSendRequestA{};
        InternetReadFile InternetReadFile{};
        InternetCloseHandle InternetCloseHandle{};
        InternetCrackUrlA InternetCrackUrlA{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_InternetOpenA = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::InternetOpenA>("InternetOpenA");
                if (!ret_InternetOpenA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    InternetOpenA = ret_InternetOpenA.value();
                }
                const auto ret_InternetConnectA = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::InternetConnectA>("InternetConnectA");
                if (!ret_InternetConnectA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    InternetConnectA = ret_InternetConnectA.value();
                }
                const auto ret_HttpOpenRequestA = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::HttpOpenRequestA>("HttpOpenRequestA");
                if (!ret_HttpOpenRequestA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    HttpOpenRequestA = ret_HttpOpenRequestA.value();
                }
                const auto ret_HttpSendRequestA = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::HttpSendRequestA>("HttpSendRequestA");
                if (!ret_HttpSendRequestA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    HttpSendRequestA = ret_HttpSendRequestA.value();
                }
                const auto ret_InternetReadFile = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::InternetReadFile>("InternetReadFile");
                if (!ret_InternetReadFile) {
                    ok = false;
                } else {
                    any_loaded = true;
                    InternetReadFile = ret_InternetReadFile.value();
                }
                const auto ret_InternetCloseHandle = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::InternetCloseHandle>("InternetCloseHandle");
                if (!ret_InternetCloseHandle) {
                    ok = false;
                } else {
                    any_loaded = true;
                    InternetCloseHandle = ret_InternetCloseHandle.value();
                }
                const auto ret_InternetCrackUrlA = api::DynamicModule::LoadFunction<::cpl::sys::api::WinINet::InternetCrackUrlA>("InternetCrackUrlA");
                if (!ret_InternetCrackUrlA) {
                    ok = false;
                } else {
                    any_loaded = true;
                    InternetCrackUrlA = ret_InternetCrackUrlA.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return Err(cpl::Error(cpl::Error::UnavailableAPI(), "load module or function failed"));
        }

        Int32Result Unload() override {
            InternetOpenA = nullptr;
            InternetConnectA = nullptr;
            HttpOpenRequestA = nullptr;
            HttpSendRequestA = nullptr;
            InternetReadFile = nullptr;
            InternetCloseHandle = nullptr;
            InternetCrackUrlA = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace IPv4 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        GetAdaptersInfo GetAdaptersInfo{};
        GetAdaptersAddresses GetAdaptersAddresses{};
        GetIpForwardTable GetIpForwardTable{};
        DeleteIpForwardEntry DeleteIpForwardEntry{};
        CreateIpForwardEntry CreateIpForwardEntry{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_GetAdaptersInfo = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv4::GetAdaptersInfo>("GetAdaptersInfo");
                if (!ret_GetAdaptersInfo) {
                    ok = false;
                } else {
                    any_loaded = true;
                    GetAdaptersInfo = ret_GetAdaptersInfo.value();
                }
                const auto ret_GetAdaptersAddresses = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv4::GetAdaptersAddresses>("GetAdaptersAddresses");
                if (!ret_GetAdaptersAddresses) {
                    ok = false;
                } else {
                    any_loaded = true;
                    GetAdaptersAddresses = ret_GetAdaptersAddresses.value();
                }
                const auto ret_GetIpForwardTable = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv4::GetIpForwardTable>("GetIpForwardTable");
                if (!ret_GetIpForwardTable) {
                    ok = false;
                } else {
                    any_loaded = true;
                    GetIpForwardTable = ret_GetIpForwardTable.value();
                }
                const auto ret_DeleteIpForwardEntry = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv4::DeleteIpForwardEntry>("DeleteIpForwardEntry");
                if (!ret_DeleteIpForwardEntry) {
                    ok = false;
                } else {
                    any_loaded = true;
                    DeleteIpForwardEntry = ret_DeleteIpForwardEntry.value();
                }
                const auto ret_CreateIpForwardEntry = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv4::CreateIpForwardEntry>("CreateIpForwardEntry");
                if (!ret_CreateIpForwardEntry) {
                    ok = false;
                } else {
                    any_loaded = true;
                    CreateIpForwardEntry = ret_CreateIpForwardEntry.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            GetAdaptersInfo = nullptr;
            GetAdaptersAddresses = nullptr;
            GetIpForwardTable = nullptr;
            DeleteIpForwardEntry = nullptr;
            CreateIpForwardEntry = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace IPv6 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        GetIpForwardTable2 GetIpForwardTable2{};
        DeleteIpForwardEntry2 DeleteIpForwardEntry2{};
        FreeMibTable FreeMibTable{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_GetIpForwardTable2 = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv6::GetIpForwardTable2>("GetIpForwardTable2", false);
                if (!ret_GetIpForwardTable2) {
                } else {
                    any_loaded = true;
                    GetIpForwardTable2 = ret_GetIpForwardTable2.value();
                }
                const auto ret_DeleteIpForwardEntry2 = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv6::DeleteIpForwardEntry2>("DeleteIpForwardEntry2", false);
                if (!ret_DeleteIpForwardEntry2) {
                } else {
                    any_loaded = true;
                    DeleteIpForwardEntry2 = ret_DeleteIpForwardEntry2.value();
                }
                const auto ret_FreeMibTable = api::DynamicModule::LoadFunction<::cpl::sys::api::IPv6::FreeMibTable>("FreeMibTable", false);
                if (!ret_FreeMibTable) {
                } else {
                    any_loaded = true;
                    FreeMibTable = ret_FreeMibTable.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            GetIpForwardTable2 = nullptr;
            DeleteIpForwardEntry2 = nullptr;
            FreeMibTable = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace PsAPI {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        GetModuleFileNameExA GetModuleFileNameExA{};
        EnumProcesses EnumProcesses{};
        EnumProcessModules EnumProcessModules{};
        EnumProcessModulesEx EnumProcessModulesEx{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_GetModuleFileNameExA = api::DynamicModule::LoadFunction<::cpl::sys::api::PsAPI::GetModuleFileNameExA>("GetModuleFileNameExA", false);
                if (!ret_GetModuleFileNameExA) {
                } else {
                    any_loaded = true;
                    GetModuleFileNameExA = ret_GetModuleFileNameExA.value();
                }
                const auto ret_EnumProcesses = api::DynamicModule::LoadFunction<::cpl::sys::api::PsAPI::EnumProcesses>("EnumProcesses", false);
                if (!ret_EnumProcesses) {
                } else {
                    any_loaded = true;
                    EnumProcesses = ret_EnumProcesses.value();
                }
                const auto ret_EnumProcessModules = api::DynamicModule::LoadFunction<::cpl::sys::api::PsAPI::EnumProcessModules>("EnumProcessModules", false);
                if (!ret_EnumProcessModules) {
                } else {
                    any_loaded = true;
                    EnumProcessModules = ret_EnumProcessModules.value();
                }
                const auto ret_EnumProcessModulesEx = api::DynamicModule::LoadFunction<::cpl::sys::api::PsAPI::EnumProcessModulesEx>("EnumProcessModulesEx", false);
                if (!ret_EnumProcessModulesEx) {
                } else {
                    any_loaded = true;
                    EnumProcessModulesEx = ret_EnumProcessModulesEx.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            GetModuleFileNameExA = nullptr;
            EnumProcesses = nullptr;
            EnumProcessModules = nullptr;
            EnumProcessModulesEx = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace NtDLL {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() = default;
        NtSuspendProcess NtSuspendProcess{};
        NtResumeProcess NtResumeProcess{};
        NtTerminateProcess NtTerminateProcess{};
        NtQueryInformationProcess NtQueryInformationProcess{};
        RtlGetVersion RtlGetVersion{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_NtSuspendProcess = api::DynamicModule::LoadFunction<::cpl::sys::api::NtDLL::NtSuspendProcess>("NtSuspendProcess");
                if (!ret_NtSuspendProcess) {
                    ok = false;
                } else {
                    any_loaded = true;
                    NtSuspendProcess = ret_NtSuspendProcess.value();
                }
                const auto ret_NtResumeProcess = api::DynamicModule::LoadFunction<::cpl::sys::api::NtDLL::NtResumeProcess>("NtResumeProcess");
                if (!ret_NtResumeProcess) {
                    ok = false;
                } else {
                    any_loaded = true;
                    NtResumeProcess = ret_NtResumeProcess.value();
                }
                const auto ret_NtTerminateProcess = api::DynamicModule::LoadFunction<::cpl::sys::api::NtDLL::NtTerminateProcess>("NtTerminateProcess");
                if (!ret_NtTerminateProcess) {
                    ok = false;
                } else {
                    any_loaded = true;
                    NtTerminateProcess = ret_NtTerminateProcess.value();
                }
                const auto ret_NtQueryInformationProcess = api::DynamicModule::LoadFunction<::cpl::sys::api::NtDLL::NtQueryInformationProcess>("NtQueryInformationProcess");
                if (!ret_NtQueryInformationProcess) {
                    ok = false;
                } else {
                    any_loaded = true;
                    NtQueryInformationProcess = ret_NtQueryInformationProcess.value();
                }
                const auto ret_RtlGetVersion = api::DynamicModule::LoadFunction<::cpl::sys::api::NtDLL::RtlGetVersion>("RtlGetVersion");
                if (!ret_RtlGetVersion) {
                    ok = false;
                } else {
                    any_loaded = true;
                    RtlGetVersion = ret_RtlGetVersion.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return Err(cpl::Error(cpl::Error::UnavailableAPI(), "load module or function failed"));
        }

        Int32Result Unload() override {
            NtSuspendProcess = nullptr;
            NtResumeProcess = nullptr;
            NtTerminateProcess = nullptr;
            NtQueryInformationProcess = nullptr;
            RtlGetVersion = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace UserEnv {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        CreateEnvironmentBlock CreateEnvironmentBlock{};
        DestroyEnvironmentBlock DestroyEnvironmentBlock{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_CreateEnvironmentBlock = api::DynamicModule::LoadFunction<::cpl::sys::api::UserEnv::CreateEnvironmentBlock>("CreateEnvironmentBlock", false);
                if (!ret_CreateEnvironmentBlock) {
                } else {
                    any_loaded = true;
                    CreateEnvironmentBlock = ret_CreateEnvironmentBlock.value();
                }
                const auto ret_DestroyEnvironmentBlock = api::DynamicModule::LoadFunction<::cpl::sys::api::UserEnv::DestroyEnvironmentBlock>("DestroyEnvironmentBlock", false);
                if (!ret_DestroyEnvironmentBlock) {
                } else {
                    any_loaded = true;
                    DestroyEnvironmentBlock = ret_DestroyEnvironmentBlock.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            CreateEnvironmentBlock = nullptr;
            DestroyEnvironmentBlock = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace Kernel32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() = default;
        ProcessIdToSessionId ProcessIdToSessionId{};
        WTSGetActiveConsoleSessionId WTSGetActiveConsoleSessionId{};
        QueryFullProcessImageNameA QueryFullProcessImageNameA{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_ProcessIdToSessionId = api::DynamicModule::LoadFunction<::cpl::sys::api::Kernel32::ProcessIdToSessionId>("ProcessIdToSessionId", false);
                if (!ret_ProcessIdToSessionId) {
                } else {
                    any_loaded = true;
                    ProcessIdToSessionId = ret_ProcessIdToSessionId.value();
                }
                const auto ret_WTSGetActiveConsoleSessionId = api::DynamicModule::LoadFunction<::cpl::sys::api::Kernel32::WTSGetActiveConsoleSessionId>("WTSGetActiveConsoleSessionId", false);
                if (!ret_WTSGetActiveConsoleSessionId) {
                } else {
                    any_loaded = true;
                    WTSGetActiveConsoleSessionId = ret_WTSGetActiveConsoleSessionId.value();
                }
                const auto ret_QueryFullProcessImageNameA = api::DynamicModule::LoadFunction<::cpl::sys::api::Kernel32::QueryFullProcessImageNameA>("QueryFullProcessImageNameA", false);
                if (!ret_QueryFullProcessImageNameA) {
                } else {
                    any_loaded = true;
                    QueryFullProcessImageNameA = ret_QueryFullProcessImageNameA.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return Err(cpl::Error(cpl::Error::UnavailableAPI(), "load module or function failed"));
        }

        Int32Result Unload() override {
            ProcessIdToSessionId = nullptr;
            WTSGetActiveConsoleSessionId = nullptr;
            QueryFullProcessImageNameA = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace User32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        SendMessageTimeoutA SendMessageTimeoutA{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_SendMessageTimeoutA = api::DynamicModule::LoadFunction<::cpl::sys::api::User32::SendMessageTimeoutA>("SendMessageTimeoutA", false);
                if (!ret_SendMessageTimeoutA) {
                } else {
                    any_loaded = true;
                    SendMessageTimeoutA = ret_SendMessageTimeoutA.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            SendMessageTimeoutA = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace WtsAPI32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}
        WTSQueryUserToken WTSQueryUserToken{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_WTSQueryUserToken = api::DynamicModule::LoadFunction<::cpl::sys::api::WtsAPI32::WTSQueryUserToken>("WTSQueryUserToken", false);
                if (!ret_WTSQueryUserToken) {
                } else {
                    any_loaded = true;
                    WTSQueryUserToken = ret_WTSQueryUserToken.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            WTSQueryUserToken = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace MsImg32 {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() = default;
        GradientFill GradientFill{};

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                const auto ret_GradientFill = api::DynamicModule::LoadFunction<::cpl::sys::api::MsImg32::GradientFill>("GradientFill");
                if (!ret_GradientFill) {
                    ok = false;
                } else {
                    any_loaded = true;
                    GradientFill = ret_GradientFill.value();
                }
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return Err(cpl::Error(cpl::Error::UnavailableAPI(), "load module or function failed"));
        }

        Int32Result Unload() override {
            GradientFill = nullptr;
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}

namespace OpenSSL {
    class DynamicModule final : public api::DynamicModule {
    public:
        explicit DynamicModule() : api::DynamicModule(false) {}

        Int32Result Load() override {
            for (const auto& dll : DLL_NAMES) {
                (void)api::DynamicModule::Unload();
                api::DynamicModule::szDllName = dll;
                const auto loadRet = api::DynamicModule::Load();
                if (!loadRet) {
                    continue;
                }
                bool ok = true;
                bool any_loaded = false;
                if (ok && (any_loaded || DLL_NAMES.size() == 1)) {
                    return 0;
                }
            }
            return 0;
        }

        Int32Result Unload() override {
            const auto unloadRet = api::DynamicModule::Unload();
            if (!unloadRet) {
                return unloadRet;
            }
            return 0;
        }
    };
}






class API final: public base::ISingleton<API> {
    friend class base::ISingleton<API>;
    API() = default;
    bool loaded{false};
public:
    Crypt32::DynamicModule Crypt32{};
    AdvAPI32::DynamicModule AdvAPI32{};
    bcrypt::DynamicModule bcrypt{};
    Ws2_32::DynamicModule Ws2_32{};
    WinINet::DynamicModule WinINet{};
    IPv4::DynamicModule IPv4{};
    IPv6::DynamicModule IPv6{};
    PsAPI::DynamicModule PsAPI{};
    NtDLL::DynamicModule NtDLL{};
    UserEnv::DynamicModule UserEnv{};
    Kernel32::DynamicModule Kernel32{};
    User32::DynamicModule User32{};
    WtsAPI32::DynamicModule WtsAPI32{};
    MsImg32::DynamicModule MsImg32{};
    OpenSSL::DynamicModule OpenSSL{};

    Int32Result Load() {
        if (!this->loaded) {
            this->loaded = true;
                const auto ret_Crypt32 = this->Crypt32.Load();
            if (!ret_Crypt32) {
                return ret_Crypt32;
            }
            const auto ret_AdvAPI32 = this->AdvAPI32.Load();
            if (!ret_AdvAPI32) {
                return ret_AdvAPI32;
            }
            const auto ret_bcrypt = this->bcrypt.Load();
            if (!ret_bcrypt) {
                return ret_bcrypt;
            }
            const auto ret_Ws2_32 = this->Ws2_32.Load();
            if (!ret_Ws2_32) {
                return ret_Ws2_32;
            }
            const auto ret_WinINet = this->WinINet.Load();
            if (!ret_WinINet) {
                return ret_WinINet;
            }
            const auto ret_IPv4 = this->IPv4.Load();
            if (!ret_IPv4) {
                return ret_IPv4;
            }
            const auto ret_IPv6 = this->IPv6.Load();
            if (!ret_IPv6) {
                return ret_IPv6;
            }
            const auto ret_PsAPI = this->PsAPI.Load();
            if (!ret_PsAPI) {
                return ret_PsAPI;
            }
            const auto ret_NtDLL = this->NtDLL.Load();
            if (!ret_NtDLL) {
                return ret_NtDLL;
            }
            const auto ret_UserEnv = this->UserEnv.Load();
            if (!ret_UserEnv) {
                return ret_UserEnv;
            }
            const auto ret_Kernel32 = this->Kernel32.Load();
            if (!ret_Kernel32) {
                return ret_Kernel32;
            }
            const auto ret_User32 = this->User32.Load();
            if (!ret_User32) {
                return ret_User32;
            }
            const auto ret_WtsAPI32 = this->WtsAPI32.Load();
            if (!ret_WtsAPI32) {
                return ret_WtsAPI32;
            }
            const auto ret_MsImg32 = this->MsImg32.Load();
            if (!ret_MsImg32) {
                return ret_MsImg32;
            }
            const auto ret_OpenSSL = this->OpenSSL.Load();
            if (!ret_OpenSSL) {
                return ret_OpenSSL;
            }
            return 0;
        }
        return 0;
    }
};



} // namespace api
} // namespace sys
} // namespace cpl
