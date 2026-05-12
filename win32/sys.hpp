#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <unordered_map>

#include "../base.hpp"
#include "../strings.hpp"

#ifndef ERROR_API_UNAVAILABLE
#define ERROR_API_UNAVAILABLE           15841L
#endif
#ifndef ERROR_INSTALL_FAILED
#define ERROR_INSTALL_FAILED             15609L
#endif

#define NOT_NECESSARY

namespace cpl {
    namespace sys {
        class Errors final {
        public:
            static constexpr int64_t base = static_cast<int64_t>(0x10) << 32;
            static constexpr cpl::Error::CodeDef WideCharToMultiByte = {base | 4};
            static constexpr cpl::Error::CodeDef MultiByteToWideChar = {base | 5};
            static constexpr cpl::Error::CodeDef Win32CallFailed = {base | 0x100};
        };

        inline void LOG_D(const char *tpl, ...);

        inline std::string FormatError(DWORD errorCode);

        // inline cpl::Err APIError(const char *api, const char *location);

        inline Result<std::string> FromWString(const std::wstring &s, const UINT CodePage = CP_ACP) {
            const auto size = WideCharToMultiByte(CodePage, 0, s.data(), -1, nullptr, 0, nullptr, nullptr);
            if (size <= 0) {
                return cpl::Err(cpl::Error(Errors::WideCharToMultiByte, "WideCharToMultiByte size query failed"));
            }
            std::vector<char> buffer(size);
            buffer.resize(size);
            //
            {
                const auto r0 = WideCharToMultiByte(
                    CodePage,
                    0,
                    s.data(),
                    -1,
                    buffer.data(),
                    size,
                    nullptr,
                    nullptr
                );
                if (0 == r0) {
                    const auto e = GetLastError();
                    auto rHex = cpl::codec::Hex::Hexlify(s.data(), s.size() * sizeof(wchar_t));
                    if (!rHex) {
                        return Err(rHex.error().Append(CPL_FILE_AND_LINE));
                    }
                    const auto h = rHex.value<>();
                    auto es = strings::Format(
                        "[X] convert WideChar [%s] to MultiByte failed [%u][...] CPL_FILE_AND_LINE",
                        h.data(),
                        e
                    );

                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::WideCharToMultiByte, es.value<>());
                }
                return std::string{buffer.begin(), buffer.end()};
            }
        }

        inline Result<std::wstring> FromString(const std::string &s, const UINT CodePage = CP_ACP) {
            const auto size = MultiByteToWideChar(CodePage, 0, s.data(), -1, nullptr, 0);
            if (size <= 0) {
                return cpl::Err(cpl::Error(Errors::MultiByteToWideChar, "MultiByteToWideChar size query failed"));
            }
            std::vector<wchar_t> buffer(size);
            buffer.resize(size);
            //
            {
                const auto r0 = MultiByteToWideChar(CodePage, 0, s.data(), -1, buffer.data(), size);
                if (0 == r0) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] cannot convert MultiByte [%s] to WideChar [%u][...]",
                        s.data(), e
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::MultiByteToWideChar, es.value<>());
                }
                return std::wstring{buffer.begin(), buffer.end()};
            }
        }

        namespace api {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x11) << 32;
                static constexpr cpl::Error::CodeDef OutputDebugStringFormat = {base | 1};
                static constexpr cpl::Error::CodeDef LoadLibraryA = {base | 2};
                static constexpr cpl::Error::CodeDef FreeLibrary_ = {base | 3};
                static constexpr cpl::Error::CodeDef GetProcAddress_ = {base | 4};
            };

            class DynamicModule : public cpl::base::IContext {
            private:
                static std::unordered_map<std::string, HMODULE> &ModuleMap() {
                    static std::unordered_map<std::string, HMODULE> map{};
                    return map;
                }

                static std::unordered_map<std::string, void *> &FunctionMap() {
                    static std::unordered_map<std::string, void *> map{};
                    return map;
                }

            public:
                explicit DynamicModule(const bool bModuleNecessary = true)
                    : bModuleNecessary(bModuleNecessary) {
                }

                ~DynamicModule() override = default;

                std::string szDllName{};
                bool bModuleNecessary{true};
                HMODULE hModule{};

                bool IsLoaded() override {
                    return this->hModule != nullptr;
                }

                Int32Result Load() override {
                    LOG_D("[^] start to load module [%s]\n", this->szDllName.data());
                    if (hModule) {
                        auto es = cpl::strings::Format("[X] module [%s] is loaded already",
                                                       this->szDllName.data());
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        LOG_D("%s\n", es.value<>().data());
                        return ERROR_ALREADY_EXISTS;
                    }
                    auto upperDllName = this->szDllName;
                    cpl::strings::Upper(upperDllName);
                    auto &modMap = ModuleMap();
                    if (modMap.find(upperDllName) != modMap.end()) {
                        const auto hMod = modMap.at(upperDllName);
                        if (!hMod) {
                            constexpr auto e = ERROR_INVALID_ADDRESS;
                            auto es = cpl::strings::Format(
                                "[#] module [%s] is loaded already, but null",
                                this->szDllName.data()
                            );
                            if (!es) {
                                return Err(es.error().Append(CPL_FILE_AND_LINE));
                            }
                            LOG_D("%s\n", es.value<>().data());
                            return MakeErr(Error::UnavailableAPI, es.value<>());
                        }
                        this->hModule = hMod;
                        auto es = cpl::strings::Format("[#] module [%s] is loaded already" CPL_FILE_AND_LINE,
                                                       this->szDllName.data());
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        LOG_D("%s\n", es.value<>().data());
                        return ERROR_ALREADY_EXISTS;
                    }
                    this->hModule = LoadLibraryA(this->szDllName.data());
                    if (nullptr == this->hModule) {
                        const auto e = GetLastError();
                        auto es = cpl::strings::Format(
                            "[X] LoadLibraryA [%s] failed [0x%lx][%s]" CPL_FILE_AND_LINE,
                            this->szDllName.data(), e,
                            FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        LOG_D("%s\n", es.value<>().data());
                        if (this->bModuleNecessary) {
                            return MakeErr(Errors::LoadLibraryA, es.value<>());
                        }
                        return ERROR_INSTALL_FAILED;
                    }
                    ModuleMap()[upperDllName] = this->hModule;
                    LOG_D("[$] load module [%s] at [0x%p]\n", this->szDllName.data(), this->hModule);
                    return 0;
                }

                Int32Result Unload() override {
                    if (nullptr != hModule) {
                        const auto bRet = FreeLibrary(hModule);
                        if (!bRet) {
                            const auto e = GetLastError();
                            auto es = strings::Format(
                                "[X] FreeLibrary <%s> failed [0x%lx]: %s" CPL_FILE_AND_LINE,
                                szDllName.data(), e,
                                FormatError(e).data()
                            );
                            if (!es) {
                                return Err(es.error().Append(CPL_FILE_AND_LINE));
                            }
                            LOG_D("%s\n", es.value<>().data());
                            return MakeErr(Errors::FreeLibrary_, es.value<>());
                        }
                        hModule = nullptr;
                    }
                    return 0;
                }

                // template<typename FuncPtrType>
                // Int32Result LoadFunction(
                //     _Out_ FuncPtrType &out,
                //     _In_ const char *functionName,
                //     _In_ const bool bFunctionNecessary = true
                // ) {
                //     LOG_D("[^] start to load function [%s][%s] of [%s]\n",
                //           functionName,
                //           bFunctionNecessary ? "necessary" : "not necessary",
                //           this->szDllName.data()
                //     );
                //
                //     auto upperModuleNameFunctionName{this->szDllName};
                //     // init index
                //     {
                //         upperModuleNameFunctionName = upperModuleNameFunctionName + "." + functionName;
                //         strings::Upper(upperModuleNameFunctionName);
                //     }
                //     // find
                //     {
                //         auto &funcMap = FunctionMap();
                //         if (funcMap.find(upperModuleNameFunctionName) != funcMap.end()) {
                //             const auto ptr = funcMap.at(upperModuleNameFunctionName);
                //             if (!ptr) {
                //                 constexpr auto e = ERROR_INVALID_ADDRESS;
                //                 auto es = cpl::strings::Format(
                //                     "[#] function [%s] of [%s] is loaded already, but null"
                //                     CPL_FILE_AND_LINE,
                //                     functionName,
                //                     this->szDllName.data()
                //                 );
                //                 if (!es) {
                //                     return Err(es.error().Append(CPL_FILE_AND_LINE));
                //                 }
                //                 LOG_D("%s\n", es.value<>().data());
                //                 return MakeErr(e, es.value<>());
                //             }
                //             auto es = cpl::strings::Format(
                //                 "[#] function [%s] of [%s] at [0x%p] is loaded already"
                //                 CPL_FILE_AND_LINE,
                //                 functionName,
                //                 this->szDllName.data(),
                //                 ptr
                //             );
                //             if (!es) {
                //                 return Err(es.error().Append(CPL_FILE_AND_LINE));
                //             }
                //             LOG_D("%s\n", es.value<>().data());
                //             out = reinterpret_cast<FuncPtrType>(ptr);
                //             return ERROR_ALREADY_EXISTS;
                //         }
                //     }
                //     out = reinterpret_cast<FuncPtrType>(GetProcAddress(this->hModule, functionName));
                //     if (!out) {
                //         const auto e = GetLastError();
                //         const auto es = strings::Format(
                //             "[X] GetProcAddress [%s] in [%s] failed [0x%lx][%s]", functionName,
                //             this->szDllName.data(), e, FormatError(e).data()
                //         );
                //         LOG_D("%s\n", es.value_or("[X] format failed" CPL_FILE_AND_LINE).data());
                //         if (bFunctionNecessary) {
                //             return static_cast<int32_t>(e);
                //         }
                //         return ERROR_INSTALL_FAILED;
                //     }
                //     FunctionMap()[upperModuleNameFunctionName] = out;
                //     const auto es = cpl::strings::Format(
                //         "[#] function [%s] of [%s] at [0x%p] is loaded",
                //         functionName,
                //         this->szDllName.data(),
                //         out
                //     );
                //     LOG_D("%s\n", es.value_or("[X] format failed" CPL_FILE_AND_LINE).data());
                //     // 可以为空
                //     return 0;
                // }

                template<typename FuncPtrType>
                Result<FuncPtrType> LoadFunction(
                    _In_ const char *functionName,
                    _In_ const bool bFunctionNecessary = true
                ) {
                    LOG_D("[^] start to load function [%s][%s] of [%s]\n",
                          functionName,
                          bFunctionNecessary ? "necessary" : "not necessary",
                          this->szDllName.data()
                    );

                    auto upperModuleNameFunctionName{this->szDllName};
                    // init index
                    {
                        upperModuleNameFunctionName = upperModuleNameFunctionName + "." + functionName;
                        strings::Upper(upperModuleNameFunctionName);
                    }
                    // find
                    {
                        auto &funcMap = FunctionMap();
                        if (funcMap.find(upperModuleNameFunctionName) != funcMap.end()) {
                            const auto ptr = funcMap.at(upperModuleNameFunctionName);
                            if (!ptr) {
                                constexpr auto e = ERROR_INVALID_ADDRESS;
                                auto es = cpl::strings::Format(
                                    "[#] function [%s] of [%s] is loaded already, but null"
                                    CPL_FILE_AND_LINE,
                                    functionName,
                                    this->szDllName.data()
                                );
                                if (!es) {
                                    return Err(es.error().Append(CPL_FILE_AND_LINE));
                                }
                                LOG_D("%s\n", es.value<>().data());
                                return MakeErr(e, es.value<>());
                            }
                            auto es = cpl::strings::Format(
                                "[#] function [%s] of [%s] at [0x%p] is loaded already"
                                CPL_FILE_AND_LINE,
                                functionName,
                                this->szDllName.data(),
                                ptr
                            );
                            if (!es) {
                                return Err(es.error().Append(CPL_FILE_AND_LINE));
                            }
                            LOG_D("%s\n", es.value<>().data());
                            return reinterpret_cast<FuncPtrType>(ptr);
                        }
                    }
                    const auto ptr = reinterpret_cast<FuncPtrType>(GetProcAddress(this->hModule, functionName));
                    if (!ptr) {
                        const auto e = GetLastError();
                        auto es = strings::Format(
                            "[X] GetProcAddress [%s] in [%s] failed [0x%lx][%s]", functionName,
                            this->szDllName.data(), e, FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        LOG_D("%s\n", es.value().data());
                        if (bFunctionNecessary) {
                            return MakeErr(e, es.value<>());
                        }
                        return nullptr; //
                    }
                    FunctionMap()[upperModuleNameFunctionName] = ptr;
                    auto es = cpl::strings::Format(
                        "[#] function [%s] of [%s] at [0x%p] is loaded",
                        functionName,
                        this->szDllName.data(),
                        ptr
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    LOG_D("%s\n", es.value().data());
                    // 可以为空
                    return ptr;
                }
            };


            namespace Crypt32 {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"Crypt32.dll",};

                NOT_NECESSARY typedef BOOL (WINAPI*CryptBinaryToStringA)(
                    _In_ const BYTE *pbBinary,
                    _In_ DWORD cbBinary,
                    _In_ DWORD dwFlags,
                    _Out_opt_ LPSTR pszString,
                    _Inout_ DWORD *pcchString
                );
            }

            namespace AdvAPI32 {
                const std::vector<std::string> DLL_NAMES = {"AdvAPI32.dll",};
                // const std::string DLL_NAME = "AdvAPI32.dll";

                typedef BOOL (WINAPI *ConvertStringSecurityDescriptorToSecurityDescriptorA)(
                    _In_ LPCSTR StringSecurityDescriptor,
                    _In_ DWORD StringSDRevision,
                    _Out_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
                    _Out_ PULONG SecurityDescriptorSize
                );

                typedef BOOL (WINAPI *ConvertSidToStringSidA)(
                    _In_ PSID Sid,
                    _Out_ LPSTR *StringSid
                );

                typedef BOOL (WINAPI *ConvertStringSidToSidA)(
                    _In_ LPCSTR StringSid,
                    _Out_ PSID *Sid
                );

                NOT_NECESSARY typedef BOOLEAN (WINAPI*RtlGenRandom)(
                    _Out_ PVOID RandomBuffer,
                    _In_ ULONG RandomBufferLength
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptAcquireContextA)(
                    HCRYPTPROV *phProv,
                    LPCSTR szContainer,
                    LPCSTR szProvider,
                    DWORD dwProvType,
                    DWORD dwFlags
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptReleaseContext)(
                    HCRYPTPROV hProv,
                    DWORD dwFlags
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptGenRandom)(
                    HCRYPTPROV hProv,
                    DWORD dwLen,
                    BYTE *pbBuffer
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptImportKey)(
                    _In_ HCRYPTPROV hProv,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwDataLen,
                    _In_ HCRYPTKEY hPubKey,
                    _In_ DWORD dwFlags,
                    _Out_ HCRYPTKEY *phKey
                );

                // CryptDestroyKey
                NOT_NECESSARY typedef BOOL (WINAPI*CryptDestroyKey)(
                    _In_ HCRYPTKEY hKey
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptSetKeyParam)(
                    _In_ HCRYPTKEY hKey,
                    _In_ DWORD dwParam,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwFlags
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptEncrypt)(
                    _In_ HCRYPTKEY hKey,
                    _In_ HCRYPTHASH hHash,
                    _In_ BOOL Final,
                    _In_ DWORD dwFlags,
                    _Inout_ BYTE *pbData,
                    _Inout_ DWORD *pdwDataLen,
                    _In_ DWORD dwBufLen
                );

                NOT_NECESSARY typedef BOOL (WINAPI*CryptDecrypt)(
                    _In_ HCRYPTKEY hKey,
                    _In_ HCRYPTHASH hHash,
                    _In_ BOOL Final,
                    _In_ DWORD dwFlags,
                    _Inout_ BYTE *pbData,
                    _Inout_ DWORD *pdwDataLen
                );

                // CryptCreateHash
                NOT_NECESSARY typedef BOOL (WINAPI*CryptCreateHash)(
                    _In_ HCRYPTPROV hProv,
                    _In_ ALG_ID Algid,
                    _In_ HCRYPTKEY hKey,
                    _In_ DWORD dwFlags,
                    _Out_ HCRYPTHASH *phHash
                );

                // CryptDestroyHash
                NOT_NECESSARY typedef BOOL (WINAPI*CryptDestroyHash)(
                    _In_ HCRYPTHASH hHash
                );

                // CryptSetHashParam
                NOT_NECESSARY typedef BOOL (WINAPI*CryptSetHashParam)(
                    _In_ HCRYPTHASH hHash,
                    _In_ DWORD dwParam,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwFlags
                );

                // CryptGetHashParam
                NOT_NECESSARY typedef BOOL (WINAPI*CryptGetHashParam)(
                    _In_ HCRYPTHASH hHash,
                    _In_ DWORD dwParam,
                    _Out_ BYTE *pbData,
                    _Inout_ DWORD *pdwDataLen,
                    _In_ DWORD dwFlags
                );

                // CryptHashData
                NOT_NECESSARY typedef BOOL (WINAPI*CryptHashData)(
                    _In_ HCRYPTHASH hHash,
                    _In_ const BYTE *pbData,
                    _In_ DWORD dwDataLen,
                    _In_ DWORD dwFlags
                );
            }

            namespace bcrypt {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"bcrypt.dll",};

                NOT_NECESSARY typedef NTSTATUS (WINAPI*BCryptGenRandom)(
                    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
                    _Inout_ PUCHAR pbBuffer,
                    _In_ ULONG cbBuffer,
                    _In_ ULONG dwFlags
                );
            }

            namespace Ws2_32 {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"Ws2_32.dll",};

                typedef int (WINAPI*WSAStartup)(
                    _In_ WORD wVersionRequested,
                    _Out_ LPWSADATA lpWSAData
                );

                typedef int (WINAPI*WSACleanup)();

                typedef int (WINAPI*WSAGetLastError)();

                typedef SOCKET (WINAPI*socket)(
                    _In_ int af,
                    _In_ int type,
                    _In_ int protocol
                );

                typedef u_short (WINAPI*htons)(
                    _In_ u_short host_short
                );

                typedef unsigned long (WINAPI*inet_addr)(
                    const char *cp
                );

                typedef int (WINAPI*sendto)(
                    _In_ SOCKET s,
                    _In_ const char *buf,
                    _In_ int len,
                    _In_ int flags,
                    _In_ const sockaddr *to,
                    _In_ int to_len
                );

                typedef int (WINAPI*closesocket)(_In_ SOCKET s);

                typedef int (WINAPI*setsockopt)(
                    _In_ SOCKET s,
                    _In_ int level,
                    _In_ int opt_name,
                    _In_ const char *opt_val,
                    _In_ int opt_len
                );

                typedef int (WINAPI*bind)(
                    _In_ SOCKET s,
                    _In_ const sockaddr *name,
                    _In_ int namelen
                );

                typedef int (WINAPI*recvfrom)(
                    _In_ SOCKET s,
                    _Out_ char *buf,
                    _In_ int len,
                    _In_ int flags,
                    _Out_ sockaddr *from,
                    _Inout_opt_ int *from_len
                );

                typedef u_short (WINAPI*ntohs)(
                    _In_ u_short net_short
                );

                typedef int (WINAPI *ioctlsocket)(
                    _In_ SOCKET s,
                    _In_ long cmd,
                    _Inout_ u_long *argp
                );
            }

            namespace WinINet {
                const std::vector<std::string> DLL_NAMES = {"WinINet.dll",};

                typedef HINTERNET (WINAPI*InternetOpenA)(
                    LPCSTR lpszAgent,
                    DWORD dwAccessType,
                    LPCSTR lpszProxy,
                    LPCSTR lpszProxyBypass,
                    DWORD dwFlags
                );

                typedef HINTERNET (WINAPI*InternetConnectA)(
                    HINTERNET hInternet,
                    LPCSTR lpszServerName,
                    INTERNET_PORT nServerPort,
                    LPCSTR lpszUserName,
                    LPCSTR lpszPassword,
                    DWORD dwService,
                    DWORD dwFlags,
                    DWORD_PTR dwContext
                );

                typedef HINTERNET (WINAPI*HttpOpenRequestA)(
                    HINTERNET hConnect,
                    LPCSTR lpszVerb,
                    LPCSTR lpszObjectName,
                    LPCSTR lpszVersion,
                    LPCSTR lpszReferrer,
                    LPCSTR *lplpszAcceptTypes,
                    DWORD dwFlags,
                    DWORD_PTR dwContext
                );

                typedef BOOL (WINAPI*HttpSendRequestA)(
                    HINTERNET hRequest,
                    LPCSTR lpszHeaders,
                    DWORD dwHeadersLength,
                    LPVOID lpOptional,
                    DWORD dwOptionalLength
                );

                typedef BOOL (WINAPI*InternetReadFile)(
                    _In_ HINTERNET hFile,
                    _Out_ LPVOID lpBuffer,
                    _In_ DWORD dwNumberOfBytesToRead,
                    _Out_ LPDWORD lpdwNumberOfBytesRead
                );

                typedef BOOL (WINAPI*InternetCloseHandle)(
                    HINTERNET hInternet
                );

                typedef BOOL (WINAPI*InternetCrackUrlA)(
                    __in_ecount(dwUrlLength) LPCSTR lpszUrl,
                    __in DWORD dwUrlLength,
                    __in DWORD dwFlags,
                    __inout LPURL_COMPONENTSA lpUrlComponents
                );
            }

            namespace IPv4 {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"IpHlpAPI.dll",};

                typedef ULONG (WINAPI*GetAdaptersInfo)(
                    PIP_ADAPTER_INFO AdapterInfo, PULONG
                    SizePointer);

                typedef ULONG (WINAPI*GetAdaptersAddresses)(
                    _In_ ULONG Family,
                    _In_ ULONG Flags,
                    _In_ PVOID Reserved,
                    _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses,
                    _Inout_ PULONG SizePointer
                );

                typedef DWORD (WINAPI*GetIpForwardTable)(
                    PMIB_IPFORWARDTABLE pIpForwardTable,
                    PULONG
                    pdwSize,
                    BOOL bOrder
                );

                typedef DWORD (WINAPI*DeleteIpForwardEntry)(
                    PMIB_IPFORWARDROW pRoute
                );

                typedef DWORD (WINAPI*CreateIpForwardEntry)(
                    PMIB_IPFORWARDROW pRoute
                );
            }

            namespace IPv6 {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"IpHlpAPI.dll",};

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

                NOT_NECESSARY typedef DWORD (WINAPI*GetIpForwardTable2)(
                    ADDRESS_FAMILY Family,
                    PMIB_IPFORWARD_TABLE2 *Table
                );

                NOT_NECESSARY typedef DWORD (WINAPI*DeleteIpForwardEntry2)(
                    const MIB_IPFORWARD_ROW2 *Row
                );

                NOT_NECESSARY typedef VOID (WINAPI*FreeMibTable)(
                    PVOID Memory
                );
            }

            namespace PsAPI {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"Kernel32.dll", "PsAPI.dll",};

                /* 这个方法V1（XP）在PsAPI.dll，V2在Kernel32.dll */
                NOT_NECESSARY typedef DWORD (WINAPI*GetModuleFileNameExA)(
                    _In_ HANDLE hProcess,
                    _In_opt_ HMODULE hModule,
                    _Out_ LPSTR lpFilename,
                    _In_ DWORD nSize
                );

                /* 这个方法V1在PsAPI.dll，V2在Kernel32.dll */
                NOT_NECESSARY typedef BOOL (WINAPI*EnumProcesses)(
                    _Out_ DWORD *lpidProcess,
                    _In_ DWORD cb,
                    _Out_ LPDWORD lpcbNeeded
                );

                /* 这个方法V1（XP）在PsAPI.dll，V2在Kernel32.dll */
                NOT_NECESSARY typedef BOOL (WINAPI*EnumProcessModules)(
                    _In_ HANDLE hProcess,
                    _Out_ HMODULE *lphModule,
                    _In_ DWORD cb,
                    _Out_ LPDWORD lpcbNeeded
                );

                /* 这个方法V1（XP）在PsAPI.dll，V2在Kernel32.dll */
                NOT_NECESSARY typedef BOOL (WINAPI*EnumProcessModulesEx)(
                    _In_ HANDLE hProcess,
                    _Out_ HMODULE *lphModule,
                    _In_ DWORD cb,
                    _Out_ LPDWORD lpcbNeeded,
                    _In_ DWORD dwFilterFlag
                );
            }

            namespace NtDLL {
                const std::vector<std::string> DLL_NAMES = {"NtDLL.dll",};

                typedef BOOL (WINAPI*NtSuspendProcess)(HANDLE hProcess);

                typedef BOOL (WINAPI*NtResumeProcess)(HANDLE hProcess);

                typedef BOOL (WINAPI*NtTerminateProcess)(HANDLE hProcess, UINT);

                typedef __kernel_entry NTSTATUS (WINAPI*NtQueryInformationProcess)(
                    _In_ HANDLE ProcessHandle,
                    _In_ PROCESSINFOCLASS ProcessInformationClass,
                    _Out_ PVOID ProcessInformation,
                    _In_ ULONG ProcessInformationLength,
                    _Out_opt_ PULONG ReturnLength
                );

                typedef /*NTSYSAPI*/ NTSTATUS (WINAPI*RtlGetVersion)(
                    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
                );
            }

            namespace UserEnv {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {NOT_NECESSARY "UserEnv.dll",};

                NOT_NECESSARY typedef BOOL (WINAPI*CreateEnvironmentBlock)(
                    _Out_ LPVOID *lpEnvironment,
                    _In_opt_ HANDLE hToken,
                    _In_ BOOL bInherit
                );

                NOT_NECESSARY typedef BOOL (WINAPI*DestroyEnvironmentBlock)(
                    _In_ LPVOID lpEnvironment
                );
            }

            namespace Kernel32 {
                // Kernel32.dll
                const std::vector<std::string> DLL_NAMES = {"Kernel32.dll",};

                NOT_NECESSARY typedef BOOL (WINAPI*ProcessIdToSessionId)(
                    _In_ DWORD dwProcessId,
                    _Out_ DWORD *pSessionId
                );

                NOT_NECESSARY typedef DWORD (WINAPI*WTSGetActiveConsoleSessionId)();

                NOT_NECESSARY typedef BOOL (WINAPI*QueryFullProcessImageNameA)(
                    _In_ HANDLE hProcess,
                    _In_ DWORD dwFlags,
                    _Out_ LPSTR lpExeName,
                    _Inout_ PDWORD lpdwSize
                );
            }

            namespace User32 {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"User32.dll",};

                NOT_NECESSARY typedef LRESULT (WINAPI*SendMessageTimeoutA)(
                    _In_ HWND hWnd,
                    _In_ UINT Msg,
                    _In_ WPARAM wParam,
                    _In_ LPARAM lParam,
                    _In_ UINT fuFlags,
                    _In_ UINT uTimeout,
                    _Out_opt_ PDWORD_PTR lpdwResult
                );
            }

            namespace WtsAPI32 {
                // Wtsapi32.dll
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"WtsAPI32.dll",};

                NOT_NECESSARY typedef BOOL (WINAPI *WTSQueryUserToken)(
                    _In_ ULONG SessionId,
                    _Out_ PHANDLE phToken
                );
            }

            namespace MsImg32 {
                // Wtsapi32.dll
                const std::vector<std::string> DLL_NAMES = {"MsImg32.dll",};

                typedef BOOL (WINAPI *GradientFill)(
                    _In_ HDC hdc,
                    _In_ PTRIVERTEX pVertex,
                    _In_ ULONG nVertex,
                    _In_ PVOID pMesh,
                    _In_ ULONG nMesh,
                    _In_ ULONG ulMode
                );
            }

            namespace OpenSSL {
                NOT_NECESSARY const std::vector<std::string> DLL_NAMES = {"libcrypto.dll", "libeay32.dll",};
            }
        }

        inline void LOG_D(const char *tpl, ...) {
            if (gDebug && !*gDebug) {
                return;
            }
            va_list args;
            va_start(args, tpl);
            // const auto retCode = cpl::strings::VFormat(nWritten, out, tpl, args);
            auto r = cpl::strings::VFormat(tpl, args);
            va_end(args);

            if (r) {
                OutputDebugStringA(r.value<>().data());
                if (base::log::exLoggerFunc) {
                    base::log::exLoggerFunc(r.value<>());
                }
            } else {
                std::string es{};
                const auto &e = r.error();
                char b[128]{};
                sprintf_s(b, 128, "0x%lx%lx", e.Code.x32.h, e.Code.x32.l);
                es = std::string{"[X] LOG_D / Format Error ["} + b + "][" + e.Reason + "]";
                OutputDebugStringA(es.c_str());
                if (base::log::exLoggerFunc) {
                    base::log::exLoggerFunc(es);
                }
            }
        }


        inline std::string FormatError(const DWORD errorCode) {
            char buffer[2048]{};
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM,
                nullptr,
                errorCode,
                0,
                buffer,
                sizeof(buffer),
                nullptr
            );
            const auto n = strlen(buffer);
            if (n >= 2 && buffer[n - 2] == '\r' && buffer[n - 1] == '\n') {
                buffer[n - 2] = '\0';
            }
            return buffer;
        }

        inline Err Win32Error(const cpl::Error::CodeDef code, const char *fmt, const DWORD e,
                              const char *loc = nullptr) {
            auto es = strings::Format(fmt, e, FormatError(e).data());
            if (!es) {
                return Err(es.error().Append(CPL_FILE_AND_LINE));
            }
            if (loc) {
                return Err(Error(code, (es.value<>() + loc).c_str()));
            }
            return Err(Error(code, es.value<>().c_str()));
        }

        inline Err APICallingError(const char *api, const char *location) {
            const auto e = GetLastError();
            const auto es = std::string("[X] ") + api + "failed 0x[%lx][%s]" + CPL_FILE_AND_LINE;
            return Win32Error(
                Errors::Win32CallFailed,
               es.data(),
                e,
                location
            );
        }
    }
}

#undef NOT_NECESSARY
