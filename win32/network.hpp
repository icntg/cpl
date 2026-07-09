#ifndef CPL_NETWORK_HPP_FLICKER_MIGHTY_BLOSSOM_GLIDE_RHYTHM_PULSE_TURBULENCE_ECHO
#define CPL_NETWORK_HPP_FLICKER_MIGHTY_BLOSSOM_GLIDE_RHYTHM_PULSE_TURBULENCE_ECHO

#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <string>

#include "api.hpp"
#include "crypto.hpp"
// ../../ccl-del/vendor/codec/base64.h removed: legacy path no longer exists.
// It was used only by the disabled wrapper::Post below.
//
// Note: cpl core has ZERO logging dependency. The legacy win32::network
// functions below (SendHTTP/SendUDP) used loguru's LOG_F, which is why those
// symbols appear; they are kept as-is for reference but the new
// sys::network::wrapper::UDPSend at the bottom is fully self-contained and
// returns Win32 error codes instead of logging.

using namespace std;

namespace cpl {
    namespace win32 {
        namespace network {
#if 0
            // ----------------------------------------------------------------------
            // Legacy cpl::win32::network (SendHTTP/SendUDP/wrapper::SendTo/Post)
            // disabled: these functions (a) depend on loguru's LOG_F via the
            // removed <share.h> include path, and (b) hard-code the RC4-based
            // Win32Crypto. New code uses cpl::sys::network::wrapper::UDPSend
            // (provider-injectable, naion CSM, zero logging) at the bottom of
            // this file. Retained as reference only.
            // ----------------------------------------------------------------------
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
                const auto &api = api::GetInstance();
                HINTERNET hInternetOpen = nullptr, hInternetConnect = nullptr, hHttpOpenRequest = nullptr; {
                    hInternetOpen = api->INet.InternetOpenA(
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
                        LOG_F(ERROR, "[x] InternetOpen failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    hInternetConnect = api->INet.InternetConnectA(
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
                        LOG_F(ERROR, "[x] InternetConnect failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    const DWORD flag = https
                                           ? INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                                             INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
                                           : 0;
                    hHttpOpenRequest = api->INet.HttpOpenRequestA(
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
                        LOG_F(ERROR, "[x] HttpOpenRequest failed: [%lu] %s", e, FormatError(e).data());
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
                    const BOOL bRet = api->INet.HttpSendRequestA(
                        hHttpOpenRequest,
                        nullptr,
                        -1,
                        p,
                        data.length()
                    );
                    if (!bRet) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<INT32>(e);
                        LOG_F(ERROR, "[x] HttpSendRequest failed: [%lu] %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                } {
                    BYTE buffer[BUFSIZ];
                    out.clear();
                    while (true) {
                        DWORD dwBytesRead = BUFSIZ;
                        bzero(buffer, sizeof(buffer));

                        const auto bRead = api->INet.InternetReadFile(
                            hHttpOpenRequest,
                            buffer,
                            BUFSIZ - 1,
                            &dwBytesRead);

                        if (dwBytesRead == 0) { break; }

                        if (!bRead) {
                            const DWORD e = GetLastError();
                            retCode = static_cast<INT32>(e);
                            LOG_F(ERROR, "[x] InternetReadFile failed: [%lu] %s", e, FormatError(e).data());
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
                    api->INet.InternetCloseHandle(hHttpOpenRequest);
                    hHttpOpenRequest = nullptr;
                }
                if (nullptr != hInternetConnect) {
                    api->INet.InternetCloseHandle(hInternetConnect);
                    hInternetConnect = nullptr;
                }
                if (nullptr != hInternetOpen) {
                    api->INet.InternetCloseHandle(hInternetOpen);
                    hInternetOpen = nullptr;
                }
                return retCode;
            }

            inline INT32 SendUDP(
                // _Out_ string& out,
                _In_ const string &host,
                _In_ const uint16_t port,
                _In_ const string &data,
                _In_ const bool initWSAData = false
            ) {
                INT32 retCode = ERROR_SUCCESS;

                const auto &p_data = data.data();
                const auto len = static_cast<int>(data.length());

                const auto &api = api::GetInstance();

                // int iRet;

                SOCKADDR *psa = nullptr;

                auto SendSocket = INVALID_SOCKET;
                sockaddr_in rcvAddr{};

                // char SendBuf[2] = "H";
                // int BufLen = 2;

                //----------------------
                // Initialize Winsock
                if (initWSAData) {
                    WSADATA wsaData{};
                    const auto r00 = api->WS32.WSAStartup(MAKEWORD(2, 2), &wsaData);
                    if (r00 != ERROR_SUCCESS) {
                        const auto e = api->WS32.WSAGetLastError();
                        retCode = e;
                        LOG_F(ERROR, "[x] WSAStartup failed %d: %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                }

                //---------------------------------------------
                // Create a socket for sending data
                SendSocket = api->WS32.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (SendSocket == INVALID_SOCKET) {
                    const int e = api->WS32.WSAGetLastError();
                    retCode = e;
                    LOG_F(ERROR, "[x] socket failed %d: %s", e, FormatError(e).data());
                    goto __ERROR__;
                }
                //---------------------------------------------
                // Set up the RecvAddr structure with the IP address of
                // the receiver (in this example case "192.168.1.1")
                // and the specified port number.
                rcvAddr.sin_family = AF_INET;
                rcvAddr.sin_port = api->WS32.htons(port);
                rcvAddr.sin_addr.s_addr = api->WS32.inet_addr(host.data());


                psa = reinterpret_cast<SOCKADDR *>(&rcvAddr); {
                    const auto r00 = api->WS32.sendto(SendSocket,
                                                      p_data,
                                                      len,
                                                      0,
                                                      psa,
                                                      sizeof(rcvAddr));

                    if (r00 == SOCKET_ERROR) {
                        const int e = api->WS32.WSAGetLastError();
                        retCode = e;
                        LOG_F(ERROR, "[x] sendto failed %d: %s", e, FormatError(e).data());
                        goto __ERROR__;
                    }
                }

                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:
                if (INVALID_SOCKET != SendSocket) {
                    const auto r00 = api->WS32.closesocket(SendSocket);
                    if (r00 == SOCKET_ERROR) {
                        const int e = api->WS32.WSAGetLastError();
                        retCode = e;
                        LOG_F(ERROR, "[x] closesocket failed %d: %s", e, FormatError(e).data());
                    }
                }
                if (initWSAData) {
                    api->WS32.WSACleanup();
                }
                return retCode;
            }

            namespace wrapper {
                inline INT32 SendTo(
                    const string &host,
                    const UINT16 port,
                    const string &data,
                    const string &secret
                ) {
                    INT32 retCode = ERROR_SUCCESS;
                    string enc{};
                    retCode |= crypto::Win32Crypto.Encrypt(
                        secret,
                        data,
                        enc
                    );
                    retCode |= SendUDP(
                        host,
                        port,
                        enc
                    );
                    return retCode;
                }

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
                    const DWORD dwTimestamp = timestamp;
                    const auto p0 = &dwTimestamp;
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
#endif // 0 (legacy win32::network disabled)
        }
    }

    // ========================================================================
    // cpl::sys::network::wrapper::UDPSend — provider-injectable encrypted UDP
    //
    // Unlike the legacy cpl::win32::network::wrapper::SendTo which hard-codes
    // the RC4-based Win32Crypto, UDPSend takes a cpl::crypto::stl::ISync *
    // (typically a cpl::naion::Client, which does CSM AEAD) and encrypts the
    // payload through it before transmission. This makes the crypto layer
    // swappable and aligns with the naion CSM path.
    //
    // The CSM client packet is self-describing, so no extra framing is added.
    // ========================================================================
    namespace sys {
        namespace network {
            namespace wrapper {
                // UDPSend — provider-injectable encrypted UDP send.
                //
                // Unlike the legacy cpl::win32::network::wrapper::SendTo (which
                // hard-codes the RC4-based Win32Crypto), UDPSend takes a
                // cpl::crypto::stl::ISync * (typically a cpl::naion::Client,
                // which performs CSM AEAD) and encrypts the payload through it
                // before transmission. The CSM client packet is self-describing,
                // so no extra framing is added.
                //
                // cpl has ZERO logging dependency: errors are returned as Win32
                // codes; the optional `tag` is for the caller's own diagnostics.
                // Winsock access goes through the NEW api system
                // (cpl::sys::api::API::Instance().Ws2_32) so this function is
                // self-contained and does not pull in legacy win32::network code.
                inline INT32 UDPSend(
                    _In_ const string &host,
                    _In_ const uint16_t port,
                    _In_ const Stream &data,
                    _In_ cpl::crypto::stl::ISync *provider,
                    _In_opt_ const char *tag = nullptr
                ) {
                    (void) tag; // reserved for caller diagnostics; cpl does not log.

                    if (nullptr == provider) {
                        return ERROR_INVALID_PARAMETER;
                    }

                    // Encrypt via the injected provider (naion CSM when a
                    // naion::Client is supplied). Encrypt returns Result<Stream>.
                    const auto enc = provider->Encrypt(data);
                    if (!enc) {
                        return ERROR_ENCRYPTION_FAILED;
                    }

                    // Defensive size guard: the CSM client packet must fit one
                    // UDP datagram (1024). Client::Encrypt already enforces the
                    // payload budget, so a violation here indicates a logic error.
                    const auto &cipher = enc.value();
                    if (cipher.size() > 1024U) {
                        return ERROR_INCORRECT_SIZE;
                    }
                    if (cipher.empty()) {
                        return ERROR_INVALID_PARAMETER;
                    }

                    const auto &api = cpl::sys::api::API::Instance();
                    auto s = INVALID_SOCKET;
                    INT32 retCode = ERROR_SUCCESS;

                    s = api.Ws2_32.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    if (s == INVALID_SOCKET) {
                        return api.Ws2_32.WSAGetLastError();
                    }

                    sockaddr_in dst{};
                    dst.sin_family = AF_INET;
                    dst.sin_port = api.Ws2_32.htons(port);
                    dst.sin_addr.s_addr = api.Ws2_32.inet_addr(host.c_str());

                    const auto sent = api.Ws2_32.sendto(
                        s,
                        reinterpret_cast<const char *>(cipher.data()),
                        static_cast<int>(cipher.size()),
                        0,
                        reinterpret_cast<const sockaddr *>(&dst),
                        sizeof(dst));
                    if (sent == SOCKET_ERROR) {
                        retCode = api.Ws2_32.WSAGetLastError();
                    }

                    (void) api.Ws2_32.closesocket(s);
                    return retCode;
                }
            } // namespace wrapper
        } // namespace network
    } // namespace sys
}

#endif //CPL_NETWORK_HPP_FLICKER_MIGHTY_BLOSSOM_GLIDE_RHYTHM_PULSE_TURBULENCE_ECHO
