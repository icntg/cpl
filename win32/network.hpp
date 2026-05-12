#pragma once

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include "sys.hpp"
#include "api.hpp"

namespace cpl {
    namespace sys {
        namespace network {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x40) << 32;
                static constexpr cpl::Error::CodeDef InternetCrackUrlA = {base | 1};
                static constexpr cpl::Error::CodeDef InternetOpenA = {base | 2};
                static constexpr cpl::Error::CodeDef InternetConnectA = {base | 3};
                static constexpr cpl::Error::CodeDef HttpOpenRequestA = {base | 4};
                static constexpr cpl::Error::CodeDef HttpSendRequestA = {base | 5};
                static constexpr cpl::Error::CodeDef WSAStartup = {base | 6};
                static constexpr cpl::Error::CodeDef WSASocket_ = {base | 7};
                static constexpr cpl::Error::CodeDef WSACloseSocket = {base | 8};
                static constexpr cpl::Error::CodeDef WSASendTo = {base | 9};
                static constexpr cpl::Error::CodeDef APIUnavailable = {base | 10};
            };

            inline std::string inet_ntop(const struct sockaddr_in &addr) {
                static char ip_str[64]{};
                const auto *pSrc = &addr.sin_addr.s_addr;
                BYTE *ipBytes{};
                memmove(&ipBytes, &pSrc, sizeof(void *));
                snprintf(ip_str, 64, "%hhu.%hhu.%hhu.%hhu", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]);
                return ip_str;
            }

            inline Int32Result inet_pton(_Out_ struct sockaddr_in &addr, const std::string &ip) {
                uint8_t bytes[4]{};
                const int parsed = sscanf_s(
                    ip.c_str(),
                    "%hhu.%hhu.%hhu.%hhu",
                    &bytes[0], &bytes[1], &bytes[2], &bytes[3]
                );
                if (parsed != 4) {
                    return Err(cpl::Error(cpl::Error::InvalidArgument, "[X] invalid ipv4 format" CPL_FILE_AND_LINE));
                }
                const uint32_t ip_host = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(ip_host);
                return 0;
            }

            inline Result<Stream> HTTPPost(
                _In_ const std::string &url,
                _In_ Stream &data
            ) {
                Stream out{};
                constexpr char headers[] = "Content-Type: application/x-www-form-urlencoded";
                HINTERNET hSession{};
                HINTERNET hConnect{};
                HINTERNET hRequest{};
                URL_COMPONENTSA urlComponents{};
                std::vector<char> hostName(65536), urlPath(65536);

                const auto *api = &cpl::sys::api::API::Instance();
                if (!api
                    || !api->WinINet.InternetCrackUrlA
                    || !api->WinINet.InternetOpenA
                    || !api->WinINet.InternetConnectA
                    || !api->WinINet.HttpOpenRequestA
                    || !api->WinINet.HttpSendRequestA
                    || !api->WinINet.InternetReadFile
                    || !api->WinINet.InternetCloseHandle) {
                    return Err(cpl::Error(Errors::APIUnavailable, "api->WinINet.*" CPL_FILE_AND_LINE));
                }

                const auto defer = base::MakeDefer([&]() {
                    if (nullptr != hRequest) {
                        api->WinINet.InternetCloseHandle(hRequest);
                        hRequest = nullptr;
                    }
                    if (nullptr != hConnect) {
                        api->WinINet.InternetCloseHandle(hConnect);
                        hConnect = nullptr;
                    }
                    if (nullptr != hSession) {
                        api->WinINet.InternetCloseHandle(hSession);
                        hSession = nullptr;
                    }
                });

                urlComponents.dwStructSize = sizeof(urlComponents);
                urlComponents.lpszHostName = hostName.data();
                urlComponents.dwHostNameLength = static_cast<DWORD>(hostName.size() - 1);
                urlComponents.lpszUrlPath = urlPath.data();
                urlComponents.dwUrlPathLength = static_cast<DWORD>(urlPath.size() - 1);

                if (!api->WinINet.InternetCrackUrlA(url.c_str(), 0, 0, &urlComponents)) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] InternetCrackUrlA error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::InternetCrackUrlA, es.value<>());
                }

                hSession = api->WinINet.InternetOpenA("IFW-CLIENT", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
                if (nullptr == hSession) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] InternetOpenA error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::InternetOpenA, es.value<>());
                }

                hConnect = api->WinINet.InternetConnectA(
                    hSession,
                    urlComponents.lpszHostName,
                    urlComponents.nPort,
                    "",
                    "",
                    INTERNET_SERVICE_HTTP,
                    0,
                    0
                );
                if (nullptr == hConnect) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] InternetConnectA error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::InternetConnectA, es.value<>());
                }

                hRequest = api->WinINet.HttpOpenRequestA(
                    hConnect,
                    "POST",
                    urlComponents.lpszUrlPath,
                    "HTTP/1.1",
                    nullptr,
                    nullptr,
                    INTERNET_FLAG_DONT_CACHE,
                    0
                );
                if (nullptr == hRequest) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] HttpOpenRequestA error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::HttpOpenRequestA, es.value<>());
                }

                if (!api->WinINet.HttpSendRequestA(
                    hRequest,
                    headers,
                    static_cast<DWORD>(strlen(headers)),
                    static_cast<LPVOID>(data.data()),
                    static_cast<DWORD>(data.size())
                )) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] HttpSendRequestA error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::HttpSendRequestA, es.value<>());
                }

                char buffer[1024]{};
                DWORD dwBytesRead{};
                while (true) {
                    const auto r00 = api->WinINet.InternetReadFile(hRequest, buffer, sizeof(buffer), &dwBytesRead);
                    if (!r00 || dwBytesRead <= 0) {
                        break;
                    }
                    out.insert(out.end(), buffer, buffer + dwBytesRead);
                }
                return out;
            }

            inline Int32Result UDPSend(
                _In_ const std::string &host,
                _In_ const uint16_t port,
                _In_ const Stream &data,
                _In_ const bool initWSAData = true
            ) {
                const auto *api = &cpl::sys::api::API::Instance();
                if (!api
                    || !api->Ws2_32.WSAStartup
                    || !api->Ws2_32.WSAGetLastError
                    || !api->Ws2_32.socket
                    || !api->Ws2_32.htons
                    || !api->Ws2_32.inet_addr
                    || !api->Ws2_32.sendto
                    || !api->Ws2_32.closesocket
                    || !api->Ws2_32.WSACleanup) {
                    return Err(cpl::Error(Errors::APIUnavailable, "api->Ws2_32.*" CPL_FILE_AND_LINE));
                }

                const auto *pData = reinterpret_cast<const char *>(data.data());
                const auto len = static_cast<int>(data.size());
                auto sendSocket = INVALID_SOCKET;
                sockaddr_in rcvAddr{};

                const auto defer = base::MakeDefer([&]() {
                    if (INVALID_SOCKET != sendSocket) {
                        const auto r = api->Ws2_32.closesocket(sendSocket);
                        (void) r;
                    }
                    if (initWSAData) {
                        api->Ws2_32.WSACleanup();
                    }
                });

                if (initWSAData) {
                    WSADATA wsaData{};
                    const auto r00 = api->Ws2_32.WSAStartup(MAKEWORD(2, 2), &wsaData);
                    if (r00 != ERROR_SUCCESS) {
                        const auto e = api->Ws2_32.WSAGetLastError();

                        auto es = strings::Format(
                            "[X] WSAStartup failed [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                            sys::FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::WSAStartup, es.value<>());
                    }
                }

                sendSocket = api->Ws2_32.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (sendSocket == INVALID_SOCKET) {
                    const auto e = api->Ws2_32.WSAGetLastError();
                    auto es = strings::Format(
                        "[X] socket error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::WSASocket_, es.value<>());
                }

                rcvAddr.sin_family = AF_INET;
                rcvAddr.sin_port = api->Ws2_32.htons(port);
                rcvAddr.sin_addr.s_addr = api->Ws2_32.inet_addr(host.data());

                const auto r00 = api->Ws2_32.sendto(
                    sendSocket,
                    pData,
                    len,
                    0,
                    reinterpret_cast<SOCKADDR *>(&rcvAddr),
                    sizeof(rcvAddr)
                );
                if (r00 == SOCKET_ERROR) {
                    const auto e = api->Ws2_32.WSAGetLastError();
                    auto es = strings::Format(
                        "[X] sendto error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::WSASendTo, es.value<>());
                }
                return ERROR_SUCCESS;
            }

            namespace wrapper {
                inline Int32Result UDPSend(
                    const std::string &host,
                    const UINT16 port,
                    const Stream &data,
                    cpl::crypto::stl::ISync *cryptoProvider = nullptr,
                    const char *debugLabel = "udp"
                ) {
                    Stream buffer{};
                    if (!cryptoProvider) {
                        buffer = data;
                    } else {
                        const auto enc = cryptoProvider->Encrypt(data);
                        if (!enc) {
                            return Err(enc.error());
                        }
                        buffer = enc.value();
                        if (cpl::gDebug && *cpl::gDebug) {
                            const auto plainHex = cpl::codec::Hex::Hexlify(data);
                            const auto cipherB64 = cpl::codec::Base64::UrlSafeBase64Encode(buffer);
                            if (!plainHex || !cipherB64) {
                                LOG_D(
                                    "[X] Failed to serialize UDP debug payload: plain_ok=%d, cipher_ok=%d%s",
                                    plainHex.has_value() ? 1 : 0,
                                    cipherB64.has_value() ? 1 : 0,
                                    CPL_FILE_AND_LINE
                                );
                            } else {
                                LOG_D(
                                    "[?] UDP encrypted payload [%s]: plain_hex=%s cipher_urlsafe_base64=%s",
                                    debugLabel ? debugLabel : "udp",
                                    plainHex.value<>().data(),
                                    cipherB64.value<>().data()
                                );
                            }
                        }
                    }
                    return network::UDPSend(host, port, buffer);
                }

                inline Result<Stream> HTTPPost(
                    _In_ const std::string &url,
                    const Stream &data,
                    cpl::crypto::stl::ISync *cryptoProvider = nullptr
                ) {
                    Stream buffer{};
                    if (!cryptoProvider) {
                        buffer = data;
                    } else {
                        const auto enc = cryptoProvider->Encrypt(data);
                        if (!enc) {
                            return Err(enc.error());
                        }
                        buffer = enc.value();
                    }

                    const auto b64 = cpl::codec::Base64::UrlSafeBase64Encode(buffer);
                    if (!b64) {
                        return Err(b64.error());
                    }
                    auto request = Stream(b64.value().begin(), b64.value().end());
                    return network::HTTPPost(url, request);
                }
            }
        }
    }
}
