#ifndef CPL_WIN32_DNS_HPP_RIVER_OCEAN_SKY_CLOUD_WIND_LIGHT_HARMONY_ECHO
#define CPL_WIN32_DNS_HPP_RIVER_OCEAN_SKY_CLOUD_WIND_LIGHT_HARMONY_ECHO

// DNS resolution via dynamically loaded getaddrinfo (Ws2_32.dll, XP+).
// Used by ifw's network-sense feature to resolve a configured domain name
// (e.g. portal.company.com) and determine whether the resolved IP falls
// inside the internal network range.

#include "../base.hpp"
#include "../net.hpp"
#include <cstdint>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "api.hpp"

namespace cpl {
    namespace win32 {
        namespace dns {

            // Resolve a hostname to the first IPv4 address (host byte order).
            // Returns Result<uint32_t> where the value is the IPv4 address
            // in the same format as cpl::net::ipv4::IPStringToUINT32().
            //
            // Uses getaddrinfo with AF_INET hint. Requires WSAStartup to
            // have been called previously (ifw calls it once during init).
            //
            // Example:
            //   auto r = Resolve("portal.company.com");
            //   if (r) { auto ipStr = cpl::net::ipv4::UINT32ToIPString(r.value<>()); }
            inline cpl::Result<uint32_t> Resolve(const std::string &hostname) {
                const auto &ws = cpl::sys::api::API::Instance().Ws2_32;

                if (!ws.getaddrinfo || !ws.freeaddrinfo) {
                    return cpl::MakeErr(cpl::Error::UnavailableAPI,
                        "[X] getaddrinfo not available" CPL_FILE_AND_LINE);
                }

                struct addrinfo hints{};
                hints.ai_family = AF_INET;       // IPv4 only
                hints.ai_socktype = SOCK_DGRAM;  // don't need a specific type
                hints.ai_protocol = IPPROTO_UDP;

                struct addrinfo *result = nullptr;
                const int rc = ws.getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
                if (rc != 0 || result == nullptr) {
                    const std::string msg = "[X] DNS resolve failed for " + hostname + " rc=" + std::to_string(rc);
                    return cpl::MakeErr(rc, msg.c_str());
                }

                // Take the first AF_INET result
                uint32_t ip = 0;
                for (auto *ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
                    if (ptr->ai_family == AF_INET) {
                        const auto *sa = reinterpret_cast<struct sockaddr_in *>(ptr->ai_addr);
                        // sin_addr.s_addr is in network byte order (big-endian).
                        // cpl::net::ipv4 uses host byte order internally, so
                        // we convert via cpl::net::ipv4::TransEndian（等价于 ntohl，
                        // 但避免直接调用 ntohl 引入对 Ws2_32.lib 的静态链接依赖——
                        // ifw 终端只动态加载 Ws2_32，不链接其导入库）。
                        ip = cpl::net::ipv4::TransEndian(sa->sin_addr.s_addr);
                        break;
                    }
                }

                ws.freeaddrinfo(result);

                if (ip == 0) {
                    return cpl::MakeErr(cpl::Error::NoData, "[X] DNS resolve returned no AF_INET results");
                }

                return ip;
            }

            // Convenience: resolve and return as dotted-decimal string.
            inline cpl::Result<std::string> ResolveToString(const std::string &hostname) {
                const auto r = Resolve(hostname);
                if (!r) return cpl::Err(r.error());
                return cpl::net::ipv4::UINT32ToIPString(r.value<>());
            }

        } // namespace dns
    } // namespace win32
} // namespace cpl

#endif // CPL_WIN32_DNS_HPP_RIVER_OCEAN_SKY_CLOUD_WIND_LIGHT_HARMONY_ECHO
