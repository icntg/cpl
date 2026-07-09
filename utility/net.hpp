// utility/net.hpp — Win32-native networking helpers used by win32/api.hpp.
//
// Per "iphlpapi 相关挪到 win32 专属代码": the platform-independent IPv4 parsing
// (AddressRange, IPStringToUINT32, etc.) now lives in the top-level net.hpp with
// a Result-based API. This file keeps only the Win32-native pieces that the
// hand-written api.hpp entities still call directly:
//   - UINT32ToIPString(uint32_t, bool) returning std::string (native flavour;
//     api.hpp does `UINT32ToIPString(...).data()` which needs a string, not a
//     Result<string>).
//   - MakeIpForwardRow(...) building MIB_IPFORWARDROW (iphlpapi, Windows-only).
//
// It re-exports the top-level net.hpp so callers also get the Result-based API
// in the same translation unit without a cpl::net::ipv4 clash (this file adds
// its helpers into cpl::win32::net, a separate namespace).

#ifndef CPL_UTILITY_NET_HPP_WIN32_NATIVE
#define CPL_UTILITY_NET_HPP_WIN32_NATIVE

#include "../net.hpp" // top-level platform-independent IPv4 (Result API)

#include <windows.h>
#include <iphlpapi.h>
#include <cstdint>
#include <string>

#include "strings.hpp"

using namespace std;

namespace cpl {
    namespace win32 {
        // Native string flavour — api.hpp hand-written entities call
        // UINT32ToIPString(...).data() and expect a std::string. Defined in
        // cpl::win32 so unqualified lookup inside cpl::win32 prefers it over
        // the top-level cpl::net::ipv4::UINT32ToIPString (Result<string>).
        inline string UINT32ToIPString(_In_ const uint32_t d, _In_ const bool bigEndian = false) {
            uint8_t a[4]{};
            if (bigEndian) {
                a[0] = (d >> 24) & 0xff;
                a[1] = (d >> 16) & 0xff;
                a[2] = (d >> 8) & 0xff;
                a[3] = d & 0xff;
            } else {
                a[3] = (d >> 24) & 0xff;
                a[2] = (d >> 16) & 0xff;
                a[1] = (d >> 8) & 0xff;
                a[0] = d & 0xff;
            }
            string out{};
            char buf[4]{};
            for (const unsigned char i : a) {
                buf[2] = static_cast<char>(i % 10);
                buf[1] = static_cast<char>(i / 10 % 10);
                buf[0] = static_cast<char>(i / 100 % 10);
                if (buf[0] != 0) {
                    out.push_back(static_cast<char>(buf[0] + '0'));
                    out.push_back(static_cast<char>(buf[1] + '0'));
                    out.push_back(static_cast<char>(buf[2] + '0'));
                } else if (buf[1] != 0) {
                    out.push_back(static_cast<char>(buf[1] + '0'));
                    out.push_back(static_cast<char>(buf[2] + '0'));
                } else {
                    out.push_back(static_cast<char>(buf[2] + '0'));
                }
                out.push_back('.');
            }
            if (!out.empty()) { out.pop_back(); }
            return out;
        }

        namespace net {
            namespace ipv4 {
                // Build a MIB_IPFORWARDROW (iphlpapi). Windows-only.
                inline int32_t MakeIpForwardRow(
                        _Out_ MIB_IPFORWARDROW &row,
                        _In_ const DWORD &destLE,
                        _In_ const DWORD &maskLE,
                        _In_ const DWORD &hostLE,
                        _In_ const DWORD &adapterIndex,
                        _In_ const bool forXP = false
                ) {
                    row.dwForwardDest = destLE;
                    row.dwForwardMask = maskLE;
                    row.dwForwardPolicy = 0;
                    row.dwForwardNextHop = hostLE;
                    row.dwForwardIfIndex = adapterIndex;
                    row.dwForwardType = 3;
                    row.dwForwardProto = MIB_IPPROTO_NETMGMT;
                    row.dwForwardAge = 0;
                    row.dwForwardNextHopAS = 0;
                    row.dwForwardMetric2 = 0;
                    row.dwForwardMetric3 = 0;
                    row.dwForwardMetric4 = 0;
                    row.dwForwardMetric5 = 0;
                    row.dwForwardMetric1 = forXP ? 1 : 511;
                    return ERROR_SUCCESS;
                }
            }
        }
    }
}

#endif // CPL_UTILITY_NET_HPP_WIN32_NATIVE
