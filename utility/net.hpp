#ifndef CPL_NET_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
#define CPL_NET_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC

#include <windows.h>
#include <iphlpapi.h>
#include <cstdint>
#include <string>

#include "strings.hpp"

using namespace std;
using namespace cpl::base::serialize;
using namespace cpl::strings;

namespace cpl {
    namespace net {
        namespace ipv4 {
            class AddressWithMask {
            public:
                uint32_t Address;
                uint32_t Mask;

                AddressWithMask(const uint32_t address, const uint32_t mask)
                        : Address(address),
                          Mask(mask) {
                }

                DWORD GetAddress() const {
                    return Address;
                }

                DWORD GetMask() const {
                    return Mask;
                }
            };

            inline uint32_t TransEndian(_In_ uint32_t v) {
                uint32_t r{};
                r |= (v & 0xff) << 24;
                r |= (v & 0xff00) << 8;
                r |= (v & 0xff0000) >> 8;
                r |= (v & 0xff000000) >> 24;
                return r;
            }

            inline int32_t IPStringToUINT32(
                    _Out_ uint32_t &out,
                    _In_ const string &ip,
                    _In_ const bool bigEndian = false
            ) {
                const size_t n = ip.length();
                size_t dotCnt = 0;
                uint64_t x = 0;
                uint32_t t = 0;
                for (size_t i = 0; i <= n; i++) {
                    const char c = ip[i];
                    if (c == '.' || c == '\0') {
                        dotCnt++;
                        if (x >= 256) {
                            return -2;
                        }
                        t = (t << 8) | (x & 0xff);
                        x = 0;
                    } else if (c >= '0' && c <= '9') {
                        x = x * 10 + (c - '0');
                    } else {
                        return -1;
                    }
                    if (dotCnt > 4) {
                        return -3;
                    }
                }
                if (dotCnt != 4) {
                    return -4;
                }

                if (bigEndian) {
                    out = t;
                } else {
                    out = ((t & 0xff) << 24)
                          | (((t >> 8) & 0xff) << 16)
                          | (((t >> 16) & 0xff) << 8)
                          | ((t >> 24) & 0xff);
                }
                return 0;
            }

            inline uint32_t IPStringToUINT32(_In_ const string &ip, _In_ const bool bigEndian = false) {
                uint32_t out{};
                IPStringToUINT32(out, ip, bigEndian);
                return out;
            }

            inline int32_t UINT32ToIPString(
                    _Out_ string &out,
                    _In_ const uint32_t d,
                    _In_ const bool bigEndian = false
            ) {
                out = "";
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
                char buf[3]{};
                for (const unsigned char i: a) {
                    buf[2] = static_cast<char>(i % 10);
                    buf[1] = static_cast<char>(i / 10 % 10);
                    buf[0] = static_cast<char>(i / 100 % 10);

                    if (buf[0] != 0) {
                        out.push_back(static_cast<char>(buf[0] + '0'));
                        out.push_back(static_cast<char>(buf[1] + '0'));
                        out.push_back(static_cast<char>(buf[2] + '0'));
                    } else if (buf[0] == 0 && buf[1] != 0) {
                        out.push_back(static_cast<char>(buf[1] + '0'));
                        out.push_back(static_cast<char>(buf[2] + '0'));
                    } else if (buf[0] == 0 && buf[1] == 0) {
                        out.push_back(static_cast<char>(buf[2] + '0'));
                    }
                    out.push_back('.');
                }
                out.pop_back();
                // out.push_back('\0');
                return 0;
            }

            inline string UINT32ToIPString(_In_ const uint32_t d, _In_ const bool bigEndian = false) {
                string out{};
                UINT32ToIPString(out, d, bigEndian);
                return out;
            }

            inline int32_t IPStringToArray(
                    _Out_ uint8_t out[4],
                    _In_ const string &ip,
                    _In_ const bool bigEndian = false
            ) {
                uint32_t x = 0;
                const auto retCode = IPStringToUINT32(x, ip, bigEndian);
                memmove(out, &x, sizeof(uint32_t));
                return retCode;
            }

            inline int32_t IPStringToArray(
                    _Out_ char out[4],
                    _In_ const string &ip,
                    _In_ const bool bigEndian = false
            ) {
                uint32_t x = 0;
                const auto retCode = IPStringToUINT32(x, ip, bigEndian);
                memmove(out, &x, sizeof(uint32_t));
                return retCode;
            }

            inline int32_t ByteMaskToUintMask(
                    _Out_ uint32_t &uintMask,
                    _In_ const uint8_t &byteMask,
                    _In_ const bool bigEndian = false
            ) {
                if (byteMask > 32) {
                    return -1;
                }
                constexpr uint32_t m = 0xffffffff;
                const uint32_t n = 32 - byteMask;
                uintMask = (m >> n) << n;
                if (!bigEndian) {
                    uintMask = TransEndian(uintMask);
                }
                return 0;
            }

            inline int32_t UintMaskToByteMask(_Out_ uint8_t &byteMask, _In_ const uint32_t &uintMaskBE) {
                int32_t n0 = 0;
                for (auto i = 0; i < 32; i++) {
                    const auto bit = (uintMaskBE >> i) & 0x1;
                    if (bit) {
                        n0 = i;
                        break;
                    }
                }
                const auto n1 = 32 - n0;
                for (auto i = n0; i < 32; i++) {
                    // 确保之后的数值都是1
                    const auto bit = (uintMaskBE >> i) & 0x1;
                    if (!bit) {
                        return -1;
                    }
                }
                byteMask = n1;
                return 0;
            }

            inline int32_t CalculateGateway(
                    _Out_ uint32_t &gatewayBE,
                    _In_ const uint32_t hostBE,
                    _In_ const uint32_t uintMaskBE
            ) {
                // check mask
                uint8_t byteMask{};
                const auto r00 = UintMaskToByteMask(byteMask, uintMaskBE);
                if (r00 != 0) {
                    return r00;
                }

                const uint32_t broadcast = hostBE & uintMaskBE | ~uintMaskBE;
                gatewayBE = broadcast - 1;
                return 0;
            }

            inline int32_t CalculateGateway(
                    _Out_ uint32_t &gatewayBE,
                    _In_ const uint32_t hostBE,
                    _In_ const uint8_t byteMask
            ) {
                // check mask
                // if (mask > 32) {
                if (byteMask > 30) {
                    // 网络地址空间不够。
                    return -1;
                }
                uint32_t uintMaskBE{};
                ByteMaskToUintMask(uintMaskBE, byteMask, true);

                const uint32_t broadcast = hostBE & uintMaskBE | ~uintMaskBE;
                gatewayBE = broadcast - 1;
                return 0;
            }

            inline int32_t JoinAddressStrings(
                    _Out_ string &out,
                    _In_ const uint32_t &hostBE,
                    _In_ const uint32_t &maskBE
            ) {
                uint8_t bm{};
                const auto r00 = net::ipv4::UintMaskToByteMask(bm, maskBE);
                if (r00 != 0) {
                    return r00;
                }
                out = strings::Format(
                        "%s/%hhu",
                        net::ipv4::UINT32ToIPString(hostBE).data(),
                        bm
                );
                return 0;
            }

            inline int32_t SplitAddressString(
                    _Out_ uint32_t &hostBE,
                    _Out_ uint32_t &maskBE,
                    _In_ const string &address
            ) {
                const auto v = strings::Split(address, "/");
                if (v.size() != 2) {
                    return -1;
                }
                const auto &v0 = v.at(0), &v1 = v.at(1);
                const auto r00 = IPStringToUINT32(hostBE, v0, true);
                if (r00 != 0) {
                    return -2;
                }
                const auto r01 = IPStringToUINT32(maskBE, v1, true);
                if (r01 != 0) {
                    if (!strings::IsDigital(v1)) {
                        return -3;
                    }
                    uint8_t byteMask = stoi(v1);
                    const auto r02 = net::ipv4::ByteMaskToUintMask(maskBE, byteMask, true);
                    if (r02 != 0) {
                        return -4;
                    }
                }
                return 0;
            }

            class AddressRange final : ISerializeJson {
            protected:
                uint32_t start{};
                uint32_t end{};
                bool isDHCPEnabled = false;

            public:
                uint32_t GetStartUINT32() const {
                    return this->start;
                }

                uint32_t GetEndUINT32() const {
                    return this->end;
                }

                bool IsDHCPEnabled() const {
                    return this->isDHCPEnabled;
                }

                string GetStartString() const {
                    return UINT32ToIPString(this->start);
                }

                string GetEndString() const {
                    return UINT32ToIPString(this->end);
                }

                int32_t SetSingleIP(_In_ const uint32_t ip) {
                    this->start = ip;
                    this->end = ip;
                    return ERROR_SUCCESS;
                }

                int32_t SetSingleIP(_In_ const string &ip) {
                    UINT32 ip32{};
                    const auto r0 = IPStringToUINT32(ip32, ip);
                    if (ERROR_SUCCESS == r0) {
                        return SetSingleIP(ip32);
                    }
                    return static_cast<int32_t>(r0);
                }

                int32_t SetAddressRange(_In_ const uint32_t ip1, _In_ const uint32_t ip2) {
                    if (ip1 > ip2) {
                        this->start = ip2;
                        this->end = ip1;
                    } else {
                        this->start = ip1;
                        this->end = ip2;
                    }
                    return ERROR_SUCCESS;
                }

                int32_t SetAddressRange(_In_ const string &ip1, _In_ const string &ip2) {
                    const auto r0 = IPStringToUINT32(this->start, ip1);
                    const auto r1 = IPStringToUINT32(this->end, ip2);
                    if (r0 == ERROR_SUCCESS && r1 == ERROR_SUCCESS) {
                        if (this->start > this->end) {
                            const auto t = this->start;
                            this->start = this->end;
                            this->end = t;
                        }
                    }
                    return static_cast<int32_t>(r0 | r1);
                }

                int32_t SetAddressMask(_In_ const uint32_t ip, _In_ const uint8_t mask) {
                    uint32_t mask32{};
                    const auto r0 = ByteMaskToUintMask(mask32, mask);
                    if (r0 != ERROR_SUCCESS) {
                        return r0;
                    }
                    this->start = ip & mask32;
                    this->end = ip | ~mask32;
                    return ERROR_SUCCESS;
                }

                int32_t SetAddressMask(_In_ const string &ip, _In_ const uint8_t mask) {
                    uint32_t ip32{};
                    uint32_t mask32{};
                    const auto r0 = ByteMaskToUintMask(mask32, mask);
                    if (r0 != ERROR_SUCCESS) {
                        return r0;
                    }
                    const auto r1 = IPStringToUINT32(ip32, ip);
                    if (r1 != ERROR_SUCCESS) {
                        return static_cast<int32_t>(r1);
                    }
                    return SetAddressMask(ip32, mask);
                }

                int32_t SetAddressAny(_In_ const string &s) {
                    int mode = 0;
                    int idx = 0;
                    for (auto i = 0; i < s.length(); i++) {
                        const auto c = s.at(i);
                        if (c == '-' || c == '/' || c == '.' || c == ' ' || (c >= '0' && c <= '9')) {

                        } else {
                            return ERROR_ILLEGAL_CHARACTER;
                        }
                        if (c == '-') {
                            mode = 1;
                            idx = i;
                            break;
                        }
                        if (c == '/') {
                            mode = 2;
                            idx = i;
                            break;
                        }
                    }
                    if (mode == 0) {
                        return SetSingleIP(s);
                    }
                    if (mode == 1) {
                        const auto ip1 = string(s.data(), idx);
                        const auto ip2 = string(s.data() + idx + 1);
                        return SetAddressRange(ip1, ip2);
                    }
                    {
                        const auto ip = string(s.data(), idx);
                        const auto mask = static_cast<uint8_t>(stoi(s.data() + idx + 1));
                        return SetAddressMask(ip, mask);
                    }
                }

                int32_t SetAddressAny(_In_ const string& s, _In_ const bool dhcp) {
                    const auto retCode = SetAddressAny(s);
                    this->isDHCPEnabled = dhcp;
                    return retCode;
                }

                int32_t SetAddressAny(_In_ const pair<const string, bool> &p) {
                    return SetAddressAny(p.first, p.second);
                }

                int32_t SetAddressAny(_In_ const tuple<const string, bool> &p) {
                    return SetAddressAny(get<0>(p), get<1>(p));
                }

                string Serialize() override {
                    return Format(R"(%s-%s)", this->GetStartString().data(),
                                  this->GetEndString().data());
                }

                string ToJson() override {
                    return Format(R"({"start":"%s","end":"%s"})", this->GetStartString().data(),
                                  this->GetEndString().data());
                }

                int32_t FromJson(const string &s) override {
                    return ERROR_EMPTY;
                }
            };

            inline int32_t MakeIpForwardRow(
                    _Out_ MIB_IPFORWARDROW &row,
                    _In_ const DWORD &destLE,
                    _In_ const DWORD &maskLE,
                    _In_ const DWORD &hostLE,
                    _In_ const DWORD &adapterIndex,
                    _In_ const bool forXP = false
            ) {
                row.dwForwardDest = destLE; // windows系统中使用小端序
                row.dwForwardMask = maskLE; // windows系统中使用小端序
                row.dwForwardPolicy = 0; // API不使用
                row.dwForwardNextHop = hostLE; // 网卡地址。windows系统中使用小端序
                row.dwForwardIfIndex = adapterIndex;
                row.dwForwardType = 3; // API不使用
                row.dwForwardProto = MIB_IPPROTO_NETMGMT;
                // row.ForwardProto = 3; //?

                row.dwForwardAge = 0; // API不使用
                row.dwForwardNextHopAS = 0; // API不使用
                row.dwForwardMetric2 = 0; // API不使用
                row.dwForwardMetric3 = 0; // API不使用
                row.dwForwardMetric4 = 0; // API不使用
                row.dwForwardMetric5 = 0; // API不使用
                if (!forXP) {
                    row.dwForwardMetric1 = 511;
                    // memmove(&row.ForwardProto, &row.dwForwardProto, sizeof(MIB_IPFORWARD_PROTO));
                } else {
                    row.dwForwardMetric1 = 1;
                    // bzero(&row.ForwardProto, sizeof(MIB_IPFORWARD_PROTO));
                }
                return ERROR_SUCCESS;
            }

            inline int32_t MakeIpForwardRow(
                    _Out_ MIB_IPFORWARDROW &row,
                    _In_ const string &dest,
                    _In_ const string &mask,
                    _In_ const string &host,
                    _In_ const DWORD &adapterIndex,
                    _In_ const bool forXP = false
            ) {
                UINT32 destLE, maskLE, hostLE;
                const auto r0 = IPStringToUINT32(destLE, dest);
                if (r0 != ERROR_SUCCESS) {
                    return r0;
                }
                const auto r1 = IPStringToUINT32(maskLE, mask);
                if (r1 != ERROR_SUCCESS) {
                    return r1;
                }
                const auto r2 = IPStringToUINT32(hostLE, host);
                if (r2 != ERROR_SUCCESS) {
                    return r2;
                }
                const auto r3 = MakeIpForwardRow(row, destLE, maskLE, adapterIndex, forXP);
                return r3;
            }

            inline int32_t MakeIpForwardRow(
                    _Out_ MIB_IPFORWARDROW &row,
                    _In_ const string &dest,
                    _In_ const BYTE &mask,
                    _In_ const string &host,
                    _In_ const DWORD &adapterIndex,
                    _In_ const bool forXP = false
            ) {
                UINT32 destLE, maskLE, hostLE;
                const auto r0 = IPStringToUINT32(destLE, dest);
                if (r0 != ERROR_SUCCESS) {
                    return r0;
                }
                const auto r1 = ByteMaskToUintMask(maskLE, mask);
                if (r1 != ERROR_SUCCESS) {
                    return r1;
                }
                const auto r2 = IPStringToUINT32(hostLE, host);
                if (r2 != ERROR_SUCCESS) {
                    return r2;
                }
                const auto r3 = MakeIpForwardRow(row, destLE, maskLE, adapterIndex, forXP);
                return r3;
            }
        }

        namespace ipv6 {
        }
    }
}


#endif // CPL_NET_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
