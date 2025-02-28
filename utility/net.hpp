#ifndef CPL_NET_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
#define CPL_NET_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC

#include <windows.h>
#include <iphlpapi.h>
#include <cstdint>
#include <string>
#include <vector>

#include "strings.hpp"

using namespace std;

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

            inline uint32_t TransEndian(uint32_t v) {
                uint32_t r{};
                r |= (v & 0xff) << 24;
                r |= (v & 0xff00) << 8;
                r |= (v & 0xff0000) >> 8;
                r |= (v & 0xff000000) >> 24;
                return r;
            }

            inline int32_t IPStringToUINT32(const string &ip, uint32_t &out, const bool bigEndian = false) {
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

            inline uint32_t IPStringToUINT32(const string &ip, const bool bigEndian = false) {
                uint32_t out{};
                IPStringToUINT32(ip, out, bigEndian);
                return out;
            }

            inline int32_t UINT32ToIPString(const uint32_t d, string &out, const bool bigEndian = false) {
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

            inline string UINT32ToIPString(const uint32_t d, const bool bigEndian = false) {
                string out{};
                UINT32ToIPString(d, out, bigEndian);
                return out;
            }

            inline int32_t IPStringToArray(const string &ip, uint8_t out[4], const bool bigEndian = false) {
                uint32_t x = 0;
                const auto retCode = IPStringToUINT32(ip, x, bigEndian);
                memmove(out, &x, sizeof(uint32_t));
                return retCode;
            }

            inline int32_t IPStringToArray(const string &ip, char out[4], const bool bigEndian = false) {
                uint32_t x = 0;
                const auto retCode = IPStringToUINT32(ip, x, bigEndian);
                memmove(out, &x, sizeof(uint32_t));
                return retCode;
            }

            inline int32_t ByteMaskToUintMask(const uint8_t &byteMask, uint32_t &uintMask,
                                              const bool bigEndian = false) {
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

            inline int32_t UintMaskToByteMask(const uint32_t &uintMaskBE, uint8_t &byteMask) {
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

            inline int32_t CalculateGateway(const uint32_t hostBE, const uint32_t uintMaskBE, uint32_t &gatewayBE) {
                // check mask
                uint8_t byteMask{};
                const auto r00 = UintMaskToByteMask(uintMaskBE, byteMask);
                if (r00 != 0) {
                    return r00;
                }

                const uint32_t broadcast = hostBE & uintMaskBE | ~uintMaskBE;
                gatewayBE = broadcast - 1;
                return 0;
            }

            inline int32_t CalculateGateway(const uint32_t hostBE, const uint8_t byteMask, uint32_t &gatewayBE) {
                // check mask
                // if (mask > 32) {
                if (byteMask > 30) {
                    // 网络地址空间不够。
                    return -1;
                }
                uint32_t uintMaskBE{};
                ByteMaskToUintMask(byteMask, uintMaskBE, true);

                const uint32_t broadcast = hostBE & uintMaskBE | ~uintMaskBE;
                gatewayBE = broadcast - 1;
                return 0;
            }

            inline int32_t JoinAddressStrings(const uint32_t &hostBE, const uint32_t &maskBE, string &out) {
                uint8_t bm{};
                const auto r00 = net::ipv4::UintMaskToByteMask(maskBE, bm);
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

            inline int32_t SplitAddressString(const string &address, uint32_t &hostBE, uint32_t &maskBE) {
                const auto v = strings::Split(address, "/");
                if (v.size() != 2) {
                    return -1;
                }
                const auto &v0 = v.at(0), &v1 = v.at(1);
                const auto r00 = IPStringToUINT32(v0, hostBE, true);
                if (r00 != 0) {
                    return -2;
                }
                const auto r01 = IPStringToUINT32(v1, maskBE, true);
                if (r01 != 0) {
                    if (!strings::IsDigital(v1)) {
                        return -3;
                    }
                    uint8_t byteMask = stoi(v1);
                    const auto r02 = net::ipv4::ByteMaskToUintMask(byteMask, maskBE, true);
                    if (r02 != 0) {
                        return -4;
                    }
                }
                return 0;
            }
        }

        namespace ipv6 {
        }
    }
}


#endif // CPL_NET_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
