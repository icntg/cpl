#ifndef NETWORK_H_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
#define NETWORK_H_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC

#include <cstdint>
#include <cstdbool>
#include <string>

using namespace std;

namespace net {
    namespace ipv4 {
        inline int32_t IPStringToUINT32(const string &ip, uint32_t &out, const bool bigEndian=true) {
            const size_t n = ip.length();
            size_t dotCnt = 0;
            uint64_t x = 0;
            uint32_t t = 0;
            for (size_t i = 0; i <= n; i++) {
                const char c = ip[i];
                if (c == '.' || c == '\0') {
                    dotCnt += 1;
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
            }
            if (dotCnt != 4) {
                return -3;
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

        inline int32_t UINT32ToIPString(const uint32_t d, string &out, const bool bigEndian = true) {
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
            out.push_back('\0');
            return 0;
        }
    }

    namespace ipv6 {
    }
}


#endif // NETWORK_H_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
