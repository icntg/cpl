#ifndef NETWORK_H_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
#define NETWORK_H_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC

#include <cstdint>
#include <string>

#include "strings.hpp"

using namespace std;

namespace net {
    namespace ipv4 {
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

        inline int32_t ByteMaskToUintMask(const uint8_t &byteMask, uint32_t &uintMask, const bool bigEndian = false) {
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

    namespace sys {
        class Adapter final : public base::serialize::ISerializeJson {
            const IP_ADAPTER_INFO *a{};

            static string makeList(const IP_ADDR_STRING *pa) {
                vector<string> a{};
                for (auto p = pa; nullptr != p; p = p->Next) {
                    const auto s = strings::Format(
                        R"("%s/%s$%lu")",
                        strings::ReplaceAll(p->IpAddress.String, "\"", "\\\"").data(),
                        strings::ReplaceAll(p->IpMask.String, "\"", "\\\"").data(),
                        p->Context
                    );
                    a.push_back(s);
                }
                return string("[") + strings::Join(a, ",") + "]";
            }

        public:
            explicit Adapter(const IP_ADAPTER_INFO *a) {
                this->a = a;
            }

            string Serialize() override {
                vector<string> t{};
                string s{};

                s = strings::Format(R"("ComboIndex":%lu)", a->ComboIndex);
                t.push_back(s);
                s = strings::Format(R"("AdapterName":"%s")", strings::ReplaceAll(a->AdapterName, "\"", "\\\"").data());
                t.push_back(s);
                s = strings::Format(R"("Description":"%s")", strings::ReplaceAll(a->Description, "\"", "\\\"").data());
                t.push_back(s);
                s = strings::Format(R"("AddressLength":%u)", a->AddressLength);
                t.push_back(s);
                s = strings::Format(R"("Address":"%s")",
                                    strings::Hexlify(string((char *) a->Address, a->AddressLength)).data());
                t.push_back(s);
                s = strings::Format(R"("Index":%lu)", a->Index);
                t.push_back(s);
                s = strings::Format(R"("Type":%u)", a->Type);
                t.push_back(s);
                s = strings::Format(R"("DhcpEnabled":%u)", a->DhcpEnabled);
                t.push_back(s);
                if (!a->CurrentIpAddress) {
                    s = R"("CurrentIpAddress":null)";
                } else {
                    s = strings::Format(
                        R"("CurrentIpAddress":"%s/%s$%lu")",
                        strings::ReplaceAll(a->CurrentIpAddress->IpAddress.String, "\"", "\\\"").data(),
                        strings::ReplaceAll(a->CurrentIpAddress->IpMask.String, "\"", "\\\"").data(),
                        a->CurrentIpAddress->Context
                    );
                }
                t.push_back(s);
                s = strings::Format(R"("IpAddressList":%s)", makeList(&a->IpAddressList).data());
                t.push_back(s);
                s = strings::Format(R"("GatewayList":%s)", makeList(&a->GatewayList).data());
                t.push_back(s);
                s = strings::Format(R"("DhcpServer":%s)", makeList(&a->DhcpServer).data());
                t.push_back(s);
                s = strings::Format(R"("HaveWins":%d)", a->HaveWins);
                t.push_back(s);
                s = strings::Format(R"("PrimaryWinsServer":%s)", makeList(&a->PrimaryWinsServer).data());
                t.push_back(s);
                s = strings::Format(R"("SecondaryWinsServer":%s)", makeList(&a->SecondaryWinsServer).data());
                t.push_back(s);
#ifdef _USE_32BIT_TIME_T
                s = strings::Format(R"("LeaseObtained":%ld)", a->LeaseObtained);
                t.push_back(s);
                s = strings::Format(R"("LeaseExpires":%ld)", a->LeaseExpires);
                t.push_back(s);
#else
                s = strings::Format(R"("LeaseObtained":%l64d)", a->LeaseObtained);
                t.push_back(s);
                s = strings::Format(R"("LeaseExpires":%l64d)", a->LeaseExpires);
                t.push_back(s);
#endif

                string ja = string("{") + strings::Join(t, ",") + "}";
                return ja;
            }

            int32_t Deserialize(const string &s) override {
                return ERROR_EMPTY;
            }
        };

        class Adapters final : public base::serialize::ISerializeJson {
            const IP_ADAPTER_INFO *a{};
            vector<string> va{};

        public:
            explicit Adapters(const IP_ADAPTER_INFO *a) {
                this->a = a;
            }

            string Serialize() override {
                for (auto pa = a; nullptr != pa; pa = pa->Next) {
                    Adapter adapter = Adapter(pa);
                    const auto s = adapter.Serialize();
                    va.push_back(s);
                }

                return string("[") + strings::Join(va, ",") + "]";
            }

            int32_t Deserialize(const string &s) override {
                return ERROR_EMPTY;
            }
        };

        class IpForwardRow final : public base::serialize::ISerializeJson {
            const MIB_IPFORWARDROW *r{};
            bool transferIPv4 = false;

        public:
            explicit IpForwardRow(const MIB_IPFORWARDROW *r, const bool transferIPv4 = false) {
                this->r = r;
                this->transferIPv4 = transferIPv4;
            }

            string Serialize() override {
                vector<string> t{};
                string s{};
                s = strings::Format(R"("dwForwardDest":%lu)", r->dwForwardDest);
                t.push_back(s);
                if (transferIPv4) {
                    s = strings::Format(R"("ForwardDest":"%s")",
                                        ipv4::UINT32ToIPString(r->dwForwardDest, false).data());
                    t.push_back(s);
                }
                s = strings::Format(R"("dwForwardMask":%lu)", r->dwForwardMask);
                t.push_back(s);
                if (transferIPv4) {
                    s = strings::Format(R"("ForwardMask":"%s")",
                                        ipv4::UINT32ToIPString(r->dwForwardMask, false).data());
                    t.push_back(s);
                }
                s = strings::Format(R"("dwForwardPolicy":%lu)", r->dwForwardPolicy);
                t.push_back(s);
                s = strings::Format(R"("dwForwardNextHop":%lu)", r->dwForwardNextHop);
                t.push_back(s);
                if (transferIPv4) {
                    s = strings::Format(R"("ForwardNextHop":"%s")",
                                        ipv4::UINT32ToIPString(r->dwForwardNextHop, false).data());
                    t.push_back(s);
                }
                s = strings::Format(R"("dwForwardIfIndex":%lu)", r->dwForwardIfIndex);
                t.push_back(s);
                s = strings::Format(R"("dwForwardType":%lu)", r->dwForwardType);
                t.push_back(s);
                s = strings::Format(R"("dwForwardProto":%lu)", r->dwForwardProto);
                t.push_back(s);
                s = strings::Format(R"("dwForwardAge":%lu)", r->dwForwardAge);
                t.push_back(s);
                s = strings::Format(R"("dwForwardNextHopAS":%lu)", r->dwForwardNextHopAS);
                t.push_back(s);
                s = strings::Format(R"("dwForwardMetric1":%lu)", r->dwForwardMetric1);
                t.push_back(s);
                s = strings::Format(R"("dwForwardMetric2":%lu)", r->dwForwardMetric2);
                t.push_back(s);
                s = strings::Format(R"("dwForwardMetric3":%lu)", r->dwForwardMetric3);
                t.push_back(s);
                s = strings::Format(R"("dwForwardMetric4":%lu)", r->dwForwardMetric4);
                t.push_back(s);
                s = strings::Format(R"("dwForwardMetric5":%lu)", r->dwForwardMetric5);
                t.push_back(s);
                string jr = string("{") + strings::Join(t, ",") + "}";
                return jr;
            }

            int32_t Deserialize(const string &s) override {
                return ERROR_EMPTY;
            }
        };

        class IpForwardTable final : public base::serialize::ISerializeJson {
            const MIB_IPFORWARDTABLE *t{};
            vector<string> vr{};

        public:
            explicit IpForwardTable(const MIB_IPFORWARDTABLE *t) {
                this->t = t;
            }

            string Serialize() override {
                for (auto i = 0; i < t->dwNumEntries; i++) {
                    const auto &r = t->table[i];
                    IpForwardRow raw = IpForwardRow(&r);
                    const auto s = raw.Serialize();
                    vr.push_back(s);
                }

                return string("[") + strings::Join(vr, ",") + "]";
            }

            int32_t Deserialize(const string &s) override {
                return ERROR_EMPTY;
            }
        };
    }
}


#endif // NETWORK_H_JUSTICE_TREASURE_ADVANCE_STRONG_GLORIOUS_ENCHANTMENT_MAJESTIC
