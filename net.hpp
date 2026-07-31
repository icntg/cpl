#ifndef CPL_NET_HPP
#define CPL_NET_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <tuple>
#include <utility>

#include "strings.hpp"

namespace cpl {
    namespace net {
        class Errors final {
        public:
            static constexpr int64_t base = static_cast<int64_t>(2) << 32;
            static constexpr cpl::Error::CodeDef IpFormat = {base | 1};
            static constexpr cpl::Error::CodeDef ByteMaskToUintMask = {base | 2};
            static constexpr cpl::Error::CodeDef UintMaskToByteMask = {base | 3};
            static constexpr cpl::Error::CodeDef AddressParse = {base | 4};
            static constexpr cpl::Error::CodeDef UrlParse = {base | 5};
        };

        namespace ipv4 {
            inline bool ParseDecUInt32(_In_ const std::string &s, _Out_ uint32_t &out) {
                if (s.empty() || !strings::IsDigital(s)) {
                    return false;
                }
                uint64_t v = 0;
                for (const char c: s) {
                    v = v * 10u + static_cast<uint32_t>(c - '0');
                    if (v > 0xffffffffull) {
                        return false;
                    }
                }
                out = static_cast<uint32_t>(v);
                return true;
            }

            class AddressWithMask {
            public:
                uint32_t Address;
                uint32_t Mask;

                AddressWithMask(const uint32_t address, const uint32_t mask)
                    : Address(address), Mask(mask) {
                }

                uint32_t GetAddress() const {
                    return Address;
                }

                uint32_t GetMask() const {
                    return Mask;
                }
            };

            inline uint32_t TransEndian(_In_ uint32_t v) {
                uint32_t r{};
                r |= (v & 0x000000ffu) << 24;
                r |= (v & 0x0000ff00u) << 8;
                r |= (v & 0x00ff0000u) >> 8;
                r |= (v & 0xff000000u) >> 24;
                return r;
            }

            inline Result<uint32_t> IPStringToUINT32(
                _In_ const std::string &ip,
                _In_ const bool bigEndian = false
            ) {
                if (ip.empty()) {
                    return Err(cpl::Error(Errors::IpFormat, "ip is empty" CPL_FILE_AND_LINE));
                }

                uint32_t be = 0;
                uint32_t part = 0;
                size_t dotCnt = 0;
                bool hasDigit = false;

                for (char c: ip) {
                    if (c >= '0' && c <= '9') {
                        hasDigit = true;
                        part = part * 10u + static_cast<uint32_t>(c - '0');
                        if (part > 255u) {
                            return Err(cpl::Error(Errors::IpFormat, "ip number out of range" CPL_FILE_AND_LINE));
                        }
                        continue;
                    }

                    if (c == '.') {
                        if (!hasDigit || dotCnt >= 3) {
                            return Err(cpl::Error(Errors::IpFormat, "dot in ip out of range" CPL_FILE_AND_LINE));
                        }
                        be = (be << 8u) | part;
                        part = 0;
                        hasDigit = false;
                        ++dotCnt;
                        continue;
                    }

                    return Err(cpl::Error(Errors::IpFormat, "invalid ip character" CPL_FILE_AND_LINE));
                }

                if (!hasDigit || dotCnt != 3) {
                    return Err(cpl::Error(Errors::IpFormat, "dot in ip out of range" CPL_FILE_AND_LINE));
                }

                be = (be << 8u) | part;
                return bigEndian ? be : TransEndian(be);
            }

            inline std::string UINT32ToIPString(
                _In_ const uint32_t d,
                _In_ const bool bigEndian = false
            ) {
                const uint32_t be = bigEndian ? d : TransEndian(d);
                const auto s = ""
                + std::to_string(static_cast<unsigned>((be >> 24u) & 0xffu)) + "."
                + std::to_string(static_cast<unsigned>((be >> 16u) & 0xffu)) + "."
                + std::to_string(static_cast<unsigned>((be >> 8u) & 0xffu)) + "."
                + std::to_string(static_cast<unsigned>((be) & 0xffu));
                return s;
            }

            inline Result<std::array<uint8_t, 4> > IPStringToArray(
                _In_ const std::string &ip,
                _In_ const bool bigEndian = false
            ) {
                const auto r = IPStringToUINT32(ip, true);
                if (!r.has_value()) {
                    return Err(r.error());
                }
                const auto be = r.value();
                std::array<uint8_t, 4> out{};
                out[0] = static_cast<uint8_t>((be >> 24u) & 0xffu);
                out[1] = static_cast<uint8_t>((be >> 16u) & 0xffu);
                out[2] = static_cast<uint8_t>((be >> 8u) & 0xffu);
                out[3] = static_cast<uint8_t>(be & 0xffu);
                if (!bigEndian) {
                    return out;
                }
                return out;
            }

            inline Result<uint32_t> ByteMaskToUintMask(
                _In_ const uint8_t &byteMask,
                _In_ const bool bigEndian = false
            ) {
                if (byteMask > 32u) {
                    return Err(cpl::Error(Errors::ByteMaskToUintMask, "byte mask out of range" CPL_FILE_AND_LINE));
                }

                uint32_t beMask = 0;
                if (byteMask != 0u) {
                    beMask = 0xffffffffu << (32u - byteMask);
                }
                return bigEndian ? beMask : TransEndian(beMask);
            }

            inline Result<uint8_t> UintMaskToByteMask(_In_ const uint32_t &uintMaskBE) {
                uint8_t ones = 0;
                bool zeroSeen = false;

                for (int i = 31; i >= 0; --i) {
                    const bool bit = ((uintMaskBE >> i) & 0x1u) != 0u;
                    if (bit) {
                        if (zeroSeen) {
                            return Err(cpl::Error(Errors::UintMaskToByteMask, "mask is not contiguous" CPL_FILE_AND_LINE));
                        }
                        ++ones;
                    } else {
                        zeroSeen = true;
                    }
                }
                return ones;
            }

            inline Result<uint32_t> CalculateGateway(
                _In_ const uint32_t hostBE,
                _In_ const uint32_t uintMaskBE
            ) {
                const auto bm = UintMaskToByteMask(uintMaskBE);
                if (!bm.has_value()) {
                    return Err(bm.error());
                }
                if (bm.value() > 30u) {
                    return Err(cpl::Error(Errors::AddressParse, "network too small for gateway" CPL_FILE_AND_LINE));
                }

                const uint32_t broadcast = (hostBE & uintMaskBE) | (~uintMaskBE);
                return broadcast - 1u;
            }

            inline Result<uint32_t> CalculateGateway(
                _In_ const uint32_t hostBE,
                _In_ const uint8_t byteMask
            ) {
                if (byteMask > 30u) {
                    return Err(cpl::Error(Errors::AddressParse, "network too small for gateway" CPL_FILE_AND_LINE));
                }
                const auto mask = ByteMaskToUintMask(byteMask, true);
                if (!mask.has_value()) {
                    return Err(mask.error());
                }
                return CalculateGateway(hostBE, mask.value());
            }

            inline Result<std::string> JoinAddressStrings(
                _In_ const uint32_t &hostBE,
                _In_ const uint32_t &maskBE
            ) {
                const auto bm = net::ipv4::UintMaskToByteMask(maskBE);
                if (!bm.has_value()) {
                    return Err(bm.error());
                }

                return strings::Format(
                    "%s/%hhu",
                    net::ipv4::UINT32ToIPString(hostBE, true).c_str(),
                    bm.value()
                );
            }

            inline Result<std::tuple<uint32_t, uint32_t> > SplitAddressString(
                _In_ const std::string &address
            ) {
                const auto v = strings::Split(address, "/");
                if (v.size() != 2) {
                    return Err(cpl::Error(Errors::AddressParse, "address format error" CPL_FILE_AND_LINE));
                }

                const auto hostRet = IPStringToUINT32(v[0], true);
                if (!hostRet.has_value()) {
                    return Err(hostRet.error());
                }

                const std::string &maskStr = v[1];
                auto maskRet = IPStringToUINT32(maskStr, true);
                if (!maskRet.has_value()) {
                    uint32_t n = 0;
                    if (!ParseDecUInt32(maskStr, n)) {
                        return Err(cpl::Error(Errors::AddressParse, "mask format error" CPL_FILE_AND_LINE));
                    }
                    if (n > 32u) {
                        return Err(cpl::Error(Errors::AddressParse, "cidr mask out of range" CPL_FILE_AND_LINE));
                    }
                    maskRet = ByteMaskToUintMask(static_cast<uint8_t>(n), true);
                    if (!maskRet.has_value()) {
                        return Err(maskRet.error());
                    }
                }

                return std::make_tuple(hostRet.value(), maskRet.value());
            }

            class AddressRange final : public base::serialize::ISerializeJSON {
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

                std::string GetStartString() const {
                    return UINT32ToIPString(this->start, true);
                }

                std::string GetEndString() const {
                    return UINT32ToIPString(this->end, true);
                }

                int32_t SetSingleIP(_In_ const uint32_t ip) {
                    this->start = ip;
                    this->end = ip;
                    return 0;
                }

                int32_t SetSingleIP(_In_ const std::string &ip) {
                    const auto r0 = IPStringToUINT32(ip, true);
                    if (!r0.has_value()) {
                        return -1;
                    }
                    this->start = r0.value();
                    this->end = r0.value();
                    return 0;
                }

                int32_t SetAddressRange(_In_ const uint32_t ip1, _In_ const uint32_t ip2) {
                    if (ip1 > ip2) {
                        this->start = ip2;
                        this->end = ip1;
                    } else {
                        this->start = ip1;
                        this->end = ip2;
                    }
                    return 0;
                }

                int32_t SetAddressRange(_In_ const std::string &ip1, _In_ const std::string &ip2) {
                    const auto r0 = IPStringToUINT32(ip1, true);
                    const auto r1 = IPStringToUINT32(ip2, true);
                    if (!r0.has_value() || !r1.has_value()) {
                        return -1;
                    }
                    if (r0.value() > r1.value()) {
                        this->start = r1.value();
                        this->end = r0.value();
                    } else {
                        this->start = r0.value();
                        this->end = r1.value();
                    }
                    return 0;
                }

                int32_t SetAddressMask(_In_ const uint32_t ip, _In_ const uint8_t mask) {
                    const auto r0 = ByteMaskToUintMask(mask, true);
                    if (!r0.has_value()) {
                        return -1;
                    }
                    const auto mask32 = r0.value();
                    this->start = ip & mask32;
                    this->end = ip | ~mask32;
                    return 0;
                }

                int32_t SetAddressMask(_In_ const std::string &ip, _In_ const uint8_t mask) {
                    const auto r1 = IPStringToUINT32(ip, true);
                    if (!r1.has_value()) {
                        return -1;
                    }
                    const auto r0 = ByteMaskToUintMask(mask, true);
                    if (!r0.has_value()) {
                        return -1;
                    }
                    const auto mask32 = r0.value();
                    this->start = r1.value() & mask32;
                    this->end = r1.value() | ~mask32;
                    return 0;
                }

                int32_t SetAddressAny(_In_ const std::string &s) {
                    if (s.empty()) {
                        return -1;
                    }

                    int mode = 0;
                    size_t idx = 0;
                    for (size_t i = 0; i < s.length(); i++) {
                        const auto c = s.at(i);
                        if (c == '-' || c == '/' || c == '.' || c == ' ' || (c >= '0' && c <= '9')) {
                        } else {
                            return -static_cast<int32_t>(i) - 1;
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
                        const auto ip1 = std::string(s.data(), idx);
                        const auto ip2 = std::string(s.data() + idx + 1);
                        return SetAddressRange(ip1, ip2);
                    }

                    const auto ip = std::string(s.data(), idx);
                    uint32_t mask32 = 0;
                    if (!ParseDecUInt32(std::string(s.data() + idx + 1), mask32) || mask32 > 255u) {
                        return -5;
                    }
                    const auto mask = static_cast<uint8_t>(mask32);
                    return SetAddressMask(ip, mask);
                }

                int32_t SetAddressAny(_In_ const std::string &s, _In_ const bool dhcp) {
                    const auto retCode = SetAddressAny(s);
                    this->isDHCPEnabled = dhcp;
                    return retCode;
                }

                int32_t SetAddressAny(_In_ const std::pair<const std::string, bool> &p) {
                    return SetAddressAny(p.first, p.second);
                }

                int32_t SetAddressAny(_In_ const std::tuple<const std::string, bool> &p) {
                    return SetAddressAny(std::get<0>(p), std::get<1>(p));
                }

                Result<std::string> Serialize() const {
                    return strings::Format(
                        "%s-%s",
                        this->GetStartString().c_str(),
                        this->GetEndString().c_str()
                    );
                }

                Result<std::string> ToJSON() override {
                    return strings::Format(
                        "{\"start\":\"%s\",\"end\":\"%s\"}",
                        this->GetStartString().c_str(),
                        this->GetEndString().c_str()
                    );
                }

                Int32Result FromJSON(const std::string &s) override {
                    const auto keyStart = std::string("\"start\":\"");
                    const auto keyEnd = std::string("\"end\":\"");
                    const auto p0 = s.find(keyStart);
                    const auto p1 = s.find(keyEnd);
                    if (p0 == std::string::npos || p1 == std::string::npos || p1 <= p0) {
                        return Err(cpl::Error(Errors::AddressParse, "json format error" CPL_FILE_AND_LINE));
                    }

                    const auto s0 = p0 + keyStart.length();
                    const auto e0 = s.find('"', s0);
                    const auto s1 = p1 + keyEnd.length();
                    const auto e1 = s.find('"', s1);
                    if (e0 == std::string::npos || e1 == std::string::npos) {
                        return Err(cpl::Error(Errors::AddressParse, "json format error" CPL_FILE_AND_LINE));
                    }

                    const auto ip0 = s.substr(s0, e0 - s0);
                    const auto ip1 = s.substr(s1, e1 - s1);
                    const auto ret = SetAddressRange(ip0, ip1);
                    if (ret != 0) {
                        return Err(cpl::Error(Errors::AddressParse, "json address parse failed" CPL_FILE_AND_LINE));
                    }
                    return 0;
                }

                bool IsAddressIn(const uint32_t ip) const {
                    const auto ipBE = TransEndian(ip);
                    return ipBE >= this->start && ipBE <= this->end;
                }
            };
        }

        namespace ipv6 {
        }

        // ====================================================================
        // cpl::net::url — 最小 URL 解析器
        // --------------------------------------------------------------------
        // 用于 ifw 配置的接收服务地址解析（internal_server / internal_http）。
        // 支持 udp://host:port 和 http://host:port/path 两种形式。
        // host 既可能是 IP（交给 ipv4::IPStringToUINT32 校验）也可能是域名
        // （原样保留，由调用方做 DNS 解析）。仅 header-only，不引新依赖。
        // ====================================================================
        namespace url {
            // 解析后的 URL 各部分。
            struct Components {
                std::string scheme;   // 协议，已转小写："udp" / "http"
                std::string host;     // 主机，IP 或域名（原样保留，不去空白）
                uint16_t port{0};     // 端口
                std::string path;     // 路径，仅 http 有（如 "/ifw"）；udp 为空
            };

            // 解析 udp://host:port 或 http://host:port/path。
            // 失败返回 Errors::UrlParse。host 为空或端口非法即报错。
            inline cpl::Result<Components> Parse(const std::string &in) {
                Components out{};
                const auto s = strings::Trim(in);
                if (s.empty()) {
                    return Err(cpl::Error(Errors::UrlParse, "url is empty" CPL_FILE_AND_LINE));
                }

                // 1) 找 "://" 拆 scheme 与剩余
                const auto sep = s.find("://");
                if (sep == std::string::npos || sep == 0) {
                    return Err(cpl::Error(Errors::UrlParse, "missing scheme separator ://" CPL_FILE_AND_LINE));
                }
                out.scheme = strings::ToLower(s.substr(0, sep));
                if (out.scheme != "udp" && out.scheme != "http") {
                    return Err(cpl::Error(Errors::UrlParse, "unsupported scheme" CPL_FILE_AND_LINE));
                }

                // 2) 剩余：host[:port][/path]
                std::string rest = s.substr(sep + 3);
                if (rest.empty()) {
                    return Err(cpl::Error(Errors::UrlParse, "missing host" CPL_FILE_AND_LINE));
                }

                // 3) 取 path（首个 / 之后，仅 http 关心，但都先切掉）
                std::string path;
                const auto slash = rest.find('/');
                if (slash != std::string::npos) {
                    path = rest.substr(slash);   // 含前导 /
                    rest = rest.substr(0, slash); // host[:port]
                }

                // 4) host 与 port：以最后一个冒号拆（IPv6 暂不支持，host 内不含冒号）
                const auto colon = rest.rfind(':');
                std::string hostPart;
                std::string portPart;
                if (colon != std::string::npos) {
                    hostPart = rest.substr(0, colon);
                    portPart = rest.substr(colon + 1);
                } else {
                    hostPart = rest;
                }
                hostPart = strings::Trim(hostPart);
                if (hostPart.empty()) {
                    return Err(cpl::Error(Errors::UrlParse, "host is empty" CPL_FILE_AND_LINE));
                }

                // 5) 解析端口（必须为数字且在 1~65535）
                uint16_t port = 0;
                if (portPart.empty() || !strings::IsDigital(portPart)) {
                    return Err(cpl::Error(Errors::UrlParse, "port is missing or non-numeric" CPL_FILE_AND_LINE));
                }
                uint64_t pv = 0;
                for (char c: portPart) {
                    pv = pv * 10u + static_cast<uint64_t>(c - '0');
                    if (pv > 65535u) {
                        return Err(cpl::Error(Errors::UrlParse, "port out of range" CPL_FILE_AND_LINE));
                    }
                }
                if (pv == 0) {
                    return Err(cpl::Error(Errors::UrlParse, "port must not be 0" CPL_FILE_AND_LINE));
                }
                port = static_cast<uint16_t>(pv);

                out.host = hostPart;
                out.port = port;
                // udp 不使用 path；http 保留 path（无 / 则为空）
                out.path = (out.scheme == "http") ? path : std::string{};
                return out;
            }
        }
    }
}

#endif // CPL_NET_HPP
