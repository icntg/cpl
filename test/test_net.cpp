#include "../vendor/doctest/doctest.hpp"
#include "../net.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <tuple>

using namespace cpl;
using namespace cpl::net;
using namespace cpl::net::ipv4;

TEST_SUITE("Net IPv4 Basic") {
    TEST_CASE("AddressWithMask ctor and getters") {
        const AddressWithMask v(0x01020304u, 0xffffff00u);
        CHECK_EQ(v.GetAddress(), 0x01020304u);
        CHECK_EQ(v.GetMask(), 0xffffff00u);
    }

    TEST_CASE("TransEndian swaps byte order") {
        CHECK_EQ(TransEndian(0x12345678u), 0x78563412u);
        CHECK_EQ(TransEndian(0x0100007fu), 0x7f000001u);
    }

    TEST_CASE("IPStringToUINT32 and UINT32ToIPString roundtrip") {
        const std::string ip = "192.168.1.10";

        const auto be = IPStringToUINT32(ip, true);
        REQUIRE(be.has_value());
        CHECK_EQ(be.value(), 0xC0A8010Au);
        CHECK_EQ(UINT32ToIPString(be.value(), true), ip);

        const auto le = IPStringToUINT32(ip, false);
        REQUIRE(le.has_value());
        CHECK_EQ(le.value(), 0x0A01A8C0u);
        CHECK_EQ(UINT32ToIPString(le.value(), false), ip);
    }

    TEST_CASE("IPStringToUINT32 rejects invalid ip text") {
        CHECK_FALSE(IPStringToUINT32("256.1.1.1", true).has_value());
        CHECK_FALSE(IPStringToUINT32("1.2.3", true).has_value());
        CHECK_FALSE(IPStringToUINT32("1.2.3.4.5", true).has_value());
        CHECK_FALSE(IPStringToUINT32("abc", true).has_value());
    }

    TEST_CASE("IPStringToArray parses IPv4 bytes") {
        const auto r = IPStringToArray("10.20.30.40", false);
        REQUIRE(r.has_value());

        const auto a = r.value();
        CHECK_EQ(a[0], static_cast<uint8_t>(10));
        CHECK_EQ(a[1], static_cast<uint8_t>(20));
        CHECK_EQ(a[2], static_cast<uint8_t>(30));
        CHECK_EQ(a[3], static_cast<uint8_t>(40));
    }

    TEST_CASE("ByteMaskToUintMask and UintMaskToByteMask") {
        const auto m24 = ByteMaskToUintMask(24, true);
        REQUIRE(m24.has_value());
        CHECK_EQ(m24.value(), 0xFFFFFF00u);

        const auto bm = UintMaskToByteMask(0xFFFFFF00u);
        REQUIRE(bm.has_value());
        CHECK_EQ(bm.value(), static_cast<uint8_t>(24));

        CHECK_FALSE(ByteMaskToUintMask(33, true).has_value());
        CHECK_FALSE(UintMaskToByteMask(0xFF00FF00u).has_value());
    }

    TEST_CASE("CalculateGateway with uint and byte mask") {
        const uint32_t hostBE = 0xC0A80164u; // 192.168.1.100

        const auto g0 = CalculateGateway(hostBE, 0xFFFFFF00u);
        REQUIRE(g0.has_value());
        CHECK_EQ(g0.value(), 0xC0A801FEu);

        const auto g1 = CalculateGateway(hostBE, static_cast<uint8_t>(24));
        REQUIRE(g1.has_value());
        CHECK_EQ(g1.value(), 0xC0A801FEu);

        CHECK_FALSE(CalculateGateway(hostBE, static_cast<uint8_t>(31)).has_value());
    }

    TEST_CASE("JoinAddressStrings and SplitAddressString") {
        const auto joined = JoinAddressStrings(0xC0A80164u, 0xFFFFFF00u);
        REQUIRE(joined.has_value());
        CHECK_EQ(joined.value(), std::string("192.168.1.100/24"));

        const auto s0 = SplitAddressString("192.168.1.100/24");
        REQUIRE(s0.has_value());
        CHECK_EQ(std::get<0>(s0.value()), 0xC0A80164u);
        CHECK_EQ(std::get<1>(s0.value()), 0xFFFFFF00u);

        const auto s1 = SplitAddressString("192.168.1.100/255.255.255.0");
        REQUIRE(s1.has_value());
        CHECK_EQ(std::get<0>(s1.value()), 0xC0A80164u);
        CHECK_EQ(std::get<1>(s1.value()), 0xFFFFFF00u);

        CHECK_FALSE(SplitAddressString("192.168.1.100").has_value());
        CHECK_FALSE(SplitAddressString("not-an-ip/24").has_value());
    }
}

TEST_SUITE("Net AddressRange") {
    TEST_CASE("SetSingleIP with uint32") {
        AddressRange r;
        CHECK_EQ(r.SetSingleIP(0xC0A80101u), 0);
        CHECK_EQ(r.GetStartUINT32(), 0xC0A80101u);
        CHECK_EQ(r.GetEndUINT32(), 0xC0A80101u);
        CHECK_EQ(r.GetStartString(), std::string("192.168.1.1"));
        CHECK_EQ(r.GetEndString(), std::string("192.168.1.1"));
    }

    TEST_CASE("SetSingleIP with string") {
        AddressRange r;
        CHECK_EQ(r.SetSingleIP("192.168.1.10"), 0);
        CHECK_EQ(r.GetStartString(), std::string("192.168.1.10"));
        CHECK_EQ(r.GetEndString(), std::string("192.168.1.10"));
    }

    TEST_CASE("SetAddressRange sorts start and end") {
        AddressRange r;
        CHECK_EQ(r.SetAddressRange("192.168.1.200", "192.168.1.10"), 0);
        CHECK_EQ(r.GetStartString(), std::string("192.168.1.10"));
        CHECK_EQ(r.GetEndString(), std::string("192.168.1.200"));
    }

    TEST_CASE("SetAddressMask by string and byte mask") {
        AddressRange r;
        CHECK_EQ(r.SetAddressMask("192.168.1.100", static_cast<uint8_t>(24)), 0);
        CHECK_EQ(r.GetStartString(), std::string("192.168.1.0"));
        CHECK_EQ(r.GetEndString(), std::string("192.168.1.255"));
    }

    TEST_CASE("SetAddressAny supports single, range and CIDR") {
        AddressRange r0;
        CHECK_EQ(r0.SetAddressAny("10.1.2.3"), 0);
        CHECK_EQ(r0.GetStartString(), std::string("10.1.2.3"));
        CHECK_EQ(r0.GetEndString(), std::string("10.1.2.3"));

        AddressRange r1;
        CHECK_EQ(r1.SetAddressAny("10.1.2.3-10.1.2.99"), 0);
        CHECK_EQ(r1.GetStartString(), std::string("10.1.2.3"));
        CHECK_EQ(r1.GetEndString(), std::string("10.1.2.99"));

        AddressRange r2;
        CHECK_EQ(r2.SetAddressAny("10.1.2.3/24"), 0);
        CHECK_EQ(r2.GetStartString(), std::string("10.1.2.0"));
        CHECK_EQ(r2.GetEndString(), std::string("10.1.2.255"));

        AddressRange r3;
        CHECK_EQ(r3.SetAddressAny(" 22.49.7.107/25 "), 0);
        CHECK_EQ(r3.GetStartString(), std::string("22.49.7.0"));
        CHECK_EQ(r3.GetEndString(), std::string("22.49.7.127"));

        const auto ip105 = IPStringToUINT32("22.49.7.105");
        const auto ip106 = IPStringToUINT32("22.49.7.106");
        const auto ip107 = IPStringToUINT32("22.49.7.107");
        const auto ip200 = IPStringToUINT32("22.49.7.200");
        REQUIRE(ip105.has_value());
        REQUIRE(ip106.has_value());
        REQUIRE(ip107.has_value());
        REQUIRE(ip200.has_value());
        CHECK(r3.IsAddressIn(ip105.value()));
        CHECK(r3.IsAddressIn(ip106.value()));
        CHECK(r3.IsAddressIn(ip107.value()));
        CHECK_FALSE(r3.IsAddressIn(ip200.value()));

        AddressRange r4;
        CHECK_NE(r4.SetAddressAny("22.49.7.107/33"), 0);
    }

    TEST_CASE("SetAddressAny with dhcp flag") {
        AddressRange r;
        CHECK_EQ(r.SetAddressAny("10.0.0.5", true), 0);
        CHECK(r.IsDHCPEnabled());
    }

    TEST_CASE("Serialize, ToJSON and IsAddressIn") {
        AddressRange r;
        REQUIRE_EQ(r.SetAddressRange("192.168.1.10", "192.168.1.20"), 0);

        const auto s = r.Serialize();
        REQUIRE(s.has_value());
        CHECK_EQ(s.value(), std::string("192.168.1.10-192.168.1.20"));

        const auto j = r.ToJSON();
        REQUIRE(j.has_value());
        CHECK_EQ(j.value(), std::string("{\"start\":\"192.168.1.10\",\"end\":\"192.168.1.20\"}"));

        const auto in = IPStringToUINT32("192.168.1.15");
        const auto out = IPStringToUINT32("192.168.1.99");
        REQUIRE(in.has_value());
        REQUIRE(out.has_value());

        CHECK(r.IsAddressIn(in.value()));
        CHECK_FALSE(r.IsAddressIn(out.value()));
    }
}
