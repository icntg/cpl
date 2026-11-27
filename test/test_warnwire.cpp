// Tests for cpl::warnwire, the builder of the warnwire version 3 alert packets.
//
// The expected bytes are written by hand from the wire format that the server parses
// (server/service/index/warnwire.go): a 7-byte little-endian header followed by a
// stream of tag (1 byte) + length (unsigned LEB128) + value. ReadItems() decodes a
// packet the way the server does; it is used to look at the items of a packet.
#include "../vendor/doctest/doctest.hpp"
#include "../warnwire.hpp"
#include "../strings.hpp" // cpl::codec::Hex and cpl::codec::Leb128

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace cpl;
using namespace cpl::warnwire;

namespace {
    // Two event ids and the IPv6 gateway fe80::1 of the examples, in the upper case
    // that cpl::codec::Hex prints.
    const char *const kIdA = "5BBAB4CF01D18529383F71B1";
    const char *const kIdB = "5BBAB4CF01D18529383F71C1";
    const char *const kGateway6 = "FE800000000000000000000000000001";

    // The header of every message type: version 3 and the time 0x78563412.
    const std::string kAdapterHeader = "03001234567800";
    const std::string kV4Header = "03001234567801";
    const std::string kV6Header = "03001234567802";
    const std::string kUsbHeader = "03001234567803";

    // Returns the value of a successful Result, or fails the test case.
    template <typename T>
    T Must(Result<T> r) {
        REQUIRE(r.has_value());
        return std::move(r.value());
    }

    Stream Unhex(const char *hex) {
        return Must(cpl::codec::Hex::UnHexlify(hex));
    }

    // Hexadecimal text of a non-empty byte string.
    std::string HexOf(const Stream &bytes) {
        return Must(cpl::codec::Hex::Hexlify(bytes));
    }

    std::string Repeat(const std::string &text, const size_t count) {
        std::string out{};
        for (size_t i = 0; i < count; i++) {
            out += text;
        }
        return out;
    }

    // A fixed size array from hexadecimal text: an address or an event id.
    template <size_t N>
    std::array<uint8_t, N> ArrayOf(const char *hex) {
        std::array<uint8_t, N> out{};
        const auto bytes = Unhex(hex);
        REQUIRE_EQ(bytes.size(), N);
        std::copy(bytes.begin(), bytes.end(), out.begin());
        return out;
    }

    ObjectId IdOf(const char *hex) {
        ObjectId id{};
        id.bytes = ArrayOf<12>(hex);
        return id;
    }

    // One item of the TLV stream.
    struct Item {
        Tag tag;
        Stream value;
    };

    // Decodes the TLV stream after the header the way the server does. Returns false
    // when the stream is malformed; `items` then holds what was decoded before.
    bool ReadItems(const Stream &packet, std::vector<Item> &items) {
        items.clear();
        if (packet.size() < kHeaderBytes) {
            return false;
        }
        size_t pos = kHeaderBytes;
        while (pos < packet.size()) {
            const auto tag = static_cast<Tag>(packet[pos]);
            pos++;
            // Length: unsigned LEB128, at most 9 bytes.
            uint64_t length = 0;
            unsigned shift = 0;
            size_t count = 0;
            while (true) {
                if (pos >= packet.size() || count == 9) {
                    return false;
                }
                const uint8_t byte = packet[pos];
                pos++;
                length |= static_cast<uint64_t>(byte & 0x7fu) << shift;
                shift += 7u;
                count++;
                if ((byte & 0x80u) == 0u) {
                    break;
                }
            }
            if (length > packet.size() - pos) {
                return false;
            }
            Item item{};
            item.tag = tag;
            const auto begin = packet.begin() + static_cast<std::ptrdiff_t>(pos);
            item.value.assign(begin, begin + static_cast<std::ptrdiff_t>(length));
            pos += static_cast<size_t>(length);
            items.push_back(item);
        }
        return true;
    }

    size_t Count(const std::vector<Item> &items, const Tag tag) {
        size_t count = 0;
        for (size_t i = 0; i < items.size(); i++) {
            if (items[i].tag == tag) {
                count++;
            }
        }
        return count;
    }

    // The last item with the tag, or null.
    const Item *FindLast(const std::vector<Item> &items, const Tag tag) {
        for (size_t i = items.size(); i > 0; i--) {
            if (items[i - 1].tag == tag) {
                return &items[i - 1];
            }
        }
        return nullptr;
    }

    std::string Text(const Item &item) {
        return std::string(item.value.begin(), item.value.end());
    }

    // A snapshot named "eth0" without mac and addresses: 12 bytes on the wire, plus
    // its description. The score carries the index.
    AdapterSnapshot MakeAdapter(const uint16_t index, const size_t descriptionBytes) {
        AdapterSnapshot snapshot{};
        snapshot.name = "eth0";
        snapshot.score = static_cast<uint8_t>(index);
        snapshot.description.assign(descriptionBytes, 'd');
        return snapshot;
    }

    // Every adapter item: name, description, mac, ifIndex, ipv4, mask, gateway,
    // score 90, dhcp on.
    AdapterSnapshot FullAdapter() {
        AdapterSnapshot snapshot{};
        snapshot.name = "eth0";
        snapshot.description = "NIC";
        snapshot.mac = MacAddress{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
        snapshot.hasMac = true;
        snapshot.ifIndex = 2;
        snapshot.ipv4 = Ipv4Address{{192, 168, 1, 1}};
        snapshot.ipv4Mask = Ipv4Address{{255, 255, 255, 0}};
        snapshot.ipv4Gateway = Ipv4Address{{192, 168, 1, 254}};
        snapshot.score = 90;
        snapshot.dhcpEnabled = 1;
        return snapshot;
    }

    // The items of FullAdapter() on the wire.
    const std::string kFullAdapter =
        "010465746830" // name "eth0"
        "02034E4943" // description "NIC"
        "0306AABBCCDDEEFF" // mac
        "090402000000" // ifIndex 2
        "0404C0A80101" // 192.168.1.1
        "0504FFFFFF00" // 255.255.255.0
        "0604C0A801FE" // 192.168.1.254
        "10015A" // score 90
        "110101"; // dhcp on

    // The adapter evidence of the reference sender
    // (server/service/index/cmd/alertsender/main.go, appendAdapterEvidence).
    const std::string kReferenceEvidence =
        "01267B3444363645383930" "2D" "46333241" "2D" "31314543" "2D" "42374130" "2D"
        "334532324642383831324137" "7D" // "{4D66E890-F32A-11EC-B7A0-3E22FB8812A7}"
        "021755534220576972656C657373203830322E3131204E4943" // "USB Wireless 802.11 NIC"
        "0306A86DAA123456" // mac
        "09040E000000" // ifIndex 14
        "04040A885A37" // 10.136.90.55
        "0504FFFFFF00"; // 255.255.255.0

    // A device group of 24 bytes: vid, pid, an empty serial and the event id, plus its
    // description. The vid carries the index.
    UsbDevice MakeDevice(const uint16_t index, const size_t descriptionBytes) {
        UsbDevice device{};
        device.vid = index;
        device.pid = 0x572B;
        device.eventId = IdOf(kIdA);
        device.description.assign(descriptionBytes, 'd');
        return device;
    }

    // Every device item.
    UsbDevice FullDevice() {
        UsbDevice device{};
        device.vid = 0x0EA0;
        device.pid = 0x7301;
        device.serial = "SR001";
        device.description = "USB Cable";
        device.className = "USB\\Class_ff";
        device.hitKeyword = "VID_0EA0&PID_7301";
        device.eventId = IdOf(kIdA);
        return device;
    }

    // The items of FullDevice() on the wire, without the event id.
    const std::string kFullDevice =
        "0C02A00E" // vid 0x0EA0
        "0D020173" // pid 0x7301
        "0B055352303031" // serial "SR001"
        "0209555342204361626C65" // description "USB Cable"
        "120C5553425C436C6173735F6666" // class name "USB\Class_ff"
        "0A115649445F30454130265049445F37333031"; // keyword "VID_0EA0&PID_7301"

    // The event id item.
    const std::string kEventIdA = "1B0C" + std::string(kIdA);

    // The snapshot of MakeAdapter(0, 0) on the wire.
    const std::string kMinimalAdapter = "010465746830" "100100" "110100";
}

TEST_SUITE("cpl::warnwire") {
    TEST_CASE("header: version, timestamp and message type are little-endian") {
        const Builder builder(MsgOutboundV4, 0x01020304u);
        CHECK_EQ(builder.Size(), kHeaderBytes);
        CHECK_EQ(builder.Remaining(), kTruncateThreshold - kHeaderBytes);
        const auto packet = Must(builder.Build());
        CHECK_EQ(HexOf(packet), std::string("03000403020101"));
    }

    TEST_CASE("header: every message type is the last byte") {
        const std::string expected[] = {kAdapterHeader, kV4Header, kV6Header, kUsbHeader};
        const MsgType types[] = {MsgIllegalAdapter, MsgOutboundV4, MsgOutboundV6, MsgWarnUsb};
        for (size_t i = 0; i < 4; i++) {
            const auto packet = Must(Builder(types[i], 0x78563412u).Build());
            REQUIRE_EQ(packet.size(), kHeaderBytes);
            CHECK_EQ(HexOf(packet), expected[i]);
        }
    }

    TEST_CASE("String writes tag, length and the bytes of the text") {
        const auto keyword = Must(Builder(MsgWarnUsb, 0x78563412u).String(TagKeyword, "USB").Build());
        CHECK_EQ(HexOf(keyword), kUsbHeader + "0A03555342");
        // An empty text is still an item.
        const auto empty = Must(Builder(MsgWarnUsb, 0x78563412u).String(TagDescription, "").Build());
        CHECK_EQ(HexOf(empty), kUsbHeader + "0200");
        // The bytes are written as they are: "caf" and the two bytes of U+00E9.
        const Stream utf8 = {0x63, 0x61, 0x66, 0xC3, 0xA9};
        const auto text = Must(Builder(MsgWarnUsb, 0x78563412u).String(
            TagDescription, std::string(utf8.begin(), utf8.end())).Build());
        CHECK_EQ(HexOf(text), kUsbHeader + "0205" + "636166C3A9");
    }

    TEST_CASE("Bytes writes tag, length and the raw bytes") {
        const uint8_t mac[6] = {0xA8, 0x6D, 0xAA, 0x12, 0x34, 0x56};
        const auto withMac = Must(Builder(MsgWarnUsb, 0x78563412u).Bytes(TagMac, mac, sizeof(mac)).Build());
        CHECK_EQ(HexOf(withMac), kUsbHeader + "0306A86DAA123456");
        // A null pointer is an empty value, so the stream stays parseable.
        const auto null = Must(Builder(MsgWarnUsb, 0x78563412u).Bytes(TagForensicRef, nullptr, 5).Build());
        CHECK_EQ(HexOf(null), kUsbHeader + "1300");
        std::vector<Item> items{};
        REQUIRE(ReadItems(null, items));
        REQUIRE_EQ(items.size(), 1u);
        CHECK(items[0].tag == TagForensicRef);
    }

    TEST_CASE("U8 writes tag, length 1 and the value") {
        const auto location = Must(Builder(MsgWarnUsb, 0x78563412u).U8(TagNetworkLocation, 1).Build());
        CHECK_EQ(HexOf(location), kUsbHeader + "0E0101");
        const auto truncated = Must(Builder(MsgWarnUsb, 0x78563412u).Truncated(200).Build());
        CHECK_EQ(HexOf(truncated), kUsbHeader + "0F01C8");
    }

    TEST_CASE("U16LE writes tag, length 2 and the value little-endian") {
        const auto vid = Must(Builder(MsgWarnUsb, 0x78563412u).U16LE(TagUsbVid, 0x04E8).Build());
        CHECK_EQ(HexOf(vid), kUsbHeader + "0C02E804");
        const auto pid = Must(Builder(MsgWarnUsb, 0x78563412u).U16LE(TagUsbPid, 0x7301).Build());
        CHECK_EQ(HexOf(pid), kUsbHeader + "0D020173");
    }

    TEST_CASE("U32LE writes tag, length 4 and the value little-endian") {
        const auto ifIndex = Must(Builder(MsgWarnUsb, 0x78563412u).U32LE(TagIfIndex, 0x01020304u).Build());
        CHECK_EQ(HexOf(ifIndex), kUsbHeader + "090404030201");
    }

    TEST_CASE("EventId writes tag, length 12 and the bytes") {
        const auto packet = Must(Builder(MsgWarnUsb, 0x78563412u).EventId(TagEventId, IdOf(kIdA)).Build());
        CHECK_EQ(HexOf(packet), kUsbHeader + kEventIdA);
    }

    TEST_CASE("chained setters keep the order of the calls") {
        const auto gateway = ArrayOf<16>(kGateway6);
        const auto packet = Must(Builder(MsgOutboundV6, 0x78563412u)
                                     .String(TagKeyword, "USB")
                                     .U8(TagTruncated, 1)
                                     .Bytes(TagIPv6Gateway, gateway.data(), gateway.size())
                                     .Build());
        CHECK_EQ(HexOf(packet), kV6Header + "0A03555342" + "0F0101" + "0810" + kGateway6);
    }

    TEST_CASE("lengths of 127, 128 and 300 bytes get a one or two byte LEB128 length") {
        const Stream bytes127(127, 0x78);
        const auto packet127 = Must(
            Builder(MsgWarnUsb, 0x78563412u).Bytes(TagKeyword, bytes127.data(), bytes127.size()).Build());
        CHECK_EQ(HexOf(packet127), kUsbHeader + "0A7F" + Repeat("78", 127));

        const Stream bytes128(128, 0x78);
        const auto packet128 = Must(
            Builder(MsgWarnUsb, 0x78563412u).Bytes(TagKeyword, bytes128.data(), bytes128.size()).Build());
        CHECK_EQ(HexOf(packet128), kUsbHeader + "0A8001" + Repeat("78", 128));

        const Stream bytes300(300, 0x78);
        const auto packet300 = Must(
            Builder(MsgWarnUsb, 0x78563412u).Bytes(TagKeyword, bytes300.data(), bytes300.size()).Build());
        CHECK_EQ(HexOf(packet300), kUsbHeader + "0AAC02" + Repeat("78", 300));

        // The lengths of the two byte case, read the way the server does.
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet300, items));
        REQUIRE_EQ(items.size(), 1u);
        CHECK(items[0].tag == TagKeyword);
        CHECK_EQ(items[0].value, bytes300);
    }

    TEST_CASE("EncodeLeb128: known values") {
        CHECK_EQ(HexOf(EncodeLeb128(0)), std::string("00"));
        CHECK_EQ(HexOf(EncodeLeb128(1)), std::string("01"));
        CHECK_EQ(HexOf(EncodeLeb128(127)), std::string("7F"));
        CHECK_EQ(HexOf(EncodeLeb128(128)), std::string("8001"));
        CHECK_EQ(HexOf(EncodeLeb128(255)), std::string("FF01"));
        CHECK_EQ(HexOf(EncodeLeb128(300)), std::string("AC02"));
        CHECK_EQ(HexOf(EncodeLeb128(16383)), std::string("FF7F"));
        CHECK_EQ(HexOf(EncodeLeb128(16384)), std::string("808001"));
        CHECK_EQ(HexOf(EncodeLeb128(2097151)), std::string("FFFF7F"));
        CHECK_EQ(HexOf(EncodeLeb128(2097152)), std::string("80808001"));
        CHECK_EQ(HexOf(EncodeLeb128(0xFFFFFFFFu)), std::string("FFFFFFFF0F"));
        // The largest 64-bit value needs 10 bytes. The server rejects LEB128 fields
        // of more than 9 bytes, so it must never be used as a TLV length.
        const auto largest = EncodeLeb128(UINT64_MAX);
        REQUIRE_EQ(largest.size(), 10u);
        CHECK_EQ(HexOf(largest), std::string("FFFFFFFFFFFFFFFFFF01"));
    }

    TEST_CASE("EncodeLeb128 agrees with cpl::codec::Leb128 below 2^63") {
        std::vector<uint64_t> values{};
        for (uint64_t v = 0; v < 700; v++) {
            values.push_back(v);
        }
        for (unsigned bit = 0; bit < 63; bit++) {
            const uint64_t power = 1ull << bit;
            values.push_back(power - 1);
            values.push_back(power);
            values.push_back(power + 1);
        }
        uint64_t state = 0x0123456789abcdefull;
        for (size_t i = 0; i < 3000; i++) {
            state = state * 6364136223846793005ull + 1442695040888963407ull;
            values.push_back(state >> 1);
        }
        for (size_t i = 0; i < values.size(); i++) {
            const auto reference = Must(cpl::codec::Leb128::Encode(static_cast<int64_t>(values[i])));
            CHECK_EQ(EncodeLeb128(values[i]), reference);
        }
    }

    TEST_CASE("Adapter writes the items in wire order and omits the absent ones") {
        const auto packet = Must(
            Builder(MsgIllegalAdapter, 0x78563412u).Adapter(FullAdapter()).Adapter(MakeAdapter(7, 0)).Build());
        CHECK_EQ(HexOf(packet), kAdapterHeader + kFullAdapter + "010465746830" "100107" "110100");

        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        const Tag expected[] = {
            TagAdapterName, TagDescription, TagMac, TagIfIndex, TagIPv4, TagIPv4Mask,
            TagIPv4Gateway, TagAdapterScore, TagDhcpEnabled, // first snapshot
            TagAdapterName, TagAdapterScore, TagDhcpEnabled, // second snapshot: name only
        };
        REQUIRE_EQ(items.size(), 12u);
        for (size_t i = 0; i < items.size(); i++) {
            CHECK(items[i].tag == expected[i]);
        }
        // The values of the first snapshot.
        CHECK_EQ(Text(items[0]), std::string("eth0"));
        CHECK_EQ(Text(items[1]), std::string("NIC"));
        CHECK_EQ(HexOf(items[2].value), std::string("AABBCCDDEEFF"));
        CHECK_EQ(HexOf(items[3].value), std::string("02000000"));
        CHECK_EQ(HexOf(items[4].value), std::string("C0A80101"));
        CHECK_EQ(HexOf(items[5].value), std::string("FFFFFF00"));
        CHECK_EQ(HexOf(items[6].value), std::string("C0A801FE"));
        CHECK_EQ(items[7].value, Stream(1, static_cast<uint8_t>(90)));
        CHECK_EQ(items[8].value, Stream(1, static_cast<uint8_t>(1)));
        // The second group starts with its name.
        CHECK_EQ(Text(items[9]), std::string("eth0"));
        CHECK_EQ(items[10].value, Stream(1, static_cast<uint8_t>(7)));
    }

    TEST_CASE("Adapter writes the name even when it is empty") {
        const auto packet = Must(Builder(MsgIllegalAdapter, 0x78563412u).Adapter(AdapterSnapshot()).Build());
        CHECK_EQ(HexOf(packet), kAdapterHeader + "0100" "100100" "110100");
    }

    TEST_CASE("IPv4 items carry the octets in text order, as the server reads them") {
        // The version 3 server copies the four bytes of an address item into a net.IP
        // and prints them. The version 2 producers wrote a little-endian uint32 with
        // the first octet as the most significant byte, which is the reversed order:
        // 192.168.1.1 would be 01 01 A8 C0.
        AdapterSnapshot snapshot{};
        snapshot.name = "eth0";
        snapshot.ipv4 = Ipv4Address{{192, 168, 1, 1}};
        snapshot.ipv4Mask = Ipv4Address{{255, 255, 255, 0}};
        snapshot.ipv4Gateway = Ipv4Address{{10, 136, 90, 1}};
        const auto packet = Must(Builder(MsgIllegalAdapter, 0x78563412u).Adapter(snapshot).Build());
        CHECK_EQ(HexOf(packet), kAdapterHeader + "010465746830"
                                "0404C0A80101" "0504FFFFFF00" "06040A885A01" "100100" "110100");
        CHECK(HexOf(packet).find("0101A8C0") == std::string::npos);

        // The default route gateway of an IPv4 alert goes through the same helper.
        const Ipv4Address gateway = {{10, 136, 90, 1}};
        const auto warning = Must(BuildWarning(
            MsgOutboundV4, 0x78563412u, "", std::vector<AdapterSnapshot>(), IdOf(kIdA), &gateway));
        CHECK_EQ(HexOf(warning), kV4Header + "06040A885A01" + kEventIdA);
    }

    TEST_CASE("Adapter ignores the mac and the addresses that are marked as absent") {
        AdapterSnapshot snapshot = MakeAdapter(1, 0);
        snapshot.mac = MacAddress{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}}; // hasMac stays false
        snapshot.ipv4 = Ipv4Address{{0, 0, 0, 0}};
        snapshot.ipv4Mask = Ipv4Address{{0, 0, 0, 0}};
        snapshot.ipv4Gateway = Ipv4Address{{0, 0, 0, 0}};
        const auto packet = Must(Builder(MsgIllegalAdapter, 0x78563412u).Adapter(snapshot).Build());
        CHECK_EQ(HexOf(packet), kAdapterHeader + "010465746830" "100101" "110100");
    }

    TEST_CASE("Adapter matches the adapter evidence of the reference sender") {
        AdapterSnapshot snapshot{};
        snapshot.name = "{4D66E890-F32A-11EC-B7A0-3E22FB8812A7}";
        snapshot.description = "USB Wireless 802.11 NIC";
        snapshot.mac = MacAddress{{0xA8, 0x6D, 0xAA, 0x12, 0x34, 0x56}};
        snapshot.hasMac = true;
        snapshot.ifIndex = 14;
        snapshot.ipv4 = Ipv4Address{{10, 136, 90, 55}};
        snapshot.ipv4Mask = Ipv4Address{{255, 255, 255, 0}};
        const auto packet = Must(Builder(MsgIllegalAdapter, 0x78563412u).Adapter(snapshot).Build());
        // The reference sender writes the same items, without score and dhcp.
        CHECK_EQ(HexOf(packet), kAdapterHeader + kReferenceEvidence + "100100" "110100");
    }

    TEST_CASE("Usb writes a complete group that starts with the vid and ends with the event id") {
        const auto packet = Must(Builder(MsgWarnUsb, 0x78563412u).Usb(FullDevice()).Build());
        CHECK_EQ(HexOf(packet), kUsbHeader + kFullDevice + kEventIdA);

        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        const Tag expected[] = {
            TagUsbVid, TagUsbPid, TagUsbSerial, TagDescription, TagUsbClassName, TagKeyword, TagEventId,
        };
        REQUIRE_EQ(items.size(), 7u);
        for (size_t i = 0; i < items.size(); i++) {
            CHECK(items[i].tag == expected[i]);
        }
        CHECK_EQ(HexOf(items[0].value), std::string("A00E"));
        CHECK_EQ(HexOf(items[1].value), std::string("0173"));
        CHECK_EQ(Text(items[2]), std::string("SR001"));
        CHECK_EQ(Text(items[3]), std::string("USB Cable"));
        CHECK_EQ(Text(items[4]), std::string("USB\\Class_ff"));
        CHECK_EQ(Text(items[5]), std::string("VID_0EA0&PID_7301"));
        CHECK_EQ(HexOf(items[6].value), std::string(kIdA));
    }

    TEST_CASE("Usb omits the empty text items but keeps the serial and the event id") {
        const auto packet = Must(Builder(MsgWarnUsb, 0x78563412u).Usb(UsbDevice()).Build());
        CHECK_EQ(HexOf(packet), kUsbHeader + "0C020000" "0D020000" "0B00" "1B0C" + Repeat("00", 12));

        UsbDevice device = MakeDevice(0x1234, 0);
        device.pid = 0x5678;
        device.serial = "SR004";
        device.eventId = IdOf(kIdB);
        const auto text = Must(Builder(MsgWarnUsb, 0x78563412u).Usb(device).Build());
        CHECK_EQ(HexOf(text), kUsbHeader + "0C023412" "0D027856" "0B055352303034" "1B0C" + kIdB);
    }

    TEST_CASE("BuildUsbReport: evidence, then one group per device") {
        AdapterSnapshot evidence = MakeAdapter(60, 0);
        evidence.dhcpEnabled = 1;
        UsbDevice second{};
        second.vid = 0x0488;
        second.pid = 0x572B;
        second.serial = "SR002";
        second.description = "Hub";
        second.eventId = IdOf(kIdB);
        const std::vector<UsbDevice> devices = {FullDevice(), second};

        const auto packet = Must(BuildUsbReport(0x78563412u, devices, &evidence));
        CHECK_EQ(HexOf(packet), kUsbHeader
                                + "010465746830" "10013C" "110101" // evidence
                                + kFullDevice + kEventIdA // first device
                                + "0C028804" "0D022B57" "0B055352303032" "0203487562" + "1B0C" + kIdB);

        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        const Tag expected[] = {
            TagAdapterName, TagAdapterScore, TagDhcpEnabled, // evidence
            TagUsbVid, TagUsbPid, TagUsbSerial, TagDescription, TagUsbClassName, TagKeyword, TagEventId,
            TagUsbVid, TagUsbPid, TagUsbSerial, TagDescription, TagEventId,
        };
        REQUIRE_EQ(items.size(), 15u);
        for (size_t i = 0; i < items.size(); i++) {
            CHECK(items[i].tag == expected[i]);
        }
        // Two devices: two vid tags and two event id tags.
        CHECK_EQ(Count(items, TagUsbVid), 2u);
        CHECK_EQ(Count(items, TagEventId), 2u);
        CHECK_EQ(Count(items, TagTruncated), 0u);
        // The evidence comes before the first device; the report ends with the event
        // id of the last device.
        CHECK(items[0].tag == TagAdapterName);
        CHECK(items[3].tag == TagUsbVid);
        CHECK_EQ(HexOf(items[9].value), std::string(kIdA));
        CHECK_EQ(HexOf(items[14].value), std::string(kIdB));
    }

    TEST_CASE("BuildUsbReport without an adapter evidence sends only the device groups") {
        const std::vector<UsbDevice> devices = {MakeDevice(1, 0), MakeDevice(2, 0)};
        const auto packet = Must(BuildUsbReport(0x78563412u, devices));
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        CHECK(items[0].tag == TagUsbVid);
        CHECK_EQ(Count(items, TagUsbVid), 2u);
        CHECK_EQ(Count(items, TagAdapterName), 0u);
        CHECK_EQ(Count(items, TagTruncated), 0u);

        // Without devices either, the report holds the evidence only.
        const AdapterSnapshot evidence = MakeAdapter(0, 0);
        const auto empty = Must(BuildUsbReport(0x78563412u, std::vector<UsbDevice>(), &evidence));
        CHECK_EQ(HexOf(empty), kUsbHeader + kMinimalAdapter);
    }

    TEST_CASE("BuildWarning: keyword, adapters, IPv4 gateway, event id") {
        const std::vector<AdapterSnapshot> adapters = {FullAdapter()};
        const Ipv4Address gateway = {{10, 136, 90, 1}};
        const auto packet = Must(BuildWarning(
            MsgOutboundV4, 0x78563412u, "0.0.0.0/0", adapters, IdOf(kIdA), &gateway));
        CHECK_EQ(HexOf(packet), kV4Header
                                + "0A09302E302E302E302F30" // keyword "0.0.0.0/0"
                                + kFullAdapter
                                + "06040A885A01" // gateway 10.136.90.1
                                + kEventIdA);
    }

    TEST_CASE("BuildWarning: IPv6 gateway without adapters") {
        const Ipv6Address gateway = ArrayOf<16>(kGateway6);
        const auto packet = Must(BuildWarning(
            MsgOutboundV6, 0x78563412u, "::/0", std::vector<AdapterSnapshot>(), IdOf(kIdA), nullptr, &gateway));
        CHECK_EQ(HexOf(packet), kV6Header
                                + "0A043A3A2F30" // keyword "::/0"
                                + "0810" + kGateway6
                                + kEventIdA);
    }

    TEST_CASE("BuildWarning without keyword and gateways sends adapters and event id only") {
        const std::vector<AdapterSnapshot> adapters = {FullAdapter(), MakeAdapter(7, 0)};
        const auto packet = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdB)));
        CHECK_EQ(HexOf(packet), kAdapterHeader + kFullAdapter + "010465746830" "100107" "110100" + "1B0C" + kIdB);
    }

    TEST_CASE("BuildWarning rejects a message type that is not an adapter or route alert") {
        const std::vector<AdapterSnapshot> adapters = {FullAdapter()};
        const auto usb = BuildWarning(MsgWarnUsb, 0, "", adapters, IdOf(kIdA));
        REQUIRE_FALSE(usb.has_value());
        CHECK_EQ(usb.error().Code.i64, static_cast<int64_t>(cpl::Error::InvalidArgument));
        const auto unknown = BuildWarning(static_cast<MsgType>(9), 0, "", adapters, IdOf(kIdA));
        REQUIRE_FALSE(unknown.has_value());
        CHECK_EQ(unknown.error().Code.i64, static_cast<int64_t>(cpl::Error::InvalidArgument));
    }

    TEST_CASE("truncation: adapters stop before the threshold and the dropped ones are counted") {
        // A snapshot of MakeAdapter() takes 12 bytes on the wire.
        std::vector<AdapterSnapshot> adapters{};
        for (uint16_t i = 0; i < 60; i++) {
            adapters.push_back(MakeAdapter(i, 0));
        }
        const auto packet = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA)));

        // The rule appends a snapshot while size + 120 <= 800. After 56 snapshots the
        // packet has 7 + 56 * 12 = 679 bytes and 679 + 120 = 799 passes. After the
        // 57th it has 691 bytes and 691 + 120 = 811 does not pass. So 3 are dropped.
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        REQUIRE_EQ(Count(items, TagAdapterName), 57u);
        REQUIRE_EQ(Count(items, TagTruncated), 1u);
        const Item *truncated = FindLast(items, TagTruncated);
        REQUIRE(truncated != nullptr);
        CHECK_EQ(truncated->value, Stream(1, static_cast<uint8_t>(3)));
        // 691 bytes + the truncated tag (3) + the event id (14).
        CHECK_EQ(packet.size(), 708u);

        // The first 57 snapshots are kept, in their order: the score is the index.
        std::vector<uint8_t> scores{};
        for (size_t i = 0; i < items.size(); i++) {
            if (items[i].tag == TagAdapterScore) {
                REQUIRE_EQ(items[i].value.size(), 1u);
                scores.push_back(items[i].value[0]);
            }
        }
        REQUIRE_EQ(scores.size(), 57u);
        for (size_t i = 0; i < scores.size(); i++) {
            CHECK_EQ(scores[i], static_cast<uint8_t>(i));
        }
        // The event id is still the last item.
        CHECK_EQ(HexOf(items[items.size() - 1].value), std::string(kIdA));
    }

    TEST_CASE("truncation: tag 15 is absent when the adapters fit") {
        std::vector<AdapterSnapshot> adapters{};
        for (uint16_t i = 0; i < 57; i++) {
            adapters.push_back(MakeAdapter(i, 0));
        }
        const auto packet = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA)));
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        CHECK_EQ(Count(items, TagAdapterName), 57u);
        CHECK_EQ(Count(items, TagTruncated), 0u);
        // 691 bytes + the event id (14).
        CHECK_EQ(packet.size(), 705u);

        // One more snapshot is the first dropped one.
        adapters.push_back(MakeAdapter(57, 0));
        const auto dropped = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA)));
        REQUIRE(ReadItems(dropped, items));
        CHECK_EQ(Count(items, TagAdapterName), 57u);
        CHECK_EQ(Count(items, TagTruncated), 1u);
        CHECK_EQ(dropped.size(), 708u);
    }

    TEST_CASE("truncation: the dropped count stops at 255") {
        std::vector<AdapterSnapshot> adapters{};
        for (size_t i = 0; i < 357; i++) {
            adapters.push_back(MakeAdapter(static_cast<uint16_t>(i), 0));
        }
        const auto packet = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA)));
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        CHECK_EQ(Count(items, TagAdapterName), 57u);
        // 357 - 57 = 300 snapshots are dropped; the tag holds 255.
        const Item *truncated = FindLast(items, TagTruncated);
        REQUIRE(truncated != nullptr);
        CHECK_EQ(truncated->value, Stream(1, static_cast<uint8_t>(255)));
        CHECK_EQ(packet.size(), 708u);
    }

    TEST_CASE("truncation: a snapshot that would overflow the packet is dropped") {
        // One snapshot with a description of 116 bytes takes 130 bytes on the wire,
        // more than the 120 bytes of the rule.
        std::vector<AdapterSnapshot> adapters(6, MakeAdapter(0, 116));
        const Ipv6Address gateway = ArrayOf<16>(kGateway6);

        // By hand, the six snapshots leave no room for the items that follow them:
        // 7 + 6 * 130 = 787, plus the gateway (18), the truncated tag (3) and the
        // event id (14) makes 822, which is above the budget.
        Builder manual(MsgOutboundV6, 0x78563412u);
        for (size_t i = 0; i < adapters.size(); i++) {
            manual.Adapter(adapters[i]);
        }
        REQUIRE_EQ(manual.Size(), 787u);

        // After five snapshots the packet has 657 bytes and 657 + 120 = 777 <= 800,
        // so the rule alone would append the sixth one.
        const auto packet = Must(BuildWarning(
            MsgOutboundV6, 0x78563412u, "", adapters, IdOf(kIdA), nullptr, &gateway));
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        CHECK_EQ(Count(items, TagAdapterName), 5u);
        CHECK_EQ(Count(items, TagTruncated), 1u);
        // 657 bytes + the gateway (18) + the truncated tag (3) + the event id (14).
        CHECK_EQ(packet.size(), 692u);

        // Without the gateway the six snapshots fit, and nothing is dropped.
        const auto all = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA)));
        REQUIRE(ReadItems(all, items));
        CHECK_EQ(Count(items, TagAdapterName), 6u);
        CHECK_EQ(Count(items, TagTruncated), 0u);
        CHECK_EQ(all.size(), 801u);
    }

    TEST_CASE("truncation of a USB report: devices stop before the threshold and are counted") {
        // A device group of MakeDevice() takes 24 bytes on the wire.
        std::vector<UsbDevice> devices{};
        for (uint16_t i = 0; i < 33; i++) {
            devices.push_back(MakeDevice(i, 0));
        }
        const AdapterSnapshot evidence = MakeAdapter(0, 0);
        const auto packet = Must(BuildUsbReport(0x78563412u, devices, &evidence));

        // The rule appends a group while size + 80 <= 800. With the evidence the
        // packet starts with 7 + 12 = 19 bytes. After 29 groups it has 19 + 29 * 24 =
        // 715 bytes and 715 + 80 = 795 passes. After the 30th it has 739 bytes and
        // 739 + 80 = 819 does not pass. So 3 are dropped.
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        REQUIRE_EQ(Count(items, TagUsbVid), 30u);
        REQUIRE_EQ(Count(items, TagEventId), 30u);
        REQUIRE_EQ(Count(items, TagTruncated), 1u);
        const Item *truncated = FindLast(items, TagTruncated);
        REQUIRE(truncated != nullptr);
        CHECK_EQ(truncated->value, Stream(1, static_cast<uint8_t>(3)));
        // 739 bytes + the truncated tag (3).
        CHECK_EQ(packet.size(), 742u);

        // The first 30 devices are kept, in their order: the vid is the index.
        std::vector<uint16_t> vids{};
        for (size_t i = 0; i < items.size(); i++) {
            if (items[i].tag == TagUsbVid) {
                REQUIRE_EQ(items[i].value.size(), 2u);
                vids.push_back(static_cast<uint16_t>(items[i].value[0] | (items[i].value[1] << 8)));
            }
        }
        REQUIRE_EQ(vids.size(), 30u);
        for (size_t i = 0; i < vids.size(); i++) {
            CHECK_EQ(vids[i], static_cast<uint16_t>(i));
        }

        // Without the last three devices nothing is dropped.
        devices.resize(30);
        const auto all = Must(BuildUsbReport(0x78563412u, devices, &evidence));
        REQUIRE(ReadItems(all, items));
        CHECK_EQ(Count(items, TagUsbVid), 30u);
        CHECK_EQ(Count(items, TagTruncated), 0u);
        CHECK_EQ(all.size(), 739u);
    }

    TEST_CASE("truncation of a USB report: the dropped count stops at 255") {
        std::vector<UsbDevice> devices{};
        for (size_t i = 0; i < 330; i++) {
            devices.push_back(MakeDevice(static_cast<uint16_t>(i), 0));
        }
        const AdapterSnapshot evidence = MakeAdapter(0, 0);
        const auto packet = Must(BuildUsbReport(0x78563412u, devices, &evidence));
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        CHECK_EQ(Count(items, TagUsbVid), 30u);
        // 330 - 30 = 300 devices are dropped; the tag holds 255.
        const Item *truncated = FindLast(items, TagTruncated);
        REQUIRE(truncated != nullptr);
        CHECK_EQ(truncated->value, Stream(1, static_cast<uint8_t>(255)));
        CHECK_EQ(packet.size(), 742u);
    }

    TEST_CASE("truncation of a USB report: a group that would overflow the packet is dropped") {
        // A group with a description of 74 bytes takes 100 bytes on the wire, more
        // than the 80 bytes of the rule.
        std::vector<UsbDevice> devices(8, MakeDevice(0, 74));
        const AdapterSnapshot evidence = MakeAdapter(0, 0);

        // By hand, the eight groups make 19 + 8 * 100 = 819 bytes; with the
        // truncated tag that is 822, which is above the budget.
        Builder manual(MsgWarnUsb, 0x78563412u);
        manual.Adapter(evidence);
        for (size_t i = 0; i < devices.size(); i++) {
            manual.Usb(devices[i]);
        }
        REQUIRE_EQ(manual.Size(), 819u);

        // After seven groups the packet has 719 bytes and 719 + 80 = 799 <= 800, so
        // the rule alone would append the eighth one.
        const auto packet = Must(BuildUsbReport(0x78563412u, devices, &evidence));
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        CHECK_EQ(Count(items, TagUsbVid), 7u);
        CHECK_EQ(Count(items, TagEventId), 7u);
        CHECK_EQ(Count(items, TagTruncated), 1u);
        // 719 bytes + the truncated tag (3).
        CHECK_EQ(packet.size(), 722u);
    }

    TEST_CASE("Build fails with OutOfRange when more than 820 bytes were appended by hand") {
        const Stream value(810, 0x41);
        Builder builder(MsgWarnUsb, 0x78563412u);
        builder.Bytes(TagForensicRef, value.data(), value.size());
        // 7 bytes of header + tag (1) + length (2) + 810 = 820: the limit itself passes.
        REQUIRE_EQ(builder.Size(), kMaxPacketBytes);
        CHECK(builder.Build().has_value());

        const auto tooLarge = builder.U8(TagTruncated, 1).Build();
        REQUIRE_EQ(builder.Size(), 823u);
        REQUIRE_FALSE(tooLarge.has_value());
        CHECK_EQ(tooLarge.error().Code.i64, static_cast<int64_t>(cpl::Error::OutOfRange));
    }

    TEST_CASE("Remaining is the distance to the threshold and never negative") {
        Builder builder(MsgIllegalAdapter, 0x78563412u);
        REQUIRE_EQ(builder.Remaining(), 793u);
        const Stream value(790, 0x41);
        builder.Bytes(TagForensicRef, value.data(), value.size());
        // 7 + tag (1) + length (2) + 790 = 800.
        REQUIRE_EQ(builder.Size(), kTruncateThreshold);
        CHECK_EQ(builder.Remaining(), 0u);
        builder.U8(TagTruncated, 1);
        CHECK_EQ(builder.Remaining(), 0u);

        // A manual loop applies the rule of report.go with Remaining().
        Builder loop(MsgIllegalAdapter, 0x78563412u);
        size_t appended = 0;
        while (appended < 100 && loop.Remaining() >= kAdapterEstimateBytes) {
            loop.Adapter(MakeAdapter(static_cast<uint16_t>(appended), 0));
            appended++;
        }
        CHECK_EQ(appended, 57u);
    }

    TEST_CASE("EncodedSize is the number of bytes that Adapter and Usb append") {
        const AdapterSnapshot snapshots[] = {
            AdapterSnapshot(), FullAdapter(), MakeAdapter(3, 116), MakeAdapter(4, 200), MakeAdapter(5, 700),
        };
        for (size_t i = 0; i < 5; i++) {
            Builder builder(MsgWarnUsb, 0x78563412u);
            const size_t before = builder.Size();
            builder.Adapter(snapshots[i]);
            CHECK_EQ(builder.Size() - before, cpl::warnwire::impl::EncodedSize(snapshots[i]));
        }
        const UsbDevice devices[] = {UsbDevice(), FullDevice(), MakeDevice(1, 74), MakeDevice(2, 300)};
        for (size_t i = 0; i < 4; i++) {
            Builder builder(MsgWarnUsb, 0x78563412u);
            const size_t before = builder.Size();
            builder.Usb(devices[i]);
            CHECK_EQ(builder.Size() - before, cpl::warnwire::impl::EncodedSize(devices[i]));
        }
        // The sizes the truncation tests rely on.
        CHECK_EQ(cpl::warnwire::impl::EncodedSize(MakeAdapter(0, 0)), 12u);
        CHECK_EQ(cpl::warnwire::impl::EncodedSize(MakeAdapter(0, 116)), 130u);
        CHECK_EQ(cpl::warnwire::impl::EncodedSize(MakeDevice(0, 0)), 24u);
        CHECK_EQ(cpl::warnwire::impl::EncodedSize(MakeDevice(0, 74)), 100u);
    }

    TEST_CASE("MakeObjectId copies 12 bytes and rejects other sizes") {
        const auto id = Must(MakeObjectId(Unhex(kIdA)));
        CHECK(id.bytes == ArrayOf<12>(kIdA));
        const auto pointer = Must(MakeObjectId(id.bytes.data(), id.bytes.size()));
        CHECK(pointer.bytes == id.bytes);
        const auto tooShort = MakeObjectId(Unhex("0102"));
        REQUIRE_FALSE(tooShort.has_value());
        CHECK_EQ(tooShort.error().Code.i64, static_cast<int64_t>(cpl::Error::OutOfRange));
        CHECK_FALSE(MakeObjectId(nullptr, 12).has_value());
    }
    TEST_CASE("forensicRef and droppedGroups: the reference is sent before the truncated tag") {
        // The same 60 snapshots as the truncation test above: 3 of them do not fit.
        std::vector<AdapterSnapshot> adapters{};
        for (uint16_t i = 0; i < 60; i++) {
            adapters.push_back(MakeAdapter(i, 0));
        }
        size_t dropped = 0;
        const auto plain = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA),
                                             nullptr, nullptr, "", &dropped));
        CHECK_EQ(dropped, 3u);
        CHECK_EQ(plain.size(), 708u);

        // "a.json" takes 8 bytes on the wire. The snapshots that fit are the same, and the
        // packet grows by the reference.
        const auto withReference = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA),
                                                     nullptr, nullptr, "a.json", &dropped));
        CHECK_EQ(dropped, 3u);
        CHECK_EQ(withReference.size(), 716u);
        std::vector<Item> items{};
        REQUIRE(ReadItems(withReference, items));
        REQUIRE_EQ(Count(items, TagForensicRef), 1u);
        const Item *reference = FindLast(items, TagForensicRef);
        REQUIRE(reference != nullptr);
        CHECK_EQ(std::string(reference->value.begin(), reference->value.end()), std::string("a.json"));
        // The reference comes before the truncated tag, and the event id is the last item.
        REQUIRE_EQ(items.size(), 57u * 3 + 3);
        CHECK(items[items.size() - 3].tag == TagForensicRef);
        CHECK(items[items.size() - 2].tag == TagTruncated);
        CHECK(items[items.size() - 1].tag == TagEventId);

        // The reference is left out when it is empty.
        const auto without = Must(BuildWarning(MsgIllegalAdapter, 0x78563412u, "", adapters, IdOf(kIdA)));
        items.clear();
        REQUIRE(ReadItems(without, items));
        CHECK_EQ(Count(items, TagForensicRef), 0u);
    }

    TEST_CASE("BuildUsbReport: the forensic reference and the dropped count are reported") {
        const std::vector<UsbDevice> devices = {MakeDevice(1, 0), MakeDevice(2, 0)};
        size_t dropped = 99;
        const auto packet = Must(BuildUsbReport(0x78563412u, devices, nullptr, "usb.json", &dropped));
        CHECK_EQ(dropped, 0u);
        std::vector<Item> items{};
        REQUIRE(ReadItems(packet, items));
        REQUIRE_EQ(Count(items, TagForensicRef), 1u);
        const Item *reference = FindLast(items, TagForensicRef);
        REQUIRE(reference != nullptr);
        CHECK_EQ(std::string(reference->value.begin(), reference->value.end()), std::string("usb.json"));
        CHECK_EQ(Count(items, TagUsbVid), 2u);
        CHECK_EQ(Count(items, TagTruncated), 0u);
    }
}
