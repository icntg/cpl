// warnwire.hpp - builder of the alert packets of protocol "warnwire version 3".
//
// A terminal reports a violation (illegal network adapter name, illegal IPv4 default
// route, IPv6 default route, illegal USB device) to the server over UDP. This header
// builds the plaintext packet. The caller encrypts it with naion CSM and sends it.
// The server parses the packet with server/service/index/warnwire.go and udp.go;
// those files are the authority for the wire format.
//
// Packet layout, all integers little-endian:
//
//   protocolVersion  uint16   kProtocolVersion
//   timestamp        uint32   Unix seconds
//   msgType          uint8    MsgType
//   TLV stream                tag (1 byte) + length (unsigned LEB128) + value
//
// The packet, header included, must not exceed kMaxPacketBytes.
//
// The server groups the flat stream by position, so the order of the items matters:
//
//   BuildWarning     keyword, adapter snapshots, IPv4 or IPv6 gateway, truncated,
//                    event id
//   BuildUsbReport   one adapter snapshot as evidence, one group per USB device
//                    (usbVid, usbPid, usbSerial, description, usbClassName, keyword,
//                    eventId), truncated
//
// Differences from the Go builder (client/ifw/client/linux/go/warnwire.go, report.go,
// adapter_snapshot.go), which still builds version 2 packets:
//
//   - The header has 7 bytes instead of 23: appVersion and configVersion are gone.
//   - An IPv4 address is written with its octets in text order, the first octet
//     first. The Go builder writes a little-endian uint32; the version 3 server reads
//     those bytes back as a reversed address.
//   - A USB report carries the adapter snapshot before the USB device groups. After
//     the first usbVid tag the server attaches every description to the last USB
//     device, so the order of the Go builder, devices first, would mix them up.
//   - A USB device group carries the serial number and its own event id (tag 27).
//   - USB devices that do not fit are counted in the truncated tag. The Go builder
//     drops them without counting them.

#ifndef CPL_WARNWIRE_HPP_GRANITE_LANTERN_HARBOR_THIRSTLE_QUIET_EMBER_VELOCITY
#define CPL_WARNWIRE_HPP_GRANITE_LANTERN_HARBOR_THIRSTLE_QUIET_EMBER_VELOCITY

#include "base.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace cpl {
    namespace warnwire {
        // kProtocolVersion is the first field of every packet.
        constexpr uint16_t kProtocolVersion = 3;

        // kHeaderBytes is the size of the fixed header.
        constexpr size_t kHeaderBytes = 7;

        // kMaxPacketBytes is the budget of one packet, header included.
        constexpr size_t kMaxPacketBytes = 820;

        // kTruncateThreshold is the packet size at which BuildWarning and
        // BuildUsbReport stop appending groups. The rest of the budget is left to the
        // items that follow the groups.
        constexpr size_t kTruncateThreshold = 800;

        // Wire size that the truncation rule assumes for one group. The values are the
        // ones of report.go.
        constexpr size_t kAdapterEstimateBytes = 120;
        constexpr size_t kUsbEstimateBytes = 80;

        // MsgType is the last byte of the header.
        enum MsgType : uint8_t {
            MsgIllegalAdapter = 0, // illegal network adapter name
            MsgOutboundV4 = 1, // illegal IPv4 default route
            MsgOutboundV6 = 2, // IPv6 default route
            MsgWarnUsb = 3, // illegal USB device
        };

        // Tag identifies a TLV item. Extend only; never renumber an existing value.
        enum Tag : uint8_t {
            TagAdapterName = 1, // UTF-8, starts an adapter group
            TagDescription = 2, // UTF-8, description of an adapter or of a USB device
            TagMac = 3, // 6 bytes
            TagIPv4 = 4, // 4 bytes: the octets of the address in text order
            TagIPv4Mask = 5, // 4 bytes: the octets of the mask in text order
            TagIPv4Gateway = 6, // 4 bytes: the octets of the gateway in text order
            TagIPv6 = 7, // 16 bytes; the server does not parse it
            TagIPv6Gateway = 8, // 16 bytes
            TagIfIndex = 9, // uint32 little-endian
            TagKeyword = 10, // UTF-8, the keyword that matched
            TagUsbSerial = 11, // UTF-8
            TagUsbVid = 12, // uint16 little-endian, starts a USB device group
            TagUsbPid = 13, // uint16 little-endian
            TagNetworkLocation = 14, // uint8: 0 external, 1 intranet
            TagTruncated = 15, // uint8: number of groups that were dropped
            TagAdapterScore = 16, // uint8
            TagDhcpEnabled = 17, // uint8; the server does not parse it
            TagUsbClassName = 18, // UTF-8
            TagForensicRef = 19, // UTF-8
            TagEventId = 27, // 12 bytes: id of the packet or of the USB device
        };

        using MacAddress = std::array<uint8_t, 6>;

        // The four octets of an IPv4 address in text order: the first octet has the
        // index 0. These are the bytes of struct in_addr, and what
        // cpl::net::ipv4::IPStringToArray() returns for an address in text.
        using Ipv4Address = std::array<uint8_t, 4>;
        using Ipv6Address = std::array<uint8_t, 16>;

        // ObjectId is a 12-byte event id. cpl::identity::ObjectId::Generate() returns
        // these bytes; MakeObjectId() copies them into this type.
        struct ObjectId {
            std::array<uint8_t, 12> bytes{};
        };

        // AdapterSnapshot is one network adapter, attached to an alert as evidence.
        // The violating adapter comes first. The three IPv4 fields hold their octets
        // in text order, see Ipv4Address.
        struct AdapterSnapshot {
            std::string name{}; // always sent, starts the adapter group
            std::string description{}; // sent when not empty
            MacAddress mac{}; // sent when hasMac is set
            bool hasMac{false};
            uint32_t ifIndex{0}; // sent when not 0
            Ipv4Address ipv4{}; // sent when not all zero
            Ipv4Address ipv4Mask{}; // sent when not all zero
            Ipv4Address ipv4Gateway{}; // gateway of the adapter, sent when not all zero;
                                       // leave it zero in MsgOutboundV4 alerts
            uint8_t score{0}; // always sent
            uint8_t dhcpEnabled{0}; // always sent, 0 or 1
        };

        // UsbDevice is one illegal USB device: one group of a USB report.
        struct UsbDevice {
            uint16_t vid{0}; // always sent, starts the group
            uint16_t pid{0}; // always sent
            std::string serial{}; // always sent, also when empty
            std::string description{}; // sent when not empty
            std::string className{}; // sent when not empty
            std::string hitKeyword{}; // sent when not empty
            ObjectId eventId{}; // always sent, ends the group
        };

        namespace impl {
            // Wire size of the items that follow the groups of a packet.
            constexpr size_t kTruncatedItemBytes = 3; // tag + length + 1 byte
            constexpr size_t kEventIdItemBytes = 14; // tag + length + 12 bytes
            constexpr size_t kIpv4ItemBytes = 6; // tag + length + 4 bytes
            constexpr size_t kIpv6ItemBytes = 18; // tag + length + 16 bytes

            // The truncated tag counts groups in one byte.
            constexpr size_t kMaxDroppedCount = 255;

            // Appends an unsigned integer as LEB128: 7 bits per byte, low bits first,
            // bit 7 set on every byte but the last. Same bytes as encodeLEB128 in Go.
            inline void AppendLeb128(Stream &out, const uint64_t value) {
                uint64_t rest = value;
                while (true) {
                    uint8_t byte = static_cast<uint8_t>(rest & 0x7fu);
                    rest >>= 7u;
                    if (rest != 0u) {
                        byte = static_cast<uint8_t>(byte | 0x80u);
                    }
                    out.push_back(byte);
                    if (rest == 0u) {
                        return;
                    }
                }
            }

            // Number of bytes that AppendLeb128() writes for a value.
            inline size_t Leb128Size(uint64_t value) {
                size_t count = 1;
                while (value >= 0x80u) {
                    value >>= 7u;
                    count++;
                }
                return count;
            }

            // Appends one TLV item. A null pointer is encoded as an empty value, so
            // that the stream stays parseable.
            inline void AppendTlv(Stream &out, const Tag tag, const void *data, const size_t size) {
                const auto *bytes = static_cast<const uint8_t *>(data);
                const size_t count = (bytes != nullptr) ? size : 0;
                out.push_back(static_cast<uint8_t>(tag));
                AppendLeb128(out, static_cast<uint64_t>(count));
                if (count > 0u) {
                    out.insert(out.end(), bytes, bytes + count);
                }
            }

            // Wire size of one TLV item whose value has `valueBytes` bytes.
            inline size_t TlvBytes(const size_t valueBytes) {
                return 1 + Leb128Size(static_cast<uint64_t>(valueBytes)) + valueBytes;
            }

            template <size_t N>
            inline bool IsZero(const std::array<uint8_t, N> &bytes) {
                for (size_t i = 0; i < N; i++) {
                    if (bytes[i] != 0u) {
                        return false;
                    }
                }
                return true;
            }

            // The four bytes of an IPv4 address item on the wire. This is the only
            // place that decides their order.
            //
            // The version 3 server copies the bytes of an address item into a net.IP
            // and prints it as dotted text (server/service/index/warnwire.go,
            // cases tagIPv4, tagIPv4Mask and tagIPv4Gateway), so the octets go out in
            // text order. The version 2 producers write a little-endian uint32 with
            // the first octet as the most significant byte, which is the reversed
            // order; the version 2 sensor reverses it back.
            inline std::array<uint8_t, 4> Ipv4WireBytes(const Ipv4Address &address) {
                std::array<uint8_t, 4> out{};
                for (size_t i = 0; i < out.size(); i++) {
                    out[i] = address[i];
                }
                return out;
            }

            // WriteAdapterItems() and WriteUsbItems() hand every item to a sink.
            // PacketSink writes the item, SizeSink only counts its bytes.
            struct PacketSink {
                Stream &out;

                void operator()(const Tag tag, const void *data, const size_t size) {
                    AppendTlv(this->out, tag, data, size);
                }
            };

            struct SizeSink {
                size_t total{0};

                void operator()(const Tag, const void *, const size_t size) {
                    this->total += TlvBytes(size);
                }
            };

            // Hands every item of one adapter snapshot to the sink, in wire order and
            // with the same "present or absent" rules as the Go builder.
            template <class Sink>
            inline void WriteAdapterItems(const AdapterSnapshot &snapshot, Sink &sink) {
                const auto putAddress = [&sink](const Tag tag, const Ipv4Address &address) {
                    const std::array<uint8_t, 4> bytes = Ipv4WireBytes(address);
                    sink(tag, bytes.data(), bytes.size());
                };
                sink(TagAdapterName, snapshot.name.data(), snapshot.name.size());
                if (!snapshot.description.empty()) {
                    sink(TagDescription, snapshot.description.data(), snapshot.description.size());
                }
                if (snapshot.hasMac) {
                    sink(TagMac, snapshot.mac.data(), snapshot.mac.size());
                }
                if (snapshot.ifIndex != 0u) {
                    uint8_t bytes[4]{};
                    for (size_t i = 0; i < sizeof(bytes); i++) {
                        bytes[i] = static_cast<uint8_t>((snapshot.ifIndex >> (8u * i)) & 0xffu);
                    }
                    sink(TagIfIndex, bytes, sizeof(bytes));
                }
                if (!IsZero(snapshot.ipv4)) {
                    putAddress(TagIPv4, snapshot.ipv4);
                }
                if (!IsZero(snapshot.ipv4Mask)) {
                    putAddress(TagIPv4Mask, snapshot.ipv4Mask);
                }
                if (!IsZero(snapshot.ipv4Gateway)) {
                    putAddress(TagIPv4Gateway, snapshot.ipv4Gateway);
                }
                sink(TagAdapterScore, &snapshot.score, 1);
                sink(TagDhcpEnabled, &snapshot.dhcpEnabled, 1);
            }

            // Hands every item of one USB device group to the sink, in wire order.
            template <class Sink>
            inline void WriteUsbItems(const UsbDevice &device, Sink &sink) {
                uint8_t id[2]{};
                id[0] = static_cast<uint8_t>(device.vid);
                id[1] = static_cast<uint8_t>(device.vid >> 8u);
                sink(TagUsbVid, id, sizeof(id));
                id[0] = static_cast<uint8_t>(device.pid);
                id[1] = static_cast<uint8_t>(device.pid >> 8u);
                sink(TagUsbPid, id, sizeof(id));
                sink(TagUsbSerial, device.serial.data(), device.serial.size());
                if (!device.description.empty()) {
                    sink(TagDescription, device.description.data(), device.description.size());
                }
                if (!device.className.empty()) {
                    sink(TagUsbClassName, device.className.data(), device.className.size());
                }
                if (!device.hitKeyword.empty()) {
                    sink(TagKeyword, device.hitKeyword.data(), device.hitKeyword.size());
                }
                sink(TagEventId, device.eventId.bytes.data(), device.eventId.bytes.size());
            }

            // Wire size of one group.
            inline size_t EncodedSize(const AdapterSnapshot &snapshot) {
                SizeSink sink{};
                WriteAdapterItems(snapshot, sink);
                return sink.total;
            }

            inline size_t EncodedSize(const UsbDevice &device) {
                SizeSink sink{};
                WriteUsbItems(device, sink);
                return sink.total;
            }
        }

        // Builder holds the packet that is being built: the header, followed by the
        // TLV items in the order in which they are appended. The setter methods never
        // fail and never check the budget; Build() reports an oversized packet.
        class Builder {
        public:
            explicit Builder(MsgType type, const uint32_t unixTime) {
                this->packet.reserve(kMaxPacketBytes);
                this->PutU16LE(kProtocolVersion);
                this->PutU32LE(unixTime);
                this->packet.push_back(static_cast<uint8_t>(type));
            }

            // Appends a UTF-8 text. The bytes are written as they are.
            Builder &String(const Tag tag, const std::string &value) {
                return this->Bytes(tag, value.data(), value.size());
            }

            // Appends `size` raw bytes. A null pointer is encoded as an empty value.
            Builder &Bytes(const Tag tag, const void *data, const size_t size) {
                impl::AppendTlv(this->packet, tag, data, size);
                return *this;
            }

            // Appends a one byte value.
            Builder &U8(const Tag tag, const uint8_t value) {
                return this->Bytes(tag, &value, 1);
            }

            // Appends a value as 2 bytes, little-endian.
            Builder &U16LE(const Tag tag, const uint16_t value) {
                uint8_t bytes[2]{};
                bytes[0] = static_cast<uint8_t>(value);
                bytes[1] = static_cast<uint8_t>(value >> 8u);
                return this->Bytes(tag, bytes, sizeof(bytes));
            }

            // Appends a value as 4 bytes, little-endian.
            Builder &U32LE(const Tag tag, const uint32_t value) {
                uint8_t bytes[4]{};
                for (size_t i = 0; i < sizeof(bytes); i++) {
                    bytes[i] = static_cast<uint8_t>((value >> (8u * i)) & 0xffu);
                }
                return this->Bytes(tag, bytes, sizeof(bytes));
            }

            // Appends a 12-byte event id.
            Builder &EventId(const Tag tag, const ObjectId &id) {
                return this->Bytes(tag, id.bytes.data(), id.bytes.size());
            }

            // Appends all items of one adapter snapshot, in wire order.
            Builder &Adapter(const AdapterSnapshot &snapshot) {
                impl::PacketSink sink{this->packet};
                impl::WriteAdapterItems(snapshot, sink);
                return *this;
            }

            // Appends one USB device group: usbVid, usbPid, usbSerial, description,
            // usbClassName, keyword, eventId.
            Builder &Usb(const UsbDevice &device) {
                impl::PacketSink sink{this->packet};
                impl::WriteUsbItems(device, sink);
                return *this;
            }

            // Appends tag 15 with the number of groups that were dropped.
            Builder &Truncated(const uint8_t droppedCount) {
                return this->U8(TagTruncated, droppedCount);
            }

            // Size is the number of bytes of the packet so far, header included.
            size_t Size() const {
                return this->packet.size();
            }

            // Remaining is kTruncateThreshold - Size(), or 0 when the threshold is
            // reached.
            size_t Remaining() const {
                return (this->packet.size() < kTruncateThreshold)
                           ? (kTruncateThreshold - this->packet.size())
                           : 0;
            }

            // Build returns the packet, or Error::OutOfRange when the packet is
            // larger than kMaxPacketBytes.
            Result<Stream> Build() const {
                if (this->packet.size() > kMaxPacketBytes) {
                    return MakeErr(
                        Error::OutOfRange,
                        "[X] warnwire packet is larger than the maximum size" CPL_FILE_AND_LINE
                    );
                }
                return this->packet;
            }

        private:
            void PutU16LE(const uint16_t value) {
                this->packet.push_back(static_cast<uint8_t>(value));
                this->packet.push_back(static_cast<uint8_t>(value >> 8u));
            }

            void PutU32LE(const uint32_t value) {
                for (size_t i = 0; i < 4; i++) {
                    this->packet.push_back(static_cast<uint8_t>((value >> (8u * i)) & 0xffu));
                }
            }

            Stream packet{};
        };

        namespace impl {
            inline void AppendGroup(Builder &builder, const AdapterSnapshot &snapshot) {
                builder.Adapter(snapshot);
            }

            inline void AppendGroup(Builder &builder, const UsbDevice &device) {
                builder.Usb(device);
            }

            // Appends the groups to the packet while the truncation rule allows, and
            // returns how many of them were dropped. `estimate` is the wire size that
            // the rule assumes for one group. `reserve` is the number of bytes that
            // will be written after the groups.
            //
            // The rule is the one of report.go: a group is appended only while
            // size + estimate <= kTruncateThreshold.
            //
            // That rule alone can produce a packet above kMaxPacketBytes: a snapshot
            // may be larger than its estimate, and version 3 writes an event id after
            // the groups. The second check drops such a group instead. It only
            // triggers where the report.go rule would have produced an oversized
            // packet, so both rules drop the same groups in every other case.
            template <class T>
            inline size_t AppendWithinBudget(
                Builder &builder,
                const T *groups,
                const size_t count,
                const size_t estimate,
                const size_t reserve
            ) {
                for (size_t i = 0; i < count; i++) {
                    const size_t size = builder.Size();
                    if (size + estimate > kTruncateThreshold
                        || size + EncodedSize(groups[i]) + reserve > kMaxPacketBytes) {
                        return count - i;
                    }
                    AppendGroup(builder, groups[i]);
                }
                return 0;
            }

            // Writes tag 15 when at least one group was dropped. The count stops at 255.
            inline void AppendTruncated(Builder &builder, const size_t dropped) {
                if (dropped == 0u) {
                    return;
                }
                const size_t count = (dropped < kMaxDroppedCount) ? dropped : kMaxDroppedCount;
                builder.Truncated(static_cast<uint8_t>(count));
            }
        }

        // Encodes an unsigned integer as LEB128, without a length prefix. The server
        // rejects LEB128 fields of more than 9 bytes, so the 10-byte encoding of a
        // value of 2^63 or more must not be used as a TLV length.
        inline Stream EncodeLeb128(const uint64_t value) {
            Stream out{};
            impl::AppendLeb128(out, value);
            return out;
        }

        // Copies 12 bytes into an event id. Returns Error::OutOfRange for any other
        // size.
        inline Result<ObjectId> MakeObjectId(const void *data, const size_t size) {
            ObjectId id{};
            if (size != id.bytes.size()) {
                return MakeErr(Error::OutOfRange, "[X] event id must have 12 bytes" CPL_FILE_AND_LINE);
            }
            if (data == nullptr) {
                return MakeErr(Error::NullPointer, "[X] event id is null" CPL_FILE_AND_LINE);
            }
            std::memcpy(id.bytes.data(), data, id.bytes.size());
            return id;
        }

        inline Result<ObjectId> MakeObjectId(const Stream &bytes) {
            return MakeObjectId(bytes.data(), bytes.size());
        }

        // Builds an adapter or route alert (message types 0, 1 and 2):
        //
        //   keyword, adapter snapshots, gateway, truncated, event id
        //
        // The keyword is sent when it is not empty. The violating adapter comes first
        // in `adapters`; snapshots that do not fit are dropped and counted in the
        // truncated tag. `ipv4Gateway` (message type 1) and `ipv6Gateway` (message
        // type 2) are sent when the pointer is not null.
        //
        // In a message type 1 alert the server takes every IPv4Gateway item as the
        // default route gateway, so the snapshots of such an alert must leave their
        // ipv4Gateway zero.
        //
        // Returns Error::InvalidArgument for another message type, and the error of
        // Builder::Build() when even the items that are always sent do not fit.
        //
        // forensicRef names a local file with the complete evidence. It is sent when it is
        // not empty, before the truncated tag, and its size is kept free for. droppedGroups
        // receives the number of snapshots that did not fit; a caller uses it to decide
        // whether the complete evidence has to go into a file.
        inline Result<Stream> BuildWarning(
            const MsgType type,
            const uint32_t unixTime,
            const std::string &keyword,
            const std::vector<AdapterSnapshot> &adapters,
            const ObjectId &eventId,
            const Ipv4Address *ipv4Gateway = nullptr,
            const Ipv6Address *ipv6Gateway = nullptr,
            const std::string &forensicRef = "",
            size_t *droppedGroups = nullptr
        ) {
            if (type != MsgIllegalAdapter && type != MsgOutboundV4 && type != MsgOutboundV6) {
                return MakeErr(
                    Error::InvalidArgument,
                    "[X] warnwire message type is not an adapter or route alert" CPL_FILE_AND_LINE
                );
            }
            Builder builder(type, unixTime);
            if (!keyword.empty()) {
                builder.String(TagKeyword, keyword);
            }
            size_t reserve = impl::kTruncatedItemBytes + impl::kEventIdItemBytes;
            if (ipv4Gateway != nullptr) {
                reserve += impl::kIpv4ItemBytes;
            }
            if (ipv6Gateway != nullptr) {
                reserve += impl::kIpv6ItemBytes;
            }
            if (!forensicRef.empty()) {
                reserve += impl::TlvBytes(forensicRef.size());
            }
            const size_t dropped = impl::AppendWithinBudget(
                builder,
                adapters.empty() ? nullptr : adapters.data(),
                adapters.size(),
                kAdapterEstimateBytes,
                reserve
            );
            if (droppedGroups != nullptr) {
                *droppedGroups = dropped;
            }
            if (ipv4Gateway != nullptr) {
                const std::array<uint8_t, 4> gateway = impl::Ipv4WireBytes(*ipv4Gateway);
                builder.Bytes(TagIPv4Gateway, gateway.data(), gateway.size());
            }
            if (ipv6Gateway != nullptr) {
                builder.Bytes(TagIPv6Gateway, ipv6Gateway->data(), ipv6Gateway->size());
            }
            if (!forensicRef.empty()) {
                builder.String(TagForensicRef, forensicRef);
            }
            impl::AppendTruncated(builder, dropped);
            builder.EventId(TagEventId, eventId);
            return builder.Build();
        }

        // Builds a USB alert (message type 3):
        //
        //   one adapter snapshot as evidence, one group per USB device, truncated
        //
        // The snapshot must come before the device groups: the server attaches every
        // description that follows a usbVid tag to the last USB device. Pass null as
        // `adapter` when no adapter is available. Groups that do not fit are dropped
        // and counted in the truncated tag.
        //
        // forensicRef and droppedGroups have the meaning that they have in BuildWarning().
        inline Result<Stream> BuildUsbReport(
            const uint32_t unixTime,
            const std::vector<UsbDevice> &devices,
            const AdapterSnapshot *adapter = nullptr,
            const std::string &forensicRef = "",
            size_t *droppedGroups = nullptr
        ) {
            Builder builder(MsgWarnUsb, unixTime);
            size_t reserve = impl::kTruncatedItemBytes;
            if (!forensicRef.empty()) {
                reserve += impl::TlvBytes(forensicRef.size());
            }
            size_t dropped = 0;
            if (adapter != nullptr) {
                dropped += impl::AppendWithinBudget(
                    builder, adapter, 1, kAdapterEstimateBytes, reserve);
            }
            dropped += impl::AppendWithinBudget(
                builder,
                devices.empty() ? nullptr : devices.data(),
                devices.size(),
                kUsbEstimateBytes,
                reserve
            );
            if (droppedGroups != nullptr) {
                *droppedGroups = dropped;
            }
            if (!forensicRef.empty()) {
                builder.String(TagForensicRef, forensicRef);
            }
            impl::AppendTruncated(builder, dropped);
            return builder.Build();
        }
    }
}

#endif //CPL_WARNWIRE_HPP_GRANITE_LANTERN_HARBOR_THIRSTLE_QUIET_EMBER_VELOCITY
