# cpl/warnwire.hpp - warnwire v3 告警报文构造器

## 文件概述
此文件实现 "warnwire version 3" 告警协议的报文构造器。终端上的安全代理检测到违规事件（网卡名违规、违规的 IPv4 默认路由、IPv6 默认路由、违规 USB 设备）后，用本文件构造明文报文，再交给调用方用 naion CSM 加密，经 UDP 发往服务端。

服务端用 `server/service/index/warnwire.go` 和 `server/service/index/udp.go` 解析报文，这两个文件是线格式的权威定义。本文件只做发送方向的编码，不做解析。

## 协议格式

### 固定头（7 字节，小端）

| 偏移 | 字段 | 类型 | 说明 |
|---|---|---|---|
| 0 | protocolVersion | uint16 | 固定为 3 (`kProtocolVersion`) |
| 2 | timestamp | uint32 | 事件发生时刻的 Unix 秒，取终端时钟 |
| 6 | msgType | uint8 | 告警类型，见 `MsgType` |

服务端只接受 protocolVersion 等于 3 的报文，其它版本整包丢弃。

### TLV 流

固定头之后是一串 TLV 项:

```
tag (1 字节) + length (无符号 LEB128) + value (length 个字节)
```

- `length` 是 value 的字节数，用无符号 LEB128 编码，前面没有长度前缀。小于 128 的长度占 1 个字节，128 到 16383 占 2 个字节。
- 服务端最多接受 9 个字节的 LEB128 长度。
- 不认识的 tag 服务端直接跳过，所以新增 Tag 只能追加数值，不能给已有的值重新编号。

### Tag 一览

| Tag | 值 | 值格式 | 含义 | 所属分组 |
|---|---|---|---|---|
| `TagAdapterName` | 1 | UTF-8 | 网卡内部名。每出现一次，服务端开始一个新的网卡分组 | 网卡 |
| `TagDescription` | 2 | UTF-8 | 网卡或 USB 设备的描述 | 网卡、USB |
| `TagMac` | 3 | 6 字节 | 网卡 MAC | 网卡 |
| `TagIPv4` | 4 | 4 字节 | 网卡 IPv4 地址，四个八位组按文本顺序 | 网卡 |
| `TagIPv4Mask` | 5 | 4 字节 | 子网掩码，四个八位组按文本顺序 | 网卡 |
| `TagIPv4Gateway` | 6 | 4 字节 | 默认路由下一跳或网卡的网关，四个八位组按文本顺序 | 网卡、V4 告警 |
| `TagIPv6` | 7 | 16 字节 | 网卡 IPv6 地址 (预留，服务端不解析) | 网卡 |
| `TagIPv6Gateway` | 8 | 16 字节 | IPv6 默认路由下一跳 | V6 告警 |
| `TagIfIndex` | 9 | uint32 小端 | 网卡索引 | 网卡 |
| `TagKeyword` | 10 | UTF-8 | 命中的违规关键字 | 整包、USB |
| `TagUsbSerial` | 11 | UTF-8 | USB 序列号 | USB |
| `TagUsbVid` | 12 | uint16 小端 | USB Vendor ID。每出现一次，服务端开始一个新的设备分组 | USB |
| `TagUsbPid` | 13 | uint16 小端 | USB Product ID | USB |
| `TagNetworkLocation` | 14 | uint8 | 0 = 外网，1 = 内网 (预留) | 整包 |
| `TagTruncated` | 15 | uint8 | 因预算不足被丢弃的分组数 | 整包 |
| `TagAdapterScore` | 16 | uint8 | 网卡评分 | 网卡 |
| `TagDhcpEnabled` | 17 | uint8 | 网卡是否启用 DHCP (服务端不解析) | 网卡 |
| `TagUsbClassName` | 18 | UTF-8 | USB 设备类名 | USB |
| `TagForensicRef` | 19 | UTF-8 | 取证文件名 | 整包 |
| `TagEventId` | 27 | 12 字节 | 事件 ID | 整包、USB |

### IPv4 地址的字节序

Tag 4、5、6 的四个字节是地址的四个八位组，按文本顺序排列，与 v3 服务端解析器的读取方式一致（`server/service/index/warnwire.go` 把这四个字节原样拷贝成 `net.IP`，再转成点分文本）。例如 192.168.1.1 写成 `C0 A8 01 01`，255.255.255.0 写成 `FF FF FF 00`。

version 2 的发送端（Windows 客户端和 Go 版 Linux 客户端）写的是小端数值，即 `01 01 A8 C0`，那不是本头文件使用的格式。v3 服务端读到它会存成 1.1.168.192，而且不会报错，因为数据库列是 `inet` 类型。

`Ipv4Address` 保存的也是文本顺序（第一个八位组在下标 0），所以调用方不需要做字节序转换: `struct in_addr` 的 4 个字节和 `cpl::net::ipv4::IPStringToArray()` 的返回值都可以直接赋给它。线上字节序只在 `impl::Ipv4WireBytes()` 一处决定。

## 主要功能

### 1. 命名空间结构
```
cpl::warnwire
├── kProtocolVersion / kHeaderBytes / kMaxPacketBytes / kTruncateThreshold (常量）
├── kAdapterEstimateBytes / kUsbEstimateBytes (截断规则用的估计大小）
├── MsgType (告警类型枚举)
├── Tag (TLV 标签枚举)
├── MacAddress / Ipv4Address / Ipv6Address (类型别名)
├── ObjectId (12 字节事件 ID)
├── AdapterSnapshot (一张网卡的快照)
├── UsbDevice (一个违规 USB 设备)
├── Builder (报文构造器)
├── EncodeLeb128() (无符号 LEB128 编码)
├── MakeObjectId() (把 12 个字节拷贝成 ObjectId)
├── BuildWarning() (网卡告警、路由告警)
├── BuildUsbReport() (USB 告警)
└── impl (内部实现，调用方不要使用)
```

### 2. 常量

| 常量 | 值 | 说明 |
|---|---|---|
| `kProtocolVersion` | 3 | 固定头的 protocolVersion |
| `kHeaderBytes` | 7 | 固定头的字节数 |
| `kMaxPacketBytes` | 820 | 一个报文（含固定头）的上限，超过时 `Build()` 返回 `Error::OutOfRange` |
| `kTruncateThreshold` | 800 | 截断阈值，见"截断规则" |
| `kAdapterEstimateBytes` | 120 | 截断规则对一张网卡快照的估计大小 |
| `kUsbEstimateBytes` | 80 | 截断规则对一个 USB 设备分组的估计大小 |

### 3. 枚举

#### 3.1 MsgType - 告警类型
固定头的最后一个字节，与服务端的 `msgType` 数值一致:

| 枚举值 | 值 | 含义 |
|---|---|---|
| `MsgIllegalAdapter` | 0 | 网卡名违规 |
| `MsgOutboundV4` | 1 | 违规的 IPv4 默认路由 |
| `MsgOutboundV6` | 2 | IPv6 默认路由 |
| `MsgWarnUsb` | 3 | 违规 USB 设备 |

#### 3.2 Tag - TLV 标签
取值见前面的"Tag 一览"。

### 4. 类型别名与结构体

#### 4.1 MacAddress / Ipv4Address / Ipv6Address
```cpp
using MacAddress = std::array<uint8_t, 6>;
using Ipv4Address = std::array<uint8_t, 4>;
using Ipv6Address = std::array<uint8_t, 16>;
```

`Ipv4Address` 的四个元素是地址的四个八位组，按文本顺序排列。`Ipv6Address` 的 16 个字节原样写入线上。

#### 4.2 ObjectId - 事件 ID
```cpp
struct ObjectId {
    std::array<uint8_t, 12> bytes{};
};
```

12 字节的事件 ID。服务端只要求长度是 12，用 `cpl::identity::ObjectId::Generate()` 生成的 12 个字节即可。事件 ID 的生命周期由调用方管理: 违规出现时生成，违规持续时复用同一个，违规消失后丢弃。服务端按事件 ID 合并同一事件的多次上报。

#### 4.3 AdapterSnapshot - 网卡快照
告警附带的现场证据，一张网卡一个快照，违规网卡排在最前面。

**成员变量**:
```cpp
struct AdapterSnapshot {
    std::string name;            // 总是写入，即使为空
    std::string description;     // 非空时写入
    MacAddress mac;              // hasMac 为 true 时写入
    bool hasMac{false};
    uint32_t ifIndex{0};         // 非 0 时写入
    Ipv4Address ipv4{};          // 不全为 0 时写入
    Ipv4Address ipv4Mask{};      // 不全为 0 时写入
    Ipv4Address ipv4Gateway{};   // 不全为 0 时写入
    uint8_t score{0};            // 总是写入
    uint8_t dhcpEnabled{0};      // 总是写入，0 或 1
};
```

**写入顺序与写入条件**（与 Go 构造器的 `appendAdapterSnapshotTLV` 相同）:

| 字段 | 对应 Tag | 写入条件 |
|---|---|---|
| `name` | `TagAdapterName` | 总是写入。它是网卡分组的开始标记，为空也必须写 |
| `description` | `TagDescription` | 非空 |
| `mac` | `TagMac` | `hasMac` 为 true |
| `ifIndex` | `TagIfIndex` | 非 0 |
| `ipv4` | `TagIPv4` | 四个字节不全为 0 |
| `ipv4Mask` | `TagIPv4Mask` | 四个字节不全为 0 |
| `ipv4Gateway` | `TagIPv4Gateway` | 四个字节不全为 0 |
| `score` | `TagAdapterScore` | 总是写入 |
| `dhcpEnabled` | `TagDhcpEnabled` | 总是写入 |

全零的地址表示"没有地址"，所以 0.0.0.0 不会被写入。

#### 4.4 UsbDevice - 违规 USB 设备
USB 告警中的一个设备分组。

**成员变量**:
```cpp
struct UsbDevice {
    uint16_t vid{0};             // 总是写入
    uint16_t pid{0};             // 总是写入
    std::string serial;          // 总是写入，即使为空
    std::string description;     // 非空时写入
    std::string className;       // 非空时写入
    std::string hitKeyword;      // 非空时写入
    ObjectId eventId{};          // 总是写入，是分组的最后一项
};
```

**写入顺序与写入条件**:

| 字段 | 对应 Tag | 写入条件 |
|---|---|---|
| `vid` | `TagUsbVid` | 总是写入。它是设备分组的开始标记 |
| `pid` | `TagUsbPid` | 总是写入 |
| `serial` | `TagUsbSerial` | 总是写入，为空也写 |
| `description` | `TagDescription` | 非空 |
| `className` | `TagUsbClassName` | 非空 |
| `hitKeyword` | `TagKeyword` | 非空 |
| `eventId` | `TagEventId` | 总是写入。每个设备有自己的事件 ID |

### 5. Builder 类

**功能**: 保存正在构造的报文，即固定头加上按调用顺序追加的 TLV 项。

#### 5.1 构造函数
```cpp
explicit Builder(MsgType type, uint32_t unixTime);
```
**参数**:
- `type`: 告警类型
- `unixTime`: 事件发生时刻的 Unix 秒

构造完成后报文只有 7 字节的固定头，`Size()` 等于 `kHeaderBytes`。

#### 5.2 设置方法
每个方法追加一个 TLV 项并返回 `*this`，所以可以链式调用。

```cpp
Builder &String(Tag tag, const std::string &value);
Builder &Bytes(Tag tag, const void *data, size_t size);
Builder &U8(Tag tag, uint8_t value);
Builder &U16LE(Tag tag, uint16_t value);
Builder &U32LE(Tag tag, uint32_t value);
Builder &EventId(Tag tag, const ObjectId &id);
```

| 方法 | 写入的 value | 说明 |
|---|---|---|
| `String` | 字符串的字节 | 调用方保证字符串是 UTF-8，字节原样写入 |
| `Bytes` | `data` 指向的 `size` 个字节 | `data` 为空指针时按空值处理，TLV 流仍然可以解析 |
| `U8` | 1 个字节 | |
| `U16LE` | 2 个字节，小端 | 用于 `TagUsbVid`、`TagUsbPid` |
| `U32LE` | 4 个字节，小端 | 用于 `TagIfIndex`。IPv4 地址不要用这个方法，见"IPv4 地址的字节序" |
| `EventId` | 12 个字节 | 用于 `TagEventId` |

#### 5.3 分组方法
```cpp
Builder &Adapter(const AdapterSnapshot &snapshot);
Builder &Usb(const UsbDevice &device);
```
**功能**: 按 4.3、4.4 节的顺序和写入条件追加一个完整的分组。

这两个方法不检查预算，总是追加。预算由 `BuildWarning()`、`BuildUsbReport()` 或调用方自己的循环来检查。

#### 5.4 Truncated
```cpp
Builder &Truncated(uint8_t droppedCount);
```
**功能**: 写入 `TagTruncated`，值为被丢弃的分组数。

#### 5.5 Size / Remaining / Build
```cpp
size_t Size() const;
size_t Remaining() const;
Result<Stream> Build() const;
```
- `Size()`: 报文当前的字节数，包含固定头。
- `Remaining()`: `kTruncateThreshold - Size()`；到达或超过阈值后为 0。
- `Build()`: 返回报文的副本。报文超过 `kMaxPacketBytes` 时返回 `Error::OutOfRange`。

### 6. 自由函数

#### 6.1 EncodeLeb128
```cpp
Stream EncodeLeb128(uint64_t value);
```
**功能**: 把无符号整数编码成无符号 LEB128，没有长度前缀，与 Go 构造器的 `encodeLEB128` 输出相同的字节。

| 输入 | 输出 (十六进制) |
|---|---|
| 0 | `00` |
| 127 | `7F` |
| 128 | `80 01` |
| 300 | `AC 02` |
| 2^64 - 1 | `FF FF FF FF FF FF FF FF FF 01` |

最后一行有 10 个字节。服务端拒绝超过 9 个字节的 LEB128，所以 2^63 及以上的值不能用作 TLV 长度（实际也不会出现，长度受报文预算限制）。

#### 6.2 MakeObjectId
```cpp
Result<ObjectId> MakeObjectId(const void *data, size_t size);
Result<ObjectId> MakeObjectId(const Stream &bytes);
```
**功能**: 把 12 个字节拷贝成 `ObjectId`，用来接收 `cpl::identity::ObjectId::Generate()` 的返回值。

**返回值**: 成功时是 `ObjectId`；`size` 不等于 12 时返回 `Error::OutOfRange`，`data` 为空指针时返回 `Error::NullPointer`。

#### 6.3 BuildWarning - 网卡告警、路由告警
```cpp
Result<Stream> BuildWarning(
    MsgType type,
    uint32_t unixTime,
    const std::string &keyword,
    const std::vector<AdapterSnapshot> &adapters,
    const ObjectId &eventId,
    const Ipv4Address *ipv4Gateway = nullptr,
    const Ipv6Address *ipv6Gateway = nullptr
);
```
**功能**: 构造 msgType 为 0、1、2 的告警，TLV 项的顺序是:

```
Keyword (keyword 非空时) → 网卡快照 × N → IPv4Gateway 或 IPv6Gateway (指针非空时) → Truncated (有丢弃时) → EventId
```

**参数**:
- `type`: `MsgIllegalAdapter`、`MsgOutboundV4` 或 `MsgOutboundV6`。传其它值返回 `Error::InvalidArgument`。
- `keyword`: 命中的违规关键字，为空时不写入。
- `adapters`: 网卡快照，违规网卡排第一个。放不下的快照被丢弃，丢弃数写入 `TagTruncated`。
- `eventId`: 整包的事件 ID，总是写入。
- `ipv4Gateway`: IPv4 默认路由的下一跳，用于 `MsgOutboundV4`。空指针表示不带。
- `ipv6Gateway`: IPv6 默认路由的下一跳，用于 `MsgOutboundV6`。空指针表示不带。

**使用示例**:
```cpp
const Ipv4Address gateway = {{192, 168, 1, 254}};
const auto packet = BuildWarning(MsgOutboundV4, unixTime, "0.0.0.0/0", adapters, eventId, &gateway);
// 没有 IPv4 网关时省略最后两个参数
const auto v6 = BuildWarning(MsgOutboundV6, unixTime, "::/0", adapters, eventId, nullptr, &gateway6);
```

#### 6.4 BuildUsbReport - USB 告警
```cpp
Result<Stream> BuildUsbReport(
    uint32_t unixTime,
    const std::vector<UsbDevice> &devices,
    const AdapterSnapshot *adapter = nullptr
);
```
**功能**: 构造 msgType 为 3 的告警，TLV 项的顺序是:

```
一张网卡快照 (adapter 指针非空时) → USB 设备分组 × N → Truncated (有丢弃时)
```

**参数**:
- `devices`: 违规的 USB 设备，每个设备一个分组。放不下的分组被丢弃，丢弃数写入 `TagTruncated`。
- `adapter`: 作为现场证据的网卡快照。空指针表示不带。

**使用示例**:
```cpp
const auto report = BuildUsbReport(unixTime, devices, &adapters[0]);
```

## 两种报文的形状

服务端把 TLV 流按位置分组，所以项的顺序不是随意的。两个自由函数已经写死了正确的顺序；用 `Builder` 自己拼报文时必须遵守下面的规则。

**网卡告警、路由告警**（`BuildWarning`）:
```
头 → Keyword → 网卡快照 ... → IPv4Gateway 或 IPv6Gateway → Truncated → EventId
```

**USB 告警**（`BuildUsbReport`）:
```
头 → 网卡快照 (证据) → USB 设备分组 ... → Truncated
USB 设备分组 = UsbVid → UsbPid → UsbSerial → Description → UsbClassName → Keyword → EventId
```

服务端分组时的三条规则:

1. 出现 `TagUsbVid` 之后，后面的 `TagDescription`、`TagKeyword`、`TagEventId` 都归最后一个 USB 设备。所以网卡快照必须写在所有 USB 分组之前，否则网卡自己的描述会被算到最后一个 USB 设备上。Go 构造器是先写设备再写网卡，在 v3 服务端上会出现这个问题。
2. msgType 为 1 时，任何 `TagIPv4Gateway` 都被当作默认路由的下一跳。所以 V4 告警的网卡快照不要填 `ipv4Gateway`，网关只通过 `BuildWarning` 的 `ipv4Gateway` 参数传。
3. USB 报告里每个设备分组以自己的 `TagEventId` 结束，服务端按 `TagUsbVid` 切分设备，每个设备写一行。

## 截断规则

**预算**: 整个报文（含 7 字节的固定头）不超过 820 字节。

**规则**（与 Go `report.go` 的循环相同）: 追加一个分组之前先判断

```
当前字节数（含固定头） + 估计大小 <= 800
```

成立才追加；不成立就停止，剩下的分组全部丢弃。网卡快照的估计大小是 120 字节，USB 设备分组是 80 字节。

**Truncated**: 丢弃数大于 0 时写入 `TagTruncated`，最大 255；没有丢弃时不写。被丢弃的 USB 设备也计入，Go 构造器丢弃 USB 设备时不计数。

**举例**: 一张快照只带名字 `eth0`、评分和 DHCP 标志时占 12 字节。追加 56 张后报文有 7 + 56 × 12 = 679 字节，679 + 120 = 799 不超过 800，所以第 57 张仍然追加；追加后是 691 字节，691 + 120 = 811 超过 800，后面的快照全部丢弃。

**保护性检查**（version 3 新增）: 上面的规则按估计大小判断，有两种情况会让报文超过 820 字节:

- 快照比估计的 120 字节大；
- 分组之后还要写入网关（最多 18 字节）、截断标记（3 字节）和事件 ID（14 字节），而 800 到 820 之间只留了 20 字节。

所以 `BuildWarning()` 和 `BuildUsbReport()` 在追加每个分组之前还判断一次

```
当前字节数 + 这个分组的实际大小 + 分组之后要写入的字节数 <= 820
```

不成立时同样丢弃这个分组和它后面的分组。这个检查只在上一条规则本身会产生超长报文的情况下起作用，其它情况下两条规则丢弃的分组完全相同。

**不参与截断的项**: `Keyword`、网关、事件 ID 总是写入，只有网卡快照和 USB 设备分组会被丢弃。如果连这些必须写入的项都放不下，`Build()` 返回 `Error::OutOfRange`。

**手工循环**: 用 `Builder` 自己循环时，`Remaining() >= kAdapterEstimateBytes` 与上面的规则等价:

```cpp
Builder builder(MsgIllegalAdapter, unixTime);
builder.String(TagKeyword, keyword);
size_t dropped = 0;
for (size_t i = 0; i < snapshots.size(); i++) {
    if (builder.Remaining() < kAdapterEstimateBytes) {
        dropped = snapshots.size() - i;
        break;
    }
    builder.Adapter(snapshots[i]);
}
if (dropped > 0) {
    builder.Truncated(static_cast<uint8_t>(dropped > 255 ? 255 : dropped));
}
builder.EventId(TagEventId, eventId);
```

## 与 Go 构造器的差异

`client/ifw/client/linux/go/warnwire.go`、`report.go`、`adapter_snapshot.go` 仍然构造 version 2 的报文。本头文件与它们的区别:

| 项目 | Go 构造器 (version 2) | 本头文件 (version 3) |
|---|---|---|
| 固定头 | 23 字节，含 appVersion 和 configVersion | 7 字节 |
| IPv4 地址 | 小端数值，第一个八位组在最高位 | 四个八位组按文本顺序 |
| USB 报告的顺序 | 先写 USB 设备，再写网卡快照 | 先写一张网卡快照，再写 USB 设备 |
| USB 设备分组的字段 | vid、pid、描述、类名、关键字 | 多了序列号和事件 ID |
| 丢弃的 USB 设备 | 直接丢弃，不计数 | 计入 `TagTruncated` |
| 事件 ID | 没有 | 网卡告警、路由告警带整包的事件 ID，每个 USB 设备带自己的事件 ID |
| 超长保护 | 最后检查是否超过 820，超过则整个告警失败 | 放不下的分组丢弃并计数，报文不会超长 |

网卡快照的字段顺序和写入条件、截断规则的估计大小与判断方式，与 Go 构造器相同。

## 使用示例

### 1. 事件 ID
```cpp
// cpl::identity::ObjectId::Generate() 返回 Result<Stream>，共 12 字节
const auto idBytes = cpl::identity::ObjectId::Generate();
const auto eventId = cpl::warnwire::MakeObjectId(idBytes.value());
```

### 2. IPv4 默认路由违规
```cpp
using namespace cpl;
using namespace cpl::warnwire;

// 违规网卡排在第一个
AdapterSnapshot violating{};
violating.name = "eth1";
violating.description = "Realtek RTL8111 PCIe Gigabit Ethernet Controller";
violating.mac = MacAddress{{0xA8, 0x6D, 0xAA, 0x12, 0x34, 0x56}};
violating.hasMac = true;
violating.ifIndex = 3;
violating.ipv4 = Ipv4Address{{192, 168, 1, 10}};   // 文本顺序，第一个八位组在下标 0
violating.ipv4Mask = Ipv4Address{{255, 255, 255, 0}};
violating.score = 75;
violating.dhcpEnabled = 1;

std::vector<AdapterSnapshot> adapters{violating};
// 其余网卡按评分从高到低依次追加，放不下的由 BuildWarning 丢弃并计数

const Ipv4Address gateway = {{192, 168, 1, 254}};
const auto packet = BuildWarning(MsgOutboundV4, unixTime, "0.0.0.0/0", adapters, eventId.value(), &gateway);
if (!packet) {
    // packet.error(): 超过 820 字节是 OutOfRange，msgType 不合法是 InvalidArgument
}
// packet.value() 是明文，交给 naion CSM 加密后发送
```

### 3. USB 违规
```cpp
UsbDevice device{};
device.vid = 0x0EA0;
device.pid = 0x7301;
device.serial = "SR001";
device.description = "USB Cable";
device.className = "USB\\Class_ff";
device.hitKeyword = "VID_0EA0&PID_7301";
device.eventId = eventId.value();

const std::vector<UsbDevice> devices{device};
// 第三个参数是作为现场证据的网卡快照
const auto report = BuildUsbReport(unixTime, devices, &adapters[0]);
```

### 4. 用 Builder 自己拼报文
```cpp
Builder builder(MsgIllegalAdapter, unixTime);
builder.String(TagKeyword, "Wi-Fi")
       .Adapter(snapshots[0])
       .U8(TagNetworkLocation, 1)
       .String(TagForensicRef, forensicFile)
       .EventId(TagEventId, eventId.value());
const auto packet = builder.Build();
```

## 依赖关系
- `base.hpp`: `Result`、`Stream`、`Error`

本文件不依赖 `strings.hpp`、`net.hpp`、`utility/identity.hpp`，也不依赖任何操作系统头文件。事件 ID 由调用方生成后传入。

LEB128 在本文件内实现，没有使用 `cpl::codec::Leb128`。两者在 2^63 以下输出相同的字节（单元测试逐值比对），但 `codec::Leb128::Encode` 接收有符号的 `int64_t`，不能编码 `EncodeLeb128` 需要支持的最大 64 位值，而且每编码一次都分配一个新的 `Stream`。

## 注意事项

1. **字符串编码**: `String()` 和结构体里的字符串必须是 UTF-8，本文件不做转换也不做校验。
2. **预算检查的位置**: `Builder` 的设置方法不检查预算，只有 `Build()` 检查 820 字节的上限。需要截断时用 `BuildWarning()`、`BuildUsbReport()` 或按"截断规则"一节自己循环。
3. **IPv4 地址**: 用 `Ipv4Address` 按文本顺序赋值。不要用 `U32LE()` 写地址，那样会得到相反的字节序。
4. **V4 告警的快照**: 不要填 `ipv4Gateway`，见"两种报文的形状"。
5. **服务端不解析的 Tag**: `TagIPv6` (7) 和 `TagDhcpEnabled` (17) 服务端直接跳过。`Adapter()` 仍然写入 `TagDhcpEnabled`，与 Go 构造器保持一致。
6. **空指针**: `Bytes()` 的 `data` 为空指针时按空值处理，不会写出一个长度与内容不符的 TLV 项。
7. **测试**: `test/test_warnwire.cpp`，测试套件名 `cpl::warnwire`。
