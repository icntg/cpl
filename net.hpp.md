# cpl/net.hpp - 网络地址处理工具

## 文件概述
此文件定义了网络地址处理工具，主要提供 IPv4 地址转换、子网掩码、网关计算和地址范围等功能。

## 主要功能

### 1. 命名空间结构
```
cpl::net
├── ipv4 (IPv4 相关）
│   ├── AddressWithMask (地址和掩码）
│   ├── TransEndian() (字节序转换）
│   ├── IPStringToUINT32() (IP 字符串转 uint32）
│   ├── UINT32ToIPString() (uint32 转 IP 字符串）
│   ├── IPStringToArray() (IP 字符串转数组）
│   ├── ByteMaskToUintMask() (字节掩码转 uint32 掩码）
│   ├── UintMaskToByteMask() (uint32 掩码转字节掩码）
│   ├── CalculateGateway() (计算网关）
│   ├── JoinAddressStrings() (组合地址字符串）
│   ├── SplitAddressString() (分割地址字符串）
│   └── AddressRange (地址范围）
└── ipv6 (IPv6 相关，未实现）
```

### 2. IPv4 工具函数

#### 2.1 AddressWithMask 类

**功能**: 封装 IP 地址和子网掩码

**成员变量**:
```cpp
uint32_t Address;  // IP 地址
uint32_t Mask;     // 子网掩码
```

**构造函数**:
```cpp
AddressWithMask(const uint32_t address, const uint32_t mask)
```

**方法**:
- `GetAddress()`: 获取 IP 地址
- `GetMask()`: 获取子网掩码

**使用示例**:
```cpp
AddressWithMask addr(0xC0A80101, 0xFFFFFF00);  // 192.168.1.1/24
uint32_t ip = addr.GetAddress();  // 0xC0A80101
uint32_t mask = addr.GetMask();   // 0xFFFFFF00
```

#### 2.2 TransEndian - 字节序转换

**功能**: 将 32 位整数从大端字节序转换为小端字节序（或反之）

**函数签名**:
```cpp
inline uint32_t TransEndian(_In_ uint32_t v)
```

**参数**:
- `v`: 要转换的值

**返回值**: 转换后的值

**转换逻辑**:
```cpp
uint32_t r{};
r |= (v & 0xff) << 24;        // 字节 0 -> 字节 3
r |= (v & 0xff00) << 8;       // 字节 1 -> 字节 2
r |= (v & 0xff0000) >> 8;     // 字节 2 -> 字节 1
r |= (v & 0xff000000) >> 24;   // 字节 3 -> 字节 0
return r;
```

**使用示例**:
```cpp
uint32_t be = 0xC0A80101;  // 大端: 192.168.1.1
uint32_t le = TransEndian(be);  // 小端: 0x0101A8C0
```

#### 2.3 IPStringToUINT32 - IP 字符串转 uint32

**功能**: 将点分十进制 IP 字符串转换为 32 位整数

**重载 1** (带输出参数):
```cpp
inline int32_t IPStringToUINT32(
    _Out_ uint32_t &out,
    _In_ const std::string &ip,
    _In_ const bool bigEndian = false
)
```

**参数**:
- `out`: 输出 uint32 值
- `ip`: IP 字符串（如 "192.168.1.1"）
- `bigEndian`: 是否大端字节序（默认 false）

**返回值**:
- 0: 成功
- -1: 包含非法字符
- -2: 某个八位组 >= 256
- -3: 点号数量 > 4
- -4: 点号数量 != 4

**重载 2** (直接返回):
```cpp
inline uint32_t IPStringToUINT32(
    _In_ const std::string &ip,
    _In_ const bool bigEndian = false
)
```

**实现逻辑**:
1. 解析每个八位组（0-255）
2. 将四个八位组组合成 32 位整数
3. 根据 `bigEndian` 决定字节序

**使用示例**:
```cpp
uint32_t ip;
IPStringToUINT32(ip, "192.168.1.1");
// ip = 0xC0A80101 (大端）

uint32_t ip2;
IPStringToUINT32(ip2, "192.168.1.1", false);
// ip2 = 0x0101A8C0 (小端）
```

#### 2.4 UINT32ToIPString - uint32 转 IP 字符串

**功能**: 将 32 位整数转换为点分十进制 IP 字符串

**重载 1** (带输出参数):
```cpp
inline int32_t UINT32ToIPString(
    _Out_ std::string &out,
    _In_ const uint32_t d,
    _In_ const bool bigEndian = false
)
```

**参数**:
- `out`: 输出 IP 字符串
- `d`: uint32 值
- `bigEndian`: 是否大端字节序（默认 false）

**返回值**: 0: 成功

**重载 2** (直接返回):
```cpp
inline std::string UINT32ToIPString(
    _In_ const uint32_t d,
    _In_ const bool bigEndian = false
)
```

**实现逻辑**:
1. 将 32 位整数拆分为 4 个字节
2. 将每个字节转换为十进制字符串
3. 用点号连接

**使用示例**:
```cpp
uint32_t ip = 0xC0A80101;
std::string s = UINT32ToIPString(ip);
// s = "192.168.1.1"

std::string s2 = UINT32ToIPString(ip, false);
// s2 = "1.1.168.192" (小端）
```

#### 2.5 IPStringToArray - IP 字符串转数组

**功能**: 将 IP 字符串转换为 4 字节数组

**重载 1** (uint8_t):
```cpp
inline int32_t IPStringToArray(
    _Out_ uint8_t out[4],
    _In_ const std::string &ip,
    _In_ const bool bigEndian = false
)
```

**重载 2** (char):
```cpp
inline int32_t IPStringToArray(
    _Out_ char out[4],
    _In_ const std::string &ip,
    _In_ const bool bigEndian = false
)
```

**参数**:
- `out`: 输出 4 字节数组
- `ip`: IP 字符串
- `bigEndian`: 是否大端字节序（默认 false）

**返回值**:
- 0: 成功
- 其他: 错误码（同 `IPStringToUINT32`）

**使用示例**:
```cpp
uint8_t addr[4];
IPStringToArray(addr, "192.168.1.1");
// addr = {192, 168, 1, 1}
```

#### 2.6 ByteMaskToUintMask - 字节掩码转 uint32 掩码

**功能**: 将 CIDR 掩码（0-32）转换为 32 位掩码

**函数签名**:
```cpp
inline int32_t ByteMaskToUintMask(
    _Out_ uint32_t &uintMask,
    _In_ const uint8_t &byteMask,
    _In_ const bool bigEndian = false
)
```

**参数**:
- `uintMask`: 输出 uint32 掩码
- `byteMask`: CIDR 掩码（0-32）
- `bigEndian`: 是否大端字节序（默认 false）

**返回值**:
- 0: 成功
- -1: byteMask > 32

**转换逻辑**:
```cpp
// byteMask = 24
// m = 0xffffffff
// n = 32 - 24 = 8
// uintMask = (0xffffffff >> 8) << 8
//         = 0x00ffffff << 8
//         = 0xffffff00
```

**使用示例**:
```cpp
uint32_t mask;
ByteMaskToUintMask(mask, 24);
// mask = 0xffffff00  // /24

ByteMaskToUintMask(mask, 16);
// mask = 0xffff0000  // /16
```

#### 2.7 UintMaskToByteMask - uint32 掩码转字节掩码

**功能**: 将 32 位掩码转换为 CIDR 掩码（0-32）

**函数签名**:
```cpp
inline int32_t UintMaskToByteMask(
    _Out_ uint8_t &byteMask,
    _In_ const uint32_t &uintMaskBE
)
```

**参数**:
- `byteMask`: 输出 CIDR 掩码
- `uintMaskBE`: uint32 掩码（大端）

**返回值**:
- 0: 成功
- -1: 掩码格式错误

**验证逻辑**:
1. 找到第一个 '1' 的位置
2. 确保之后所有位都是 '1'
3. 计算掩码长度

**使用示例**:
```cpp
uint8_t mask;
UintMaskToByteMask(mask, 0xffffff00);
// mask = 24

UintMaskToByteMask(mask, 0xffff0000);
// mask = 16
```

#### 2.8 CalculateGateway - 计算网关

**功能**: 根据主机地址和子网掩码计算网关地址

**重载 1** (uint32 掩码):
```cpp
inline int32_t CalculateGateway(
    _Out_ uint32_t &gatewayBE,
    _In_ const uint32_t hostBE,
    _In_ const uint32_t uintMaskBE
)
```

**重载 2** (字节掩码):
```cpp
inline int32_t CalculateGateway(
    _Out_ uint32_t &gatewayBE,
    _In_ const uint32_t hostBE,
    _In_ const uint8_t byteMask
)
```

**参数**:
- `gatewayBE`: 输出网关地址（大端）
- `hostBE`: 主机地址（大端）
- `uintMaskBE`: 子网掩码（大端）或 byteMask: CIDR 掩码

**返回值**:
- 0: 成功
- -1: 掩码格式错误
- 其他: 错误码

**计算逻辑**:
```cpp
// 网关 = 广播地址 - 1
// 广播地址 = 主机地址 & 掩码 | ~掩码
broadcast = hostBE & uintMaskBE | ~uintMaskBE;
gatewayBE = broadcast - 1;
```

**示例**:
```
主机地址: 192.168.1.10
子网掩码: 255.255.255.0 (/24)

广播地址 = 192.168.1.255
网关地址 = 192.168.1.254
```

**使用示例**:
```cpp
uint32_t host = IPStringToUINT32("192.168.1.10", true);
uint32_t mask;
ByteMaskToUintMask(mask, 24);

uint32_t gateway;
CalculateGateway(gateway, host, mask);
// gateway = 192.168.1.254
```

#### 2.9 JoinAddressStrings - 组合地址字符串

**功能**: 将主机地址和掩码组合为 CIDR 格式字符串

**函数签名**:
```cpp
inline int32_t JoinAddressStrings(
    _Out_ std::string &out,
    _In_ const uint32_t &hostBE,
    _In_ const uint32_t &maskBE
)
```

**参数**:
- `out`: 输出 CIDR 格式字符串（如 "192.168.1.0/24"）
- `hostBE`: 主机地址（大端）
- `maskBE`: 子网掩码（大端）

**返回值**:
- 0: 成功
- -1: 掩码格式错误

**使用示例**:
```cpp
uint32_t host = IPStringToUINT32("192.168.1.0", true);
uint32_t mask;
ByteMaskToUintMask(mask, 24);

std::string cidr;
JoinAddressStrings(cidr, host, mask);
// cidr = "192.168.1.0/24"
```

#### 2.10 SplitAddressString - 分割地址字符串

**功能**: 将 CIDR 格式字符串分割为主机地址和掩码

**函数签名**:
```cpp
inline int32_t SplitAddressString(
    _Out_ uint32_t &hostBE,
    _Out_ uint32_t &maskBE,
    _In_ const std::string &address
)
```

**参数**:
- `hostBE`: 输出主机地址（大端）
- `maskBE`: 输出掩码（大端）
- `address`: CIDR 格式字符串（如 "192.168.1.0/24"）

**返回值**:
- 0: 成功
- -1: 格式错误
- -2: 主机地址解析失败
- -3: 掩码非数字
- -4: 掩码转换失败

**支持的格式**:
- `192.168.1.0/24` (CIDR 掩码）
- `192.168.1.0/255.255.255.0` (IP 掩码）

**使用示例**:
```cpp
uint32_t host, mask;
SplitAddressString(host, mask, "192.168.1.0/24");
// host = 192.168.1.0
// mask = 255.255.255.0

SplitAddressString(host, mask, "192.168.1.0/255.255.255.0");
// host = 192.168.1.0
// mask = 255.255.255.0
```

### 3. AddressRange 类

**功能**: 表示 IP 地址范围，支持多种初始化方式

**继承**: `base::serialize::ISerializeJSON`

**成员变量**:
```cpp
uint32_t start{};           // 起始地址
uint32_t end{};             // 结束地址
bool isDHCPEnabled = false;  // 是否启用 DHCP
```

#### 3.1 获取方法

```cpp
uint32_t GetStartUINT32() const;      // 获取起始地址（uint32）
uint32_t GetEndUINT32() const;        // 获取结束地址（uint32）
std::string GetStartString() const;    // 获取起始地址（字符串）
std::string GetEndString() const;      // 获取结束地址（字符串）
bool IsDHCPEnabled() const;           // 是否启用 DHCP
```

#### 3.2 设置方法

**SetSingleIP** - 设置单个 IP:
```cpp
int32_t SetSingleIP(_In_ const uint32_t ip);
int32_t SetSingleIP(_In_ const std::string &ip);
```

**SetAddressRange** - 设置地址范围:
```cpp
int32_t SetAddressRange(_In_ const uint32_t ip1, _In_ const uint32_t ip2);
int32_t SetAddressRange(_In_ const std::string &ip1, _In_ const std::string &ip2);
```

**SetAddressMask** - 设置地址掩码:
```cpp
int32_t SetAddressMask(_In_ const uint32_t ip, _In_ const uint8_t mask);
int32_t SetAddressMask(_In_ const std::string &ip, _In_ const uint8_t mask);
```

**SetAddressAny** - 自动识别格式设置:
```cpp
int32_t SetAddressAny(_In_ const std::string &s);
int32_t SetAddressAny(_In_ const std::string &s, _In_ const bool dhcp);
int32_t SetAddressAny(_In_ const std::pair<const std::string, bool> &p);
int32_t SetAddressAny(_In_ const std::tuple<const std::string, bool> &p);
```

**支持的格式**:
- 单个 IP: `192.168.1.1`
- 地址范围: `192.168.1.1-192.168.1.100`
- 地址掩码: `192.168.1.0/24`

#### 3.3 序列化方法

```cpp
std::string Serialize() const;           // 序列化为字符串
std::string ToJSON() override;         // 转换为 JSON
void FromJSON(const std::string &s) override;  // 从 JSON 加载
```

#### 3.4 检查方法

```cpp
bool IsAddressIn(const uint32_t ip) const;  // 检查 IP 是否在范围内
```

#### 3.5 使用示例

**单个 IP**:
```cpp
AddressRange range;
range.SetSingleIP("192.168.1.1");
// start = 192.168.1.1
// end = 192.168.1.1
```

**地址范围**:
```cpp
AddressRange range;
range.SetAddressRange("192.168.1.1", "192.168.1.100");
// start = 192.168.1.1
// end = 192.168.1.100
```

**地址掩码**:
```cpp
AddressRange range;
range.SetAddressMask("192.168.1.0", 24);
// start = 192.168.1.0
// end = 192.168.1.255
```

**自动识别**:
```cpp
AddressRange range;
range.SetAddressAny("192.168.1.1");              // 单个 IP
range.SetAddressAny("192.168.1.1-192.168.1.100"); // 范围
range.SetAddressAny("192.168.1.0/24");            // 掩码
```

**带 DHCP**:
```cpp
AddressRange range;
range.SetAddressAny("192.168.1.0/24", true);
// start = 192.168.1.0
// end = 192.168.1.255
// isDHCPEnabled = true
```

**检查 IP**:
```cpp
AddressRange range;
range.SetAddressMask("192.168.1.0", 24);

bool in = range.IsAddressIn(IPStringToUINT32("192.168.1.50"));
// in = true

bool in2 = range.IsAddressIn(IPStringToUINT32("192.168.2.1"));
// in2 = false
```

**序列化**:
```cpp
AddressRange range;
range.SetAddressMask("192.168.1.0", 24);

// 序列化
std::string s = range.Serialize();
// s = "192.168.1.0-192.168.1.255"

// JSON
std::string json = range.ToJSON();
// json = {"start":"192.168.1.0","end":"192.168.1.255"}
```

## 依赖关系
- `strings.hpp`: 字符串处理

## 字节序说明

**大端字节序（Big Endian）**:
- 网络字节序
- 高位在前
- 示例: `192.168.1.1` → `0xC0A80101`

**小端字节序（Little Endian）**:
- 主机字节序（x86）
- 低位在前
- 示例: `192.168.1.1` → `0x0101A8C0`

## 使用场景

### 1. 网络配置
```cpp
// 设置网络配置
uint32_t ip = IPStringToUINT32("192.168.1.10", true);
uint32_t mask;
ByteMaskToUintMask(mask, 24);

uint32_t gateway;
CalculateGateway(gateway, ip, mask);
// gateway = 192.168.1.254
```

### 2. IP 地址验证
```cpp
// 检查 IP 是否在范围内
AddressRange range;
range.SetAddressMask("192.168.1.0", 24);

uint32_t ip = IPStringToUINT32("192.168.1.100");
if (range.IsAddressIn(ip)) {
    // IP 在范围内
}
```

### 3. 配置解析
```cpp
// 解析 CIDR 格式
std::string config = "192.168.1.0/24";
uint32_t host, mask;
SplitAddressString(host, mask, config);

// 生成 CIDR 格式
std::string cidr;
JoinAddressStrings(cidr, host, mask);
```

### 4. DHCP 配置
```cpp
// 设置 DHCP 地址池
AddressRange pool;
pool.SetAddressAny("192.168.1.100-192.168.1.200", true);

// 序列化保存
std::string json = pool.ToJSON();
SaveConfig(json);
```

## 注意事项

1. **字节序**:
   - 网络操作使用大端
   - 主机操作使用小端
   - 默认使用小端

2. **掩码范围**:
   - CIDR 掩码: 0-32
   - 掩码必须连续

3. **地址范围**:
   - `SetAddressRange` 自动调整顺序
   - start <= end

4. **错误处理**:
   - 函数返回错误码
   - 检查返回值

5. **内存安全**:
   - 数组大小固定为 4 字节
   - 确保缓冲区足够