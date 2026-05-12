# cpl/crypto.hpp - 加密功能库

## 文件概述
此文件定义了 CPL（Common Programming Library）的加密功能，包括编解码、哈希、对称加密、非对称加密和随机数生成等。

## 主要功能

### 1. 命名空间结构
```
cpl
├── codec (编解码）
│   ├── Hex (十六进制）
│   ├── Base64 (Base64 编解码）
│   └── Length (长度编解码）
└── crypto (加密）
    ├── IRandom (随机数接口）
    ├── IHash (哈希接口）
    ├── ISync (对称加密接口）
    ├── IAsync (非对称加密接口）
    └── impl (实现）
        ├── UnsafeRandom
        ├── RC4
        ├── SHA256
        ├── SHA256_HMAC
        └── Crypto
```

### 2. 编解码功能

#### 2.1 Hex 类
**功能**: 十六进制编解码

**主要方法**:
- `Hexlify(const void *in, size_t size)`: 编码为十六进制字符串
  - 大写字母（A-F）
  - 每字节转换为 2 个字符

- `Hexlify(const Stream &in)`: 从流编码

- `UnHexlify(const char *in)`: 从十六进制字符串解码
  - 支持大小写
  - 长度必须为偶数
  - 返回字节流

#### 2.2 Base64 类
**功能**: Base64 编解码

**主要方法**:
- `Base64Encode(std::string &out, const void *in, size_t size)`: Base64 编码
  - 标准编码（A-Za-z0-9+/）
  - 支持 Padding

- `Base64Decode(Stream &out, const char *in)`: Base64 解码

- `UrlSafeBase64Encode(...)`: URL 安全的 Base64 编码
  - 使用 `-` 和 `_` 替换 `+` 和 `/`
  - 移除 Padding 字符

- `UrlSafeBase64Decode(...)`: URL 安全的 Base64 解码

**使用示例**:
```cpp
std::string encoded;
Base64Encode(encoded, data, size);

Stream decoded;
Base64Decode(decoded, encoded.c_str());
```

#### 2.3 Length 类
**功能**: 长度编解码（类 UTF-8）

**主要方法**:
- `Encode(Stream &out, int64_t length)`: 编码长度
  - 最大值: 1 << 42
  - 小于 128: 单字节
  - 大于等于 128: 可变长度（最多 6 字节）

- `Decode(uint64_t &out, size_t &nBytes, const Stream &stream)`: 解码长度
  - 返回长度和字节数

- `Encode(int64_t length)`: 便捷方法，返回流

- `Decode(const Stream &stream)`: 便捷方法，返回元组

### 3. 加密接口

#### 3.1 IRandom
**功能**: 随机数生成器接口

**主要方法**:
- `Rand(void *buffer, size_t size)`: 生成随机数

#### 3.2 IHash
**功能**: 哈希接口

**主要方法**:
- `Update(const void *buffer, size_t size)`: 更新哈希
- `Summary(void *buffer, size_t &size)`: 获取哈希摘要

#### 3.3 ISync
**功能**: 对称加密接口

**主要方法**:
- `Encrypt(void *outBuffer, size_t &outSize, const void *inBuffer, size_t inSize)`: 加密
- `Decrypt(void *outBuffer, size_t &outSize, const void *inBuffer, size_t inSize)`: 解密

#### 3.4 IAsync
**功能**: 非对称加密接口（继承自 ISync）

**主要方法**:
- `Sign(void *outBuffer, size_t &outSize, void *inBuffer, size_t inSize)`: 签名
- `Verify(void *inBuffer, size_t inSize)`: 验证签名

### 4. 实现类

#### 4.1 UnsafeRandom
**功能**: 不安全的伪随机数生成器

**实现方式**:
- 使用多个熵源:
  1. 时间（time()）
  2. 计数器
  3. 全局地址
  4. 栈地址
  5. 堆地址 + 堆未知值
  6. 进程 ID
  7. 线程 ID
  8. 缓冲区未知值
- 使用 `srand()` 和 `rand()` 生成随机数

**使用场景**: 没有可用加密 API 时的后备方案

**主要方法**:
- `Rand(void *buffer, size_t size)`: 生成随机数
- `Rand(size_t size)`: 便捷方法，返回流
- `RandHex(size_t size)`: 生成随机十六进制字符串

#### 4.2 RC4
**功能**: RC4 对称加密算法

**实现**:
- KSA (Key Scheduling Algorithm)
- PRGA (Pseudo-Random Generation Algorithm)

**主要方法**:
- `RC4(void *key, size_t size)`: 构造函数
  - 如果 key 为空，生成随机密钥

- `Encrypt(...)`: 加密
- `Decrypt(...)`: 解密（与加密相同）

**注意**: RC4 已被认为不安全，仅用于兼容性

#### 4.3 SHA256
**功能**: SHA-256 哈希算法

**实现**:
- 完整的 SHA-256 算法实现
- 包含 64 个常量 K[0..63]
- 支持分块更新

**主要方法**:
- `SHA256()`: 构造函数，初始化状态

- `Update(const void *buffer, size_t size)`: 更新哈希
  - 处理 64 字节块
  - 调用 transform()

- `Summary(void *buffer, size_t &size)`: 获取摘要
  - 添加 padding
  - 生成 32 字节哈希

- `sha256(const Stream &data)`: 静态便捷方法

#### 4.4 SHA256_HMAC
**功能**: HMAC-SHA256 算法

**实现**:
- 内层 SHA256 和外层 SHA256
- 使用 I_PAD (0x36) 和 O_PAD (0x5c)
- 块大小: 64 字节

**主要方法**:
- `SHA256_HMAC(const Stream &key)`: 构造函数
  - 如果 key > 64 字节，先哈希
  - XOR PAD 字符

- `Update(const void *buffer, size_t size)`: 更新内层哈希

- `Summary(void *buffer, size_t &size)`: 获取摘要
  - 获取内层哈希
  - 更新外层哈希
  - 返回外层摘要

- `hmac256(const Stream &key, const Stream &data)`: 静态便捷方法

#### 4.5 Crypto
**功能**: 组合加密（RC4 + HMAC-SHA256）

**特性**:
- 格式: `signE | signL | nonce | length | encrypted`
- signE: HMAC of (signE to End)
- signL: HMAC of (nonce + length)
- nonce: 8 字节随机数
- length: 可变长度编码
- encrypted: RC4 加密数据

**常量**:
- `NONCE_BYTES_LENGTH = 8`
- `SIGN_L_BYTES_LENGTH = 8`
- `SIGN_E_BYTES_LENGTH = 8`

**主要方法**:
- `Crypto(const Stream &key, IRandom *randomProvider)`: 构造函数
  - 默认使用 `UnsafeRandomProvider`

- `Encrypt(...)`: 加密
  - 生成 nonce
  - 派生加密密钥: HMAC-SHA256(nonce, key)
  - 派生签名密钥: HMAC-SHA256(key, nonce)
  - RC4 加密
  - 计算 HMAC 签名
  - 组合输出

- `Decrypt(...)`: 解密（未实现）

- `Encrypt(const Stream &in)`: 便捷方法

**使用场景**: 加密配置文件、网络通信加密

## 依赖关系
- `strings.hpp`: 字符串处理
- `base.hpp`: 基础类

## 关键设计决策

1. **接口和实现分离**:
   - `IRandom`, `IHash`, `ISync`, `IAsync` 定义接口
   - `UnsafeRandom`, `RC4`, `SHA256` 等提供实现
   - 便于替换和测试

2. **多种编解码**:
   - Hex: 调试和日志
   - Base64: 传输和存储
   - URL-Safe Base64: URL 参数
   - Length: 自定义协议

3. **加密算法选择**:
   - SHA256: 安全哈希
   - HMAC-SHA256: 消息认证
   - RC4: 简单对称加密（仅兼容性）

4. **随机数生成器**:
   - 多层后备方案
   - 最后使用 `UnsafeRandom`（不安全但可用）

5. **组合加密**:
   - 使用 HMAC 提供认证
   - 使用 RC4 提供加密
   - 防止篡改和伪造

## 注意事项
- RC4 已被认为不安全
- `UnsafeRandom` 不应用于安全敏感场景
- `Crypto::Decrypt` 未实现
- 包含测试注释（"hexlify test pass"）

## 使用示例

### 十六进制编解码
```cpp
// 编码
std::string hex = cpl::codec::Hex::Hexlify(data, size);

// 解码
Stream data = cpl::codec::Hex::UnHexlify(hex.c_str());
```

### Base64 编解码
```cpp
// 标准 Base64
std::string encoded;
cpl::codec::Base64::Base64Encode(encoded, data, size);

Stream decoded;
cpl::codec::Base64::Base64Decode(decoded, encoded.c_str());

// URL 安全 Base64
std::string urlSafe = cpl::codec::Base64::UrlSafeBase64Encode(data, size);
```

### SHA256 哈希
```cpp
// 使用接口
auto hash = cpl::crypto::SHA256();
hash.Update(data, size);
hash.Output(buffer, outSize);

// 静态方法
Stream digest = cpl::crypto::SHA256::sha256(data);
```

### HMAC-SHA256
```cpp
// 使用接口
auto hmac = cpl::crypto::SHA256_HMAC(key);
hmac.Update(data, size);
hmac.Output(buffer, outSize);

// 静态方法
Stream mac = cpl::crypto::SHA256_HMAC::hmac256(key, data);
```

### 随机数生成
```cpp
// 使用接口
auto rng = cpl::crypto::impl::UnsafeRandom();
rng.Rand(buffer, size);

// 静态方法
Stream random = cpl::crypto::impl::UnsafeRandom::Rand(32);
std::string hex = cpl::crypto::impl::UnsafeRandom::RandHex(32);
```

### 组合加密
```cpp
auto crypto = cpl::crypto::impl::Crypto(key);
Stream encrypted = crypto.Encrypt(data);