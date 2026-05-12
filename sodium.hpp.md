# cpl/sodium.hpp - libsodium 加密库封装

## 文件概述
此文件封装了 libsodium 加密库，提供了基于 ED25519 签名和 X25519 加密的通信机制。

## 设计原则
- 使用 libsodium 提供的现代加密算法
- ED25519 用于数字签名
- X25519 用于密钥交换和加密
- 静态链接 libsodium（SODIUM_STATIC）

## 主要功能

### 1. 命名空间结构
```
cpl::sodium
├── 类型定义
│   ├── ESK (ED25519 私钥）
│   ├── ESD (ED25519 种子）
│   ├── EPK (ED25519 公钥）
│   ├── XSK (X25519 私钥）
│   └── XPK (X25519 公钥）
├── Utility (加密工具）
│   ├── Seal() (加密）
│   ├── Open() (解密）
│   ├── Sign() (签名）
│   └── Verify() (验证）
├── Client (客户端）
│   ├── Create() (创建客户端）
│   ├── Encrypt() (加密）
│   └── Decrypt() (解密）
└── Server (服务端）
    ├── Create() (创建服务端）
    ├── Encrypt() (加密）
    └── Decrypt() (解密）
```

### 2. 类型定义

#### 2.1 ED25519 类型（签名）

**ESK (ED25519 Secret Key)**:
```cpp
using ESK = std::array<uint8_t, crypto_sign_SECRETKEYBYTES>;
```
- 大小: 64 字节
- 用途: ED25519 私钥

**ESD (ED25519 Seed)**:
```cpp
using ESD = std::array<uint8_t, crypto_sign_SEEDBYTES>;
```
- 大小: 32 字节
- 用途: ED25519 种子（用于生成密钥对）

**EPK (ED25519 Public Key)**:
```cpp
using EPK = std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>;
```
- 大小: 32 字节
- 用途: ED25519 公钥

#### 2.2 X25519 类型（加密）

**XSK (X25519 Secret Key)**:
```cpp
using XSK = std::array<uint8_t, crypto_box_SECRETKEYBYTES>;
```
- 大小: 32 字节
- 用途: X25519 私钥

**XPK (X25519 Public Key)**:
```cpp
using XPK = std::array<uint8_t, crypto_box_PUBLICKEYBYTES>;
```
- 大小: 32 字节
- 用途: X25519 公钥

### 3. Utility 工具类

#### 3.1 Seal - 加密

**功能**: 使用 X25519 和 XSalsa20-Poly1305 加密数据

**函数签名**:
```cpp
static Stream Seal(
    _In_ const Stream &plaintext,
    _In_ const XPK &publicKeyBob,
    _In_ const XSK &secretKeyAlice
)
```

**参数**:
- `plaintext`: 明文数据
- `publicKeyBob`: Bob 的公钥（接收方）
- `secretKeyAlice`: Alice 的私钥（发送方）

**返回值**: 加密后的数据流

**输出格式**:
```
nonce(24) | ciphertext(?) | mac(16)
```

**加密流程**:
1. 检查明文是否为空
2. 生成随机 Nonce（24 字节）
3. 使用 `crypto_box_easy()` 加密:
   - 通过 X25519 计算共享密钥: `K = H(X25519(alice_sk, bob_pk))`
   - 使用 K 和 nonce 通过 XSalsa20-Poly1305 加密消息
4. 组合 nonce 和密文

**使用示例**:
```cpp
// Alice 加密消息给 Bob
Stream plaintext = {0x01, 0x02, 0x03};
Stream encrypted = sodium::Utility::Seal(plaintext, bob_pubkey, alice_secretkey);
```

#### 3.2 Open - 解密

**功能**: 解密加密的数据

**函数签名**:
```cpp
static Stream Open(
    _In_ const Stream &ciphertext,
    _In_ const XPK &publicKeyAlice,
    _In_ const XSK &secretKeyBob
)
```

**参数**:
- `ciphertext`: 加密的数据流
- `publicKeyAlice`: Alice 的公钥（发送方）
- `secretKeyBob`: Bob 的私钥（接收方）

**返回值**: 明文数据流

**输入格式**:
```
nonce(24) | ciphertext(?) | mac(16)
```

**最小大小**: `crypto_box_NONCEBYTES + crypto_box_MACBYTES` = 40 字节

**解密流程**:
1. 检查密文长度
2. 提取 nonce 和密文
3. 使用 `crypto_box_open_easy()` 解密
4. 返回明文

**使用示例**:
```cpp
// Bob 解密 Alice 的消息
Stream plaintext = sodium::Utility::Open(encrypted, alice_pubkey, bob_secretkey);
```

#### 3.3 Sign - 签名

**功能**: 使用 ED25519 对数据进行签名

**函数签名**:
```cpp
static Stream Sign(
    _In_ const Stream &buffer,
    _In_ const ESK &edSecKey
)
```

**参数**:
- `buffer`: 要签名的数据
- `edSecKey`: ED25519 私钥

**返回值**: 签名数据（64 字节）

**签名大小**: 64 字节

**使用示例**:
```cpp
Stream data = {0x01, 0x02, 0x03};
Stream signature = sodium::Utility::Sign(data, ed25519_secretkey);
```

#### 3.4 Verify - 验证

**功能**: 验证 ED25519 签名

**函数签名**:
```cpp
static bool Verify(
    _In_ const Stream &signature,
    _In_ const Stream &buffer,
    _In_ const EPK &edPubKey
)
```

**参数**:
- `signature`: 签名（64 字节）
- `buffer`: 原始数据
- `edPubKey`: ED25519 公钥

**返回值**:
- true: 验证成功
- false: 验证失败

**使用示例**:
```cpp
bool valid = sodium::Utility::Verify(signature, data, ed25519_pubkey);
if (valid) {
    // 签名有效
}
```

### 4. Client 类

#### 4.1 功能说明

**用途**: 客户端加密通信

**成员变量**:
```cpp
ESD edSeedC{};              // 客户端 ED25519 种子
ESK edSecKeyC{};            // 客户端 ED25519 私钥
EPK edPubKeyC{};            // 客户端 ED25519 公钥
EPK edPubKeyS{};            // 服务端 ED25519 公钥
```

**继承**: `cpl::crypto::stl::ISync`

#### 4.2 Create - 创建客户端

**函数签名**:
```cpp
static std::unique_ptr<Client> Create(
    const ESD &edSeedClient,
    const EPK &edPubKeyServer
)
```

**参数**:
- `edSeedClient`: 客户端 ED25519 种子（32 字节）
- `edPubKeyServer`: 服务端 ED25519 公钥（32 字节）

**返回值**: 客户端智能指针

**初始化流程**:
1. 保存客户端种子和服务端公钥
2. 使用种子生成 ED25519 密钥对
3. 返回客户端实例

**使用示例**:
```cpp
// 生成客户端种子
ESD client_seed = {/* 32 字节 */};
// 服务端公钥（从服务端获取）
EPK server_pubkey = {/* 32 字节 */};

// 创建客户端
auto client = sodium::Client::Create(client_seed, server_pubkey);
```

#### 4.3 Encrypt - 加密（发往服务端）

**功能**: 加密发送给服务端的数据，只有服务端 ED25519 私钥才能解密

**函数签名**:
```cpp
Stream Encrypt(const Stream &in) override
```

**参数**:
- `in`: 明文数据

**返回值**: 加密后的数据流

**输出格式**:
```
signByClientED25519SK(64) | sessionX25519PK(32) | ciphertext
ciphertext [ nonce(24) | [ ClientED25519PK(32) | plaintext(?) ] tag(16) ]
```

**加密流程**:
1. **计算服务端 X25519 公钥**:
   ```cpp
   crypto_sign_ed25519_pk_to_curve25519(serverXpk, edPubKeyS)
   ```

2. **生成会话 X25519 密钥对**:
   ```cpp
   crypto_box_keypair(spk, ssk)
   ```

3. **构建明文**:
   ```
   ClientED25519PK_Plaintext = [客户端 ED25519 公钥] + [原始明文]
   ```

4. **加密**:
   ```cpp
   SessionX25519PK_Ciphertext = Seal(ClientED25519PK_Plaintext, serverXpk, ssk)
   ```

5. **添加会话公钥**:
   ```
   SessionX25519PK_Ciphertext = [会话公钥] + [加密数据]
   ```

6. **签名**:
   ```cpp
   signature = Sign(SessionX25519PK_Ciphertext, edSecKeyC)
   ```

7. **组合最终数据**:
   ```
   out = [签名] + [会话公钥 + 加密数据]
   ```

**使用示例**:
```cpp
Stream plaintext = {0x01, 0x02, 0x03};
Stream encrypted = client->Encrypt(plaintext);
```

#### 4.4 Decrypt - 解密（来自服务端）

**功能**: 解密服务端发送的数据

**函数签名**:
```cpp
Stream Decrypt(const Stream &in) override
```

**参数**:
- `in`: 加密的数据流

**返回值**: 明文数据

**输入格式**:
```
signByServerED25519SK(64) | sessionX25519PK(32) | ciphertext
ciphertext [ nonce(24) | [ plaintext(?) ] tag(16) ]
```

**最小大小**: 
```
64 (签名) + 32 (公钥) + 24 (nonce) + 16 (mac) = 136 字节
```

**解密流程**:
1. **校验签名**:
   - 提取签名（前 64 字节）
   - 提取待验证数据（剩余部分）
   - 使用服务端公钥验证签名

2. **计算客户端 X25519 私钥**:
   ```cpp
   crypto_sign_ed25519_sk_to_curve25519(clientXsk, edSecKeyC)
   ```

3. **提取会话公钥**:
   ```cpp
   memmove(spk, in.data() + 64, 32)
   ```

4. **解密**:
   ```cpp
   plaintext = Open(ciphertext, spk, clientXsk)
   ```

**使用示例**:
```cpp
Stream encrypted = {/* 来自服务端 */};
Stream plaintext = client->Decrypt(encrypted);
```

### 5. Server 类

#### 5.1 功能说明

**用途**: 服务端加密通信

**成员变量**:
```cpp
ESD edSeedS{};                         // 服务端 ED25519 种子
ESK edSecKeyS{};                       // 服务端 ED25519 私钥
EPK edPubKeyS{};                       // 服务端 ED25519 公钥
EPK edPubKeyC{};                       // 客户端 ED25519 公钥
bool ed25519PublicKeyClientInitialized{false};  // 客户端公钥是否已初始化
```

**继承**: `cpl::crypto::stl::ISync`

#### 5.2 Create - 创建服务端

**函数签名**:
```cpp
static std::unique_ptr<Server> Create(const ESD &edSeedS)
```

**参数**:
- `edSeedS`: 服务端 ED25519 种子（32 字节）

**返回值**: 服务端智能指针

**初始化流程**:
1. 保存服务端种子
2. 使用种子生成 ED25519 密钥对
3. 返回服务端实例

**使用示例**:
```cpp
// 生成服务端种子
ESD server_seed = {/* 32 字节 */};

// 创建服务端
auto server = sodium::Server::Create(server_seed);

// 获取服务端公钥，分发给客户端
EPK server_pubkey = /* server->edPubKeyS */;
```

#### 5.3 Decrypt - 解密（来自客户端）

**功能**: 解密客户端发送的数据，只有服务端 ED25519 私钥才能解密

**函数签名**:
```cpp
Stream Decrypt(const Stream &in) override
```

**参数**:
- `in`: 加密的数据流

**返回值**: 明文数据

**输入格式**:
```
signByClientED25519SK(64) | sessionX25519PK(32) | ciphertext
ciphertext [ nonce(24) | [ ClientED25519PK(32) | plaintext(?) ] tag(16) ]
```

**最小大小**:
```
64 (签名) + 32 (公钥) + 24 (nonce) + 32 (客户端公钥) + 16 (mac) = 168 字节
```

**解密流程**:
1. **获取服务端 X25519 私钥**:
   ```cpp
   crypto_sign_ed25519_sk_to_curve25519(serverXsk, edSecKeyS)
   ```

2. **提取会话公钥**:
   ```cpp
   memmove(sessionXpk, in.data() + 64, 32)
   ```

3. **解密**:
   ```cpp
   ClientED25519PK_Plaintext = Open(ciphertext, sessionXpk, serverXsk)
   ```

4. **提取客户端 ED25519 公钥**:
   ```cpp
   memmove(edPubKeyC, ClientED25519PK_Plaintext, 32)
   ed25519PublicKeyClientInitialized = true
   ```

5. **提取明文**:
   ```
   plaintext = ClientED25519PK_Plaintext[32:]  // 跳过客户端公钥
   ```

6. **校验签名**:
   ```cpp
   Verify(signature, toVerify, edPubKeyC)
   ```

**使用示例**:
```cpp
Stream encrypted = {/* 来自客户端 */};
Stream plaintext = server->Decrypt(encrypted);
```

#### 5.4 Encrypt - 加密（发往客户端）

**功能**: 加密发送给客户端的数据，只有客户端 ED25519 私钥才能解密

**函数签名**:
```cpp
Stream Encrypt(const Stream &in) override
```

**参数**:
- `in`: 明文数据

**返回值**: 加密后的数据流

**前置条件**: 客户端公钥已初始化（必须先解密一次客户端的消息）

**输出格式**:
```
signByServerED25519SK(64) | sessionX25519PK(32) | ciphertext
ciphertext [ nonce(24) | [ plaintext(?) ] tag(16) ]
```

**加密流程**:
1. **检查客户端公钥**:
   ```cpp
   if (!ed25519PublicKeyClientInitialized) {
       throw std::system_error("client public key is not initialized");
   }
   ```

2. **计算客户端 X25519 公钥**:
   ```cpp
   crypto_sign_ed25519_pk_to_curve25519(clientXpk, edPubKeyC)
   ```

3. **生成会话 X25519 密钥对**:
   ```cpp
   crypto_box_keypair(spk, ssk)
   ```

4. **加密**:
   ```cpp
   SessionX25519PK_Ciphertext = Seal(in, clientXpk, ssk)
   ```

5. **添加会话公钥**:
   ```
   SessionX25519PK_Ciphertext = [会话公钥] + [加密数据]
   ```

6. **签名**:
   ```cpp
   signature = Sign(SessionX25519PK_Ciphertext, edSecKeyS)
   ```

7. **组合最终数据**:
   ```
   out = [签名] + [会话公钥 + 加密数据]
   ```

**使用示例**:
```cpp
Stream plaintext = {0x01, 0x02, 0x03};
Stream encrypted = server->Encrypt(plaintext);
```

## 依赖关系
- `base.hpp`: 基础定义
- `strings.hpp`: 字符串处理
- `crypto_stl.hpp`: 加密接口
- `vendor/jedisct1/libsodium/sodium.h`: libsodium 库

## 加密算法

### ED25519
- **类型**: 椭圆曲线签名算法
- **密钥大小**: 公钥 32 字节，私钥 64 字节
- **签名大小**: 64 字节
- **用途**: 数字签名

### X25519
- **类型**: 椭圆曲线 Diffie-Hellman 密钥交换
- **密钥大小**: 公钥 32 字节，私钥 32 字节
- **用途**: 密钥交换

### XSalsa20-Poly1305
- **类型**: 对称加密
- **Nonce 大小**: 24 字节
- **MAC 大小**: 16 字节
- **用途**: 数据加密

## 通信流程

### 初始化阶段
```
1. 服务端创建（Server::Create）
   - 生成服务端 ED25519 密钥对
   - 发布服务端 ED25519 公钥

2. 客户端创建（Client::Create）
   - 生成客户端 ED25519 密钥对
   - 导入服务端 ED25519 公钥
```

### 消息交换阶段
```
客户端 -> 服务端
1. 客户端 Encrypt()
   - 生成会话 X25519 密钥对
   - 使用客户端 ED25519 私钥签名
   - 使用会话密钥加密明文
   - 发送给服务端

2. 服务端 Decrypt()
   - 验证客户端签名
   - 解密获取客户端 ED25519 公钥
   - 解密获取明文

服务端 -> 客户端
3. 服务端 Encrypt()
   - 生成会话 X25519 密钥对
   - 使用服务端 ED25519 私钥签名
   - 使用会话密钥加密明文
   - 发送给客户端

4. 客户端 Decrypt()
   - 验证服务端签名
   - 解密获取明文
```

## 安全特性

1. **前向保密**:
   - 每条消息使用新的会话密钥
   - 即使密钥泄露，之前消息仍安全

2. **认证加密**:
   - 使用 ED25519 签名保证身份
   - 使用 Poly1305 MAC 保证完整性

3. **抗重放**:
   - 每次加密使用随机 Nonce
   - Nonce 随密文一起传输

4. **密钥分离**:
   - ED25519 用于签名
   - X25519 用于加密
   - 避免密钥复用

## 注意事项

1. **客户端公钥初始化**:
   - 服务端必须先解密客户端的消息
   - 才能加密发送给客户端的数据

2. **密钥管理**:
   - ED25519 种子必须安全存储
   - 私钥不能泄露
   - 公钥必须通过安全通道交换

3. **错误处理**:
   - 加密失败抛出异常
   - 解密失败抛出异常
   - 签名验证失败抛出异常

4. **线程安全**:
   - Utility 方法是线程安全的
   - Client/Server 实例不建议多线程共享

## 使用示例

### 完整通信示例

```cpp
// 1. 服务端初始化
ESD server_seed = {/* 32 字节随机数 */};
auto server = sodium::Server::Create(server_seed);

// 获取服务端公钥，分发给客户端
EPK server_pubkey = server->GetPublicKey();

// 2. 客户端初始化
ESD client_seed = {/* 32 字节随机数 */};
auto client = sodium::Client::Create(client_seed, server_pubkey);

// 3. 客户端发送消息给服务端
Stream client_msg = {/* 客户端明文 */};
Stream encrypted_to_server = client->Encrypt(client_msg);

// 4. 服务端接收并解密
Stream decrypted_from_client = server->Decrypt(encrypted_to_server);

// 5. 服务端发送消息给客户端
Stream server_msg = {/* 服务端明文 */};
Stream encrypted_to_client = server->Encrypt(server_msg);

// 6. 客户端接收并解密
Stream decrypted_from_server = client->Decrypt(encrypted_to_client);
```

### 直接使用 Utility

```cpp
// 1. 生成 X25519 密钥对
XPK alice_xpk, bob_xpk;
XSK alice_xsk, bob_xsk;
crypto_box_keypair(alice_xpk.data(), alice_xsk.data());
crypto_box_keypair(bob_xpk.data(), bob_xsk.data());

// 2. Alice 加密消息给 Bob
Stream plaintext = {0x01, 0x02, 0x03};
Stream ciphertext = sodium::Utility::Seal(plaintext, bob_xpk, alice_xsk);

// 3. Bob 解密消息
Stream decrypted = sodium::Utility::Open(ciphertext, alice_xpk, bob_xsk);

// 4. 生成 ED25519 密钥对
ESD seed = {/* 32 字节 */};
EPK ed_pubkey;
ESK ed_seckey;
crypto_sign_seed_keypair(ed_pubkey.data(), ed_seckey.data(), seed.data());

// 5. 签名
Stream signature = sodium::Utility::Sign(plaintext, ed_seckey);

// 6. 验证签名
bool valid = sodium::Utility::Verify(signature, plaintext, ed_pubkey);
```

## 关键设计决策

1. **双重加密机制**:
   - ED25519 保证身份认证
   - X25519 保证前向保密

2. **会话密钥**:
   - 每条消息使用不同的会话密钥
   - 前向保密

3. **签名优先**:
   - 签名在加密之前
   - 保证不可伪造

4. **公钥传输**:
   - 客户端公钥通过加密传输
   - 服务端公钥通过安全通道发布