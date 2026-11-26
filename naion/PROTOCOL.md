# Naion CSM 协议

本文档描述以下实现共同遵循的运行时包协议：

- `naion.h`（CSM + CSM-CA，原 `csm.h` 已合并入 naion）
- `csm.py`
- `csm.go`

CSM 是一个小型客户端/服务端安全通信层。它只负责身份绑定、包加密、包签名，以及基础的请求/响应密钥发现。协议版本、时间戳、重放拒绝、消息类型、应用层 flags 等更高层元数据，应该放在 CSM 之上的应用 payload 中处理。

CSM 有两种部署形态，对应 naion 的 Layer 3 与 Layer 4：

- **CSM（Layer 3）**：Client 预先持有 Server 的 Ed25519 公钥。这是本文档后续描述的基础包协议。
- **CSM-CA（Layer 4）**：Client 只持有一个内置 CA 公钥，通过一次握手从服务端获得经 CA 签名的 Server 公钥（见末尾「CA 握手」一节），握手后即复用 Layer 3 的包格式。

## 概览

信任模型：

- Client 持有 Server 的 Ed25519 公钥（CSM-CA 下改为持有 CA 公钥，握手后获得 Server 公钥）。
- Server 在收到有效 Client 包之前，不知道 Client 的公钥。
- 第一个有效 Client 包会在加密明文中携带 Client 的 Ed25519 公钥。
- 之后 Server 可以使用这个 Client 身份加密响应包。

密码构件：

- 身份/签名：Ed25519 detached signature
- 密钥交换：X25519
- 密钥派生：X25519 共享密钥经过 HChaCha20
- Payload 加密：XChaCha20-Poly1305-IETF
- AEAD 附加认证数据：当前包的 `session_x25519_public_key`

## 包布局

两个方向使用相同的外层包布局。布局由 nonce 模式决定（见「nonce 模式」一节）。

随机模式（`nonce_mode != 0`，nonce 随包传输）：

```text
signature(64) | session_x25519_public_key(32) | nonce(24) | mac(16) | ciphertext(variable)
```

派生模式（`nonce_mode = 0`，也称为压缩模式，包内没有 nonce 字段）：

```text
signature(64) | session_x25519_public_key(32) | mac(16) | ciphertext(variable)
```

字段含义：

- `signature`：Ed25519 detached signature，签名覆盖它之后的全部内容。
- `session_x25519_public_key`：当前包的一次性 X25519 公钥。
- `nonce`：24 字节 XChaCha20-Poly1305-IETF nonce。只有随机模式包含这个字段。
- `mac`：16 字节 Poly1305 认证标签。
- `ciphertext`：加密后的 CSM 明文。

`session_x25519_public_key` 同时会作为 AEAD associated data 传入，因此它既被 AEAD tag 认证，也被 detached signature 认证。

固定外层开销：

```text
随机模式：64 + 32 + 24 + 16 = 136 bytes
派生模式：64 + 32 + 16      = 112 bytes
```

接收方必须按照与发送方约定的 nonce 模式解析包。包本身不携带模式标记。

## 加密前明文布局

### Client -> Server

```text
client_ed25519_public_key(32) | application_payload(variable)
```

### Server -> Client

```text
application_payload(variable)
```

这种方向不对称是有意设计：

- Client 已经从配置中知道 Server 公钥。
- Server 从第一个解密成功的 Client 包中学习 Client 公钥。
- 因此 Server 响应包不需要再次携带 Client 公钥。

## 加密流程

### Client Encrypt

1. 将 Server Ed25519 公钥转换为 X25519 公钥。
2. 为当前包生成一组临时 X25519 keypair。
3. 构造明文：
   `client_ed25519_public_key || payload`
4. 派生共享密钥：
   `X25519(session_x25519_secret_key, server_x25519_public_key)`
5. 使用 HChaCha20 派生 AEAD key。
6. 使用 XChaCha20-Poly1305-IETF 加密明文：
   `aad = session_x25519_public_key`
7. 构造 body：
   `session_x25519_public_key || [nonce ||] mac || ciphertext`（`nonce ||` 只存在于随机模式）
8. 使用 Client Ed25519 私钥签名 body。
9. 输出最终包：
   `signature || body`

### Server Decrypt

1. 将包拆分为 `signature` 和 `body`。
2. 从 `body` 中读取 `session_x25519_public_key`。
3. 将 Server Ed25519 私钥转换为 X25519 私钥。
4. 派生共享密钥：
   `X25519(server_x25519_secret_key, session_x25519_public_key)`
5. 使用 HChaCha20 派生 AEAD key。
6. 解密 `[nonce ||] mac || ciphertext`（nonce 字段只存在于随机模式）：
   `aad = session_x25519_public_key`
7. 从解密后的明文中读取 `client_ed25519_public_key`。
8. 使用 Client Ed25519 公钥验证 body 的 detached signature。
9. 保存该 Client 公钥，用于后续响应。
10. 返回剩余的 application payload。

### Server Encrypt

1. 确认已经从之前的 Client 包中学习到 Client 公钥。
2. 将已保存的 Client Ed25519 公钥转换为 X25519 公钥。
3. 为当前包生成一组临时 X25519 keypair。
4. 派生共享密钥：
   `X25519(session_x25519_secret_key, client_x25519_public_key)`
5. 使用 HChaCha20 派生 AEAD key。
6. 使用 XChaCha20-Poly1305-IETF 加密 payload：
   `aad = session_x25519_public_key`
7. 构造 body：
   `session_x25519_public_key || [nonce ||] mac || ciphertext`（`nonce ||` 只存在于随机模式）
8. 使用 Server Ed25519 私钥签名 body。
9. 输出最终包：
   `signature || body`

### Client Decrypt

1. 将包拆分为 `signature` 和 `body`。
2. 使用 Server Ed25519 公钥验证 body 的 detached signature。
3. 从 `body` 中读取 `session_x25519_public_key`。
4. 将 Client Ed25519 私钥转换为 X25519 私钥。
5. 派生共享密钥：
   `X25519(client_x25519_secret_key, session_x25519_public_key)`
6. 使用 HChaCha20 派生 AEAD key。
7. 解密 `[nonce ||] mac || ciphertext`（nonce 字段只存在于随机模式）：
   `aad = session_x25519_public_key`
8. 返回 application payload。

## 方向性身份规则

Client 侧：

- 发送包之前必须知道 Server Ed25519 公钥。
- 出站包使用 Client Ed25519 私钥签名。
- 入站包使用 Server Ed25519 公钥验签。

Server 侧：

- 第一个入站包之前不需要知道 Client 公钥。
- 从第一个解密成功的 Client 包中学习 Client Ed25519 公钥。
- 使用该包中携带的 Client Ed25519 公钥验证入站 Client 包。
- 使用已保存的 Client 公钥加密后续响应。

## nonce 模式

每个 CSM 包都使用一次性的 X25519 密钥对，因此每个包的共享密钥都是新的。nonce 模式决定 nonce 的来源：

- **派生模式**（`NAION_CSM_NONCE_DERIVED`，值为 0，是默认值）。nonce 由本包的共享密钥派生，并且不随包传输。这种模式也称为压缩模式，包里没有 nonce 字段。
- **随机模式**（`NAION_CSM_NONCE_RANDOM`，值为 1）。nonce 是 24 字节随机数，并且随包传输。

派生模式下的计算方式如下。`shared` 是 `X25519(self_x25519_secret_key, peer_x25519_public_key)` 的 32 字节原始输出。

```text
ekey  = HChaCha20(key = shared, in = 0x00 × 16)                    // AEAD key
nonce = HChaCha20(key = shared, in = "naion.csm.nonce.")[0 .. 23]  // 前 24 字节
```

`"naion.csm.nonce."` 是 16 字节的 ASCII 字符串。两次 HChaCha20 的输入不同，所以 nonce 不泄露 `ekey` 的信息。随机模式下 `ekey` 的计算方式相同，nonce 则取自随机源。

约束：

- 发送方和接收方必须使用同一个 nonce 模式。如果两端的模式不同，那么 AEAD 验证失败，接收方返回解密错误。
- 包里没有模式标记。通信双方必须在带外约定模式。
- CSM-SESSION（`naion_csm_sess_*`）在握手后使用固定的会话密钥，所以 CSM-SESSION 必须始终使用随机 nonce。nonce 模式不适用于 CSM-SESSION。

API 约定（C 实现）：

- 带 `_ex` 后缀的函数多一个 `int nonce_mode` 参数，例如 `naion_csm_client_encrypt_ex()`。
- 不带 `_ex` 后缀的原函数保留原签名，并且等价于 `nonce_mode = NAION_CSM_NONCE_DERIVED`。
- CSM-CA 的加解密函数和计算包大小的函数遵循相同的约定。
- 实现中使用的宏：`NAION_CSM_NONCE_FIELD_BYTES(mode)`、`NAION_CSM_PACKET_OVERHEAD_EX(mode)`、`NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES_EX(mode)`、`NAION_CSM_MAX_SERVER_PAYLOAD_BYTES_EX(mode)`。

## 大小预算

UDP 包预算固定为 1024 字节。

| | 随机模式 | 派生模式（压缩模式） |
|---|---|---|
| 外层固定开销 | 136 bytes | 112 bytes |
| Client -> Server 方向额外的 Client 公钥 | 32 bytes | 32 bytes |
| Client -> Server 最大 application payload | `1024 - 136 - 32 = 856 bytes` | `1024 - 112 - 32 = 880 bytes` |
| Server -> Client 最大 application payload | `1024 - 136 = 888 bytes` | `1024 - 112 = 912 bytes` |

实现中使用的参考常量：

- 随机模式：`NAION_CSM_PACKET_OVERHEAD = 136`、`NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES = 856`、`NAION_CSM_MAX_SERVER_PAYLOAD_BYTES = 888`。
- 派生模式：`NAION_CSM_COMPACT_PACKET_OVERHEAD = 112`、`NAION_CSM_COMPACT_MAX_CLIENT_PAYLOAD_BYTES = 880`、`NAION_CSM_COMPACT_MAX_SERVER_PAYLOAD_BYTES = 912`。
- `NAION_CSM_MAX_UDP_DATAGRAM_BYTES = 1024`。

超过方向性 payload 上限的数据不应该通过这个 UDP 包格式发送。

## 测试向量

下面的向量由固定的输入产生。三个实现（`naion.h`、`csm.go`、`csm.py`）都必须逐字节复现这些结果。

输入：

```text
Client Ed25519 seed = 32 字节，每个字节是 0x01
Server Ed25519 seed = 32 字节，每个字节是 0x02
随机源              = 每次调用都把整个缓冲区填成 0x5A
payload             = 16 字节：00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
```

期望输出：

```text
server_ed_pk (32 bytes) = 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
client_ed_pk (32 bytes) = 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c

# nonce_mode = 0（派生模式，压缩模式）
c2s_compact (160 bytes) = 676f9b6a8cdfa755841a467b2709b5b3cbe4249665bca1f30922237678aedf6e714b553b0f27fc4dfff8b1d0ca68d00c8333eaf1c12abf1ce72e8b85bac0100ab0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c1f639c2334f0089bcb0a7d5da997c2016e84fa6a6df29e24e4aa8d4b394b9b980e0e11f7bf5b7f4fbce4435ba5d50e4fd432f7121f2b9b97d7fa83a0431d3b5d
s2c_compact (128 bytes) = 0c4c0249692bc2852662efe431530e03f94237b589ad2c53ed758101eca18f2c139ef42b1437b77c775dfd59e93dd1dcc48f44547cd631f4fcbc31f266dc6708b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c86345b488d8ff6fdec5f09c153d04202f0db445448e1f320021649bb4d717143

# nonce_mode != 0（随机模式）
c2s_random (184 bytes) = 987f308ffecb2c195194c1f81b1c78db264b1d47073a009853869bb1f5ccfe84048317f7173b61bc57a91e6bf194221ebcbb6166dc6ccd83d7916ea7246dbd0cb0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5afbae93e8305a23e3a08f3f6d4cec110a364beb3d7e7c30a008b53895752c490bf48fab438eb09a71e7584cb6b0b7d9f0f6907d93f078090e34e100884d11ca5f
s2c_random (152 bytes) = 82b009cb900f66e2004ad257680ed111c586517cffcaae8cf9c0c020b628c5eac8700f4af571821ddf8442e7358f60b221f782aa5b8a6a3f2f2392a0a4365808b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af77b969223bfbf7eb79137cb22dad8aba92a7a99f5d08ba76c494c33b0d09b6f
```

注意：

- 随机模式的两个向量与引入 nonce 模式之前的 `naion.h` 产生的包完全相同。随机模式与旧实现保持兼容。
- 同一方向的两个向量使用相同的一次性 X25519 密钥对，因为固定的随机源每次都返回相同的字节。

## 校验规则

接收方应拒绝以下情况：

- 总包大小小于该方向的最小预期大小。
- 签名验证失败。
- AEAD 解密失败。如果发送方和接收方的 nonce 模式不一致，那么 AEAD 验证也会失败。
- Client 包明文太短，无法包含 `client_ed25519_public_key`。
- Server 在尚未学习到 Client 公钥前尝试加密响应。
- 明文超过该方向的 UDP payload 预算。

## CA 握手（CSM-CA / Layer 4）

CSM-CA 允许 Client 不预先持有 Server 公钥，而是只内置一个 CA 的 Ed25519 公钥。Client 在通信前先完成一次握手，从服务端拿到经 CA 签名的 Server 公钥证书，验签通过后即按上方 Layer 3 的包格式通信。

服务端的密钥持有证明不需要额外字段——后续能正确解密 Client 发来的 CSM 包并加密响应，本身就证明了服务端持有对应私钥。

### 证书结构（96 字节）

```text
server_ed25519_public_key(32) | ca_signature(64)
```

CA 离线使用其 Ed25519 私钥对 `server_ed25519_public_key` 这 32 字节做 detached 签名，得到 `ca_signature`。证书预置在服务端（`naion_csm_ca_server` 的 `ca_signature` 字段）。

### 握手流程

```text
1. Client -> Server：发起请求（传输层负责，不含密码学载荷）
2. Server -> Client：m1 = server_ed_pk(32) | ca_signature(64)   （96 字节，明文）
3. Client 验证：
   Ed25519_verify_detached(ca_signature, server_ed_pk, 32, ca_ed_pk)
   通过后存储 server_ed_pk，标记 server_key_verified = 1
4. 后续按上方 CSM 包格式通信。包的布局由双方约定的 nonce 模式决定（见「nonce 模式」）。
```

握手响应固定为 96 字节（`NAION_CSM_CA_CERT_BYTES`）。验签失败时 Client 不得进入后续通信。

### 握手后的通信

握手成功后，CSM-CA 的 encrypt/decrypt 直接复用 Layer 3 的包格式与方向性规则（Client 出站包明文仍携带 Client 公钥，Server 从首个解密成功的包中学习 Client 公钥）。其 API（`naion_csm_ca_client_*` / `naion_csm_ca_server_*`）在内部委托给同一套 CSM 加解密实现。

## 跨语言一致性

`naion.h`、`csm.py`、`csm.go` 应实现同一协议：

- 相同的外层包布局。
- 相同的方向性明文布局。
- 相同的 AEAD associated data。
- 相同的 detached signature 覆盖范围。
- 相同的 nonce 模式语义，以及相同的派生 nonce 计算方式。
- 相同的 UDP 大小预算。
- 都逐字节复现「测试向量」一节里的结果。

## 本协议不包含的内容

本文档不定义：

- 应用层消息类型。
- 协议版本元数据。
- 时间戳或重放拒绝策略。
- 多 Client 的 Server session table 行为。
- HTTP、HTTPS 或 raw UDP socket 等传输绑定方式。

这些都属于 CSM 之上的服务侧或应用侧策略。

