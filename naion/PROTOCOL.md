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

两个方向使用相同的外层包布局：

```text
signature(64) | session_x25519_public_key(32) | nonce(24) | mac(16) | ciphertext(variable)
```

字段含义：

- `signature`：Ed25519 detached signature，签名覆盖它之后的全部内容。
- `session_x25519_public_key`：当前包的一次性 X25519 公钥。
- `nonce`：24 字节 XChaCha20-Poly1305-IETF nonce。
- `mac`：16 字节 Poly1305 认证标签。
- `ciphertext`：加密后的 CSM 明文。

`session_x25519_public_key` 同时会作为 AEAD associated data 传入，因此它既被 AEAD tag 认证，也被 detached signature 认证。

固定外层开销：

```text
64 + 32 + 24 + 16 = 136 bytes
```

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
   `session_x25519_public_key || nonce || mac || ciphertext`
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
6. 解密 `nonce || mac || ciphertext`：
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
   `session_x25519_public_key || nonce || mac || ciphertext`
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
7. 解密 `nonce || mac || ciphertext`：
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

## 大小预算

UDP 包预算固定为 1024 字节。

外层固定开销：

```text
136 bytes
```

Client -> Server 方向额外携带 Client 公钥：

```text
32 bytes
```

最大 application payload：

- Client -> Server：`1024 - 136 - 32 = 856 bytes`
- Server -> Client：`1024 - 136 = 888 bytes`

实现中使用的参考常量：

- `NAION_CSM_MAX_UDP_DATAGRAM_BYTES = 1024`
- `NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES = 856`
- `NAION_CSM_MAX_SERVER_PAYLOAD_BYTES = 888`

超过方向性 payload 上限的数据不应该通过这个 UDP 包格式发送。

## 校验规则

接收方应拒绝以下情况：

- 总包大小小于该方向的最小预期大小。
- 签名验证失败。
- AEAD 解密失败。
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
4. 后续按上方 CSM 包格式通信（sig|xpk|nonce|mac|ciphertext）
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
- 相同的 UDP 大小预算。

## 本协议不包含的内容

本文档不定义：

- 应用层消息类型。
- 协议版本元数据。
- 时间戳或重放拒绝策略。
- 多 Client 的 Server session table 行为。
- HTTP、HTTPS 或 raw UDP socket 等传输绑定方式。

这些都属于 CSM 之上的服务侧或应用侧策略。

