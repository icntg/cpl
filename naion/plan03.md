# Naion Layer 5 — CSM-Session 设计文档

> 状态：设计阶段（不实现）
> 日期：2026-06-26
> 依赖：Layer 1-4 (CSM-CA)

---

## 〇、动机

### 当前 CSM/CSM-CA (Layer 3/4) 的前向保密局限

CSM 每数据包使用临时-静态 DH：

```
Client→Server: DH(client_ephemeral_sk, server_static_xpk)
Server→Client: DH(server_ephemeral_sk, client_static_xpk)
```

其中 `server_static_xpk` / `client_static_xpk` 由 Ed25519 长期身份密钥派生。DH 的一方始终是**长期静态密钥**。

**威胁模型**：Server 长期 Ed25519 密钥在未来某个时刻泄露，则：
- 攻击者可解密**所有历史** Client→Server 方向数据包（因为 client 的临时公钥就在包体中）
- 攻击者可**主动冒充**服务端（持有签名密钥 + 解密密钥）

Layer 5 的目标：**即使 Server 长期密钥泄露，历史会话也不可解密**（完全前向保密）。

### 设计原则

1. **新增而非替换**：Layer 5 构建在 Layer 4 (CSM-CA) 之上，原 CSM-CA 保持不变
2. **最小改动**：复用现有 CSM 内部加密路径，只替换 DH 参与方的密钥来源
3. **临时-临时 DH**：双方均使用会话级临时 X25519 密钥对参与 DH
4. **证书链验证**：CA → server_ed_pk → server_session_xpk 三级签名链
5. **握手互知身份**：Client 在 CLIENT_HELLO 中暴露身份+持有证明，握手结束时双方互知对方 Ed25519 公钥，不再依赖 decrypt-then-verify

---

## 一、协议规范

### 1.1 握手流程

```
Client (持有 ed_sk, ca_ed_pk)            Server (持有 ed_sk, ca_signature)
  |                                                    |
  | 1. 生成 client-session 密钥对:                       |
  |    client_session_xsk, client_session_xpk            |
  |    = X25519_keypair()                               |
  |                                                    |
  | 2. 签名 client_session_xpk:                          |
  |    client_hello_sig =                               |
  |      Ed25519_sign_detached(                         |
  |        client_session_xpk, client_ed_sk)            |
  |                                                    |
  |--- CLIENT_HELLO (128 bytes) ----------------------->|
  |    client_session_xpk(32)                           |
  |    client_ed_pk(32)                                 |
  |    client_hello_sig(64)                             |
  |                                                    |
  |                           3. 验证 client_session_xpk |
  |                              (非全零)               |
  |                                                    |
  |                           4. 验证客户端身份持有:      |
  |                              Ed25519_verify_detached(|
  |                                sig = client_hello_sig,
  |                                msg = client_session_xpk,
  |                                pk  = client_ed_pk)  |
  |                              失败 → 拒绝，不分配会话  |
  |                                                    |
  |                           5. 生成 server-session 密钥对:
  |                              server_session_xsk,
  |                              server_session_xpk
  |                              = X25519_keypair()
  |                                                    |
  |                           6. 构造 Server 响应:       |
  |                              cert = server_session_xpk(32)
  |                                   || sign(server_session_xpk, server_ed_sk)(64)
  |                                   || server_ed_pk(32)
  |                                   || ca_signature(64)
  |                              (共 192 bytes)
  |                                                    |
  |                           7. 计算会话共享密钥:        |
  |                              session_shared_key =
  |                              X25519(server_session_xsk,
  |                                     client_session_xpk)
  |                                                    |
  |                           8. 存储 client_ed_pk       |
  |                              (用于后续数据包验签)     |
  |                                                    |
  |<-- SERVER_RESPONSE (192 bytes) --------------------|
  |                                                    |
  | 9. 解析 cert，验证:                                  |
  |    a) Ed25519_verify_detached(                      |
  |         ca_signature, server_ed_pk, ca_ed_pk)       |
  |    b) Ed25519_verify_detached(                      |
  |         sig, server_session_xpk, server_ed_pk)      |
  |    任一失败 → 中止                                   |
  |                                                    |
  | 10. 计算会话共享密钥:                                 |
  |     session_shared_key =                            |
  |     X25519(client_session_xsk,                      |
  |            server_session_xpk)                      |
  |                                                    |
  | 11. 存储 server_ed_pk (用于后续数据包验签)            |
  |                                                    |
  |<====== CSM 加密通信 (使用会话密钥) =================>|
  |  握手后双方互知身份：                                 |
  |  - Client 已知 server_ed_pk (CA 证书链验证)          |
  |  - Server 已知 client_ed_pk (CLIENT_HELLO 签名验证)  |
  |  数据包解密：先验签 → 再 AEAD 解密（两端对称）        |
```

### 1.2 握手后数据包格式

**与 Layer 3/4 不同**——去掉了每包临时 X25519 公钥字段。同时因为握手阶段 Server 已学到 `client_ed_pk`，Client→Server 明文不再需要携带 client 身份公钥：

```
Layer 3/4:  signature(64) | pk_e(32) | nonce(24) | mac(16) | ciphertext(variable)  ← 136 开销
Layer 5:    signature(64) |           nonce(24) | mac(16) | ciphertext(variable)  ← 104 开销
```

节省 32 字节包开销 + 32 字节 Client→Server 明文 = 两端均净增 64 字节 payload。

内部明文布局——**握手后两端对称**（Server 在握手中已学到 client_ed_pk）：

```
Client→Server: application_payload
Server→Client: application_payload
```

对比 Layer 3/4，Client→Server 方向不再在明文中嵌入 `client_ed25519_pk(32)`。

### 1.3 会话密钥的使用方式

**核心变更**：不再有每包临时 DH。会话共享密钥通过 HChaCha20 派生为会话 AEAD 密钥后，整个会话期间复用。每包仅生成新 nonce。

```
握手阶段 (一次):
  session_shared = X25519(my_session_xsk, peer_session_xpk)   // 32 bytes raw DH
  session_aead_key = HChaCha20(session_shared, zero_nonce)    // 32 bytes

每包加密:
  nonce = random(24)                                           // 每包新 nonce
  body = nonce || mac || ciphertext
  sig = Ed25519_sign(identity_sk, body)
  packet = sig || body

每包解密（两端对称——握手后双方互知对方 Ed25519 公钥）：
  sig = packet[0..63]
  body = packet[64..]
  Ed25519_verify(sig, body, peer_ed_pk)   // 先验签，失败直接丢弃
  AEAD_decrypt(body, session_aead_key)     // 再解密
```

| | Layer 3/4（每包） | Layer 5（每包） |
|---|---|---|
| DH 计算 | 每包一次 X25519 | **无**（握手时一次） |
| AEAD 密钥来源 | 每包 DH → HChaCha20 | 会话共享密钥 → HChaCha20（一次） |
| Nonce | 每包随机 24B | 每包随机 24B |
| 前向保密粒度 | 每包 | 每会话 |
| 解密顺序 | Server 端先解密后验签（因为不知道 client_ed_pk） | **两端都是先验签后解密** |

### 1.4 常量和 Payload 预算

```c
// 握手
#define NAION_CSM_SESS_CLIENT_HELLO_BYTES    128  // = 32 + 32 + 64 (xpk + ed_pk + sig)
#define NAION_CSM_SESS_SERVER_RESPONSE_BYTES 192  // = 32 + 64 + 32 + 64

// 会话密钥
#define NAION_CSM_SESS_SESSION_XSK_BYTES     32
#define NAION_CSM_SESS_SESSION_XPK_BYTES     32
#define NAION_CSM_SESS_SESSION_SHARED_BYTES  32
#define NAION_CSM_SESS_SESSION_AEAD_KEY_BYTES 32

// 数据包开销 (sig + nonce + mac)
#define NAION_CSM_SESS_PACKET_OVERHEAD \
    (naion_sign_ed25519_BYTES + naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX)
// = 64 + 24 + 16 = 104

// Payload 预算 (UDP ≤ 1024)
// 握手后两端对称——明文均为纯 application_payload（无身份字段）
#define NAION_CSM_SESS_MAX_UDP_DATAGRAM_BYTES    1024
#define NAION_CSM_SESS_MAX_CLIENT_PAYLOAD_BYTES  (1024 - 104)  // = 920
#define NAION_CSM_SESS_MAX_SERVER_PAYLOAD_BYTES  (1024 - 104)  // = 920
```

与 Layer 3/4 对比：

| | Layer 3/4 | Layer 5 | 差异 |
|---|---|---|---|
| 包开销 | 136 B | 104 B | **-32 B** |
| Client→Server payload | 856 B | 920 B | **+64 B** |
| Server→Client payload | 888 B | 920 B | **+32 B** |

Client→Server 多得的 64 字节来自：去掉 `pk_e`(32) 省 32 字节包开销 + 去掉明文中的 `client_ed_pk`(32) 省 32 字节 payload。

---

## 二、数据结构

### 2.1 Client 结构体

```c
typedef struct naion_csm_sess_client {
    // === 身份密钥 (Ed25519) ===
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];           // 32
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES]; // 64
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; // 32

    // === CA 信任锚 ===
    uint8_t ca_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; // 32

    // === 从握手学到的 Server 信息 ===
    uint8_t server_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; // 32

    // === 会话临时密钥 (X25519) ===
    uint8_t client_session_xsk[32];  // 客户端会话临时私钥
    uint8_t client_session_xpk[32];  // 客户端会话临时公钥
    uint8_t server_session_xpk[32];  // 服务端会话临时公钥 (从握手学到)
    uint8_t session_shared_key[32];  // X25519 DH 结果 (预计算)

    // === 状态标志 ===
    int handshake_complete;  // 0 = 未完成, 1 = 完成
} naion_csm_sess_client;
// 总大小: 32+64+32 + 32 + 32 + 32+32+32+32 + int ≈ 320 bytes
```

### 2.2 Server 结构体

```c
typedef struct naion_csm_sess_server {
    // === 身份密钥 (Ed25519) ===
    uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES];           // 32
    uint8_t ed_secret_key[naion_sign_ed25519_SECRETKEYBYTES]; // 64
    uint8_t ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; // 32

    // === CA 预置签名 ===
    uint8_t ca_signature[naion_sign_ed25519_BYTES];          // 64

    // === 会话临时密钥 (X25519) ===
    uint8_t server_session_xsk[32];   // 服务端会话临时私钥
    uint8_t server_session_xpk[32];   // 服务端会话临时公钥
    uint8_t client_session_xpk[32];   // 客户端会话临时公钥 (从 CLIENT_HELLO 学到)
    uint8_t session_shared_key[32];   // X25519 DH 结果 (预计算)

    // === 客户端身份 (握手阶段验证) ===
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; // 32
    // client_ed_public_key 在 server_handshake 中通过 CLIENT_HELLO 签名
    // 验证后设置，后续 encrypt/decrypt 直接使用——不再是"从数据包学到"
} naion_csm_sess_server;
// 总大小: 32+64+32 + 64 + 32+32+32+32 + 32 ≈ 352 bytes
```

### 2.3 Server 会话表（DoS 防护）

Server 端需要维护活跃会话表。建议的会话表条目结构（应用层管理，非库内实现）：

```
session_id (可选，由 client_session_xpk 标识)
├── client_session_xpk[32]     -- 会话标识符
├── server_session_xsk[32]     -- 服务端临时私钥 (敏感)
├── server_session_xpk[32]     -- 服务端临时公钥 (可重新计算)
├── session_shared_key[32]     -- 预计算 DH 结果 (敏感)
├── client_ed_public_key[32]   -- 客户端身份 (握手阶段已验证)
├── created_at: timestamp      -- 创建时间 (用于超时清理)
└── last_activity: timestamp   -- 最后活跃时间 (用于空闲清理)
```

配置参数建议：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `max_sessions` | 1024 | 最大并发会话数 |
| `handshake_timeout` | 30s | 握手未完成则清理 |
| `idle_timeout` | 300s | 无数据包通信则清理 |
| `max_sessions_per_ip` | 8 | 每源 IP 最大会话数 (可选) |

---

## 三、API 设计

### 3.1 创建与销毁

```c
// 客户端创建。ca_ed_pk: CA Ed25519 公钥 (32 bytes)
int naion_csm_sess_client_create(
    naion_csm_sess_client *client,
    const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ca_ed_pk[naion_sign_ed25519_PUBLICKEYBYTES]);

// 服务端创建。ca_signature: 预置 CA 签名 (64 bytes)
int naion_csm_sess_server_create(
    naion_csm_sess_server *server,
    const uint8_t ed_seed[naion_sign_ed25519_SEEDBYTES],
    const uint8_t ca_signature[naion_sign_ed25519_BYTES]);

// 安全擦除
void naion_csm_sess_client_wipe(naion_csm_sess_client *client);
void naion_csm_sess_server_wipe(naion_csm_sess_server *server);
```

### 3.2 握手 API

```c
// === Step 1: Client Hello ===
// Client 生成会话临时密钥对，签名 session_xpk，构造 CLIENT_HELLO
// out_client_hello: 128 bytes (client_session_xpk || client_ed_pk || sig)
int naion_csm_sess_client_hello(
    naion_csm_sess_client *client,
    uint8_t out_client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES]);

// === Step 2: Server Response ===
// Server 收到 CLIENT_HELLO 后：
//   1. 验证 client_session_xpk 合法性
//   2. 验证 Ed25519 签名（client_hello_sig, client_session_xpk, client_ed_pk）
//   3. 失败 → NAION_CSM_ERR_VERIFY_FAILED（不分配会话状态）
//   4. 通过 → 生成自己的会话密钥对，构造 SERVER_RESPONSE，
//      计算会话共享密钥，存储 client_ed_pk
// client_hello: 128 bytes
// out_m1: 192 bytes (server_session_xpk || sig || server_ed_pk || ca_sig)
int naion_csm_sess_server_handshake(
    naion_csm_sess_server *server,
    const uint8_t client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES],
    uint8_t out_m1[NAION_CSM_SESS_SERVER_RESPONSE_BYTES],
    size_t out_cap, size_t *out_len);

// === Step 3: Client Finish ===
// Client 验证 Server 响应的证书链，计算会话共享密钥
// m1: 192 bytes (Server 响应)
int naion_csm_sess_client_finish(
    naion_csm_sess_client *client,
    const uint8_t *m1, size_t m1_len);
```

### 3.3 加密/解密 API

```c
// === 大小查询 ===
size_t naion_csm_sess_client_encrypt_size(size_t plaintext_len);
size_t naion_csm_sess_client_decrypt_max_plaintext_size(size_t packet_len);
size_t naion_csm_sess_server_encrypt_size(size_t plaintext_len);
size_t naion_csm_sess_server_decrypt_max_plaintext_size(size_t packet_len);

// === Client 加密/解密 ===
// 前置条件: handshake_complete == 1
int naion_csm_sess_client_encrypt(
    naion_csm_sess_client *client,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

int naion_csm_sess_client_decrypt(
    const naion_csm_sess_client *client,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// === Server 加密/解密 ===
// 前置条件: client_ed_public_key 已在 handshake 中设置
// 解密: 先验签（用 client_ed_pk）→ 再 AEAD 解密（用 session_aead_key）
//       与 Layer 3/4 不同——不再依赖 decrypt-then-verify
int naion_csm_sess_server_encrypt(
    const naion_csm_sess_server *server,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

int naion_csm_sess_server_decrypt(
    naion_csm_sess_server *server,
    const uint8_t *packet, size_t packet_len,
    uint8_t *out, size_t out_cap, size_t *out_len);
```

### 3.4 错误码

复用 CSM 错误码 `NAION_CSM_ERR_*`。Layer 5 不引入新的错误码。新增错误条件：

| 条件 | 错误码 |
|---|---|
| 握手未完成时调用 encrypt/decrypt | `NAION_CSM_ERR_STATE` |
| Client hello 公钥为全零/非法点 | `NAION_CSM_ERR_INVALID_ARGUMENT` |
| Client hello 大小 ≠ 128 | `NAION_CSM_ERR_INVALID_ARGUMENT` |
| Client hello 签名验证失败 | `NAION_CSM_ERR_VERIFY_FAILED` |
| Server 响应大小 ≠ 192 | `NAION_CSM_ERR_INVALID_ARGUMENT` |
| CA 签名验证失败 | `NAION_CSM_ERR_VERIFY_FAILED` |
| Server 会话密钥签名验证失败 | `NAION_CSM_ERR_VERIFY_FAILED` |
| 随机数生成失败 | `NAION_CSM_ERR_RANDOM_PROVIDER` |

---

## 四、密码学细节

### 4.1 会话密钥对生成

```
client_session_xsk = random(32)          // 32 字节安全随机数
client_session_xpk = X25519_base(client_session_xsk)
// 同 server 端
```

X25519 私钥使用标准 clamping（`naion_box_keypair` 内部已完成）。

### 4.2 CLIENT_HELLO 构造与验证

**Client 构造：**

```
hello[0..31]   = client_session_xpk
hello[32..63]  = client_ed_pk
hello[64..127] = Ed25519_sign_detached(client_session_xpk, client_ed_sk)
```

**Server 验证（在 `server_handshake` 中）：**

```
// Step 1: 检查 client_session_xpk 合法性
if (is_zero(client_session_xpk)) → ABORT

// Step 2: 验证客户端身份持有
ret = Ed25519_verify_detached(
    sig       = hello[64..127],   // client_hello_sig
    message   = hello[0..31],     // client_session_xpk
    msg_len   = 32,
    public_key = hello[32..63]    // client_ed_pk
);
if (ret != 0) → ABORT              // 握手阶段拒绝，不分配会话

// Step 3: 存储 client_ed_pk 和 client_session_xpk
// 后续数据包验签直接用已存储的 client_ed_pk
```

签名覆盖 `client_session_xpk` 实现了两个绑定：
- **身份绑定**：证明 CLIENT_HELLO 发送者持有 `client_ed_sk`
- **会话绑定**：将 client 身份与本次会话临时密钥绑定，防止攻击者替换 `client_session_xpk`

### 4.3 Server 响应构造

```
m1[0..31]   = server_session_xpk
m1[32..95]  = Ed25519_sign_detached(server_session_xpk, server_ed_sk)
m1[96..127] = server_ed_pk
m1[128..191]= ca_signature  (预置的 CA 对 server_ed_pk 的签名)
```

### 4.4 证书链验证（Client 端，在 `client_finish` 中）

```
// Step 1: 验 CA → server_ed_pk
ret = Ed25519_verify_detached(
    sig       = m1[128..191],   // ca_signature
    message   = m1[96..127],    // server_ed_pk
    msg_len   = 32,
    public_key = ca_ed_pk
);
if (ret != 0) → ABORT

// Step 2: 验 server_ed_pk → server_session_xpk
ret = Ed25519_verify_detached(
    sig       = m1[32..95],     // server 对 session key 的签名
    message   = m1[0..31],      // server_session_xpk
    msg_len   = 32,
    public_key = server_ed_pk   // 已通过 CA 验证
);
if (ret != 0) → ABORT
```

### 4.5 会话共享密钥派生

```
session_shared = X25519(my_session_xsk, peer_session_xpk)
// 32 字节 Curve25519 标量乘法结果
// Client: X25519(client_session_xsk, server_session_xpk)
// Server: X25519(server_session_xsk, client_session_xpk)
```

**密钥派生**：原始 DH 结果通过 HChaCha20 派生为会话 AEAD 密钥（与 libsodium `crypto_box_beforenm` 一致）：

```
session_aead_key = HChaCha20(key = session_shared, nonce = zero16)
// 32 字节，作为整个会话的 XChaCha20-Poly1305 AEAD 密钥
```

**方向性考虑**：可选派生两个方向独立的 AEAD 密钥：

```
aead_key_c2s = HChaCha20(session_shared, nonce = "C2S\0\0\0\0...")
aead_key_s2c = HChaCha20(session_shared, nonce = "S2C\0\0\0\0...")
```

简化设计可先使用单一 `session_aead_key`，签名已覆盖方向信息。两个方向使用同一密钥 + 不同的随机 nonce 不会产生安全问题（XChaCha20-Poly1305 的 nonce 碰撞概率可忽略）。

### 4.6 每包加密/解密流程

与 Layer 3/4 不同，Layer 5 无需每包 DH。加解密直接使用预派生的 `session_aead_key`。
**两端解密顺序对称**——握手后双方互知对方 Ed25519 公钥，均可先验签后解密。

#### 加密

```
// === Client 加密 ===
nonce = random(24)
aad = NULL / 空                                       // Ed25519 签名已覆盖 body
ct, mac = XChaCha20-Poly1305-IETF_encrypt_detached(
    key    = session_aead_key,
    nonce  = nonce,
    plaintext = app_payload,                          // 不再携带 client_ed_pk
    aad    = aad
)
body = nonce || mac || ct
sig = Ed25519_sign_detached(client_ed_sk, body)
packet = sig || body

// === Server 加密 ===
nonce = random(24)
ct, mac = XChaCha20-Poly1305-IETF_encrypt_detached(
    key    = session_aead_key,
    nonce  = nonce,
    plaintext = app_payload,
    aad    = aad
)
body = nonce || mac || ct
sig = Ed25519_sign_detached(server_ed_sk, body)
packet = sig || body
```

#### 解密（两端对称——先验签，后解密）

```
// === Server 解密 (Client→Server) ===
sig  = packet[0..63]
body = packet[64..]

// Step 1: 先验签（server 在握手阶段已学到 client_ed_pk）
ok = Ed25519_verify_detached(sig, body, client_ed_pk)
// 验签失败 → 直接丢弃，无需尝试 AEAD 解密

// Step 2: AEAD 解密
nonce = body[0..23]
mac   = body[24..39]
ct    = body[40..]
app_payload = XChaCha20-Poly1305-IETF_decrypt_detached(
    key    = session_aead_key,
    nonce  = nonce,
    ciphertext = ct,
    mac    = mac,
    aad    = NULL
)

// === Client 解密 (Server→Client) ===
sig  = packet[0..63]
body = packet[64..]

// Step 1: 先验签（client 在握手阶段已学到 server_ed_pk）
ok = Ed25519_verify_detached(sig, body, server_ed_pk)

// Step 2: AEAD 解密
// ...（同上）
```

**与 Layer 3/4 解密顺序的关键区别：**

| | Layer 3/4 Server decrypt | Layer 5 Server decrypt |
|---|---|---|
| 验签前是否知道 client_ed_pk？ | ❌（从首个数据包明文学到） | ✅（CLIENT_HELLO 签名验证时学到） |
| 解密顺序 | AEAD 解密 → 验签 | **验签 → AEAD 解密** |
| 伪造包处理 | 先做 AEAD 解密（浪费 CPU）后验签失败 | 验签失败直接丢弃（节省 AEAD 计算） |

**与 Layer 3/4 内部实现对比：**

| 步骤 | Layer 3/4 | Layer 5 |
|---|---|---|
| 生成每包临时密钥 | ✅ `X25519_keypair()` | ❌ 跳过 |
| DH 计算 | ✅ `X25519(sk, pk)` | ❌ 跳过 |
| HChaCha20 派生 | ✅ 每包一次 | ❌ 握手时一次 |
| AEAD 加解密 | ✅ | ✅ 直接使用 `session_aead_key` |
| Ed25519 签名/验签 | ✅ | ✅ 不变 |

Layer 5 加密路径更短：没有 X25519 密钥生成、没有 DH、没有 HChaCha20 派生。只需要一次 AEAD 加密 + 一次 Ed25519 签名。

### 4.7 Nonce 管理

24 字节 (192-bit) 随机 nonce，每包由 RNG provider 生成。192 位随机 nonce 在单会话生命周期内的碰撞概率可忽略（生日界 ~2^96 条消息）。

备选方案：计数器 nonce（从 0 递增），无需 RNG 调用，保证无碰撞。需要在结构体中增加 24 字节计数器字段。当前设计选择随机 nonce 以保持与现有 CSM nonce 生成方式一致。

### 4.8 Ed25519 签名仍使用身份密钥

数据包上的 Ed25519 分离签名**仍使用长期身份密钥**（不是会话密钥）。会话密钥仅用于加密，身份密钥用于签名认证。两者生命周期不同：

| 密钥 | 用途 | 生命周期 | 泄露后果 |
|---|---|---|---|
| Ed25519 身份密钥 | 数据包签名 + 证书签名 | 长期 (月/年) | 可冒充身份 |
| X25519 会话密钥 → AEAD 密钥 | 加解密 | 会话 (秒/分) | 仅本会话可解密 |

---

## 五、安全分析

### 5.1 前向保密对比

| 场景 | Layer 3/4 | Layer 5 |
|---|---|---|
| Server 长期密钥泄露 → 历史数据解密 | ❌ 全部可解密 | ✅ 不可解密 (会话密钥已丢弃) |
| Server 长期密钥泄露 → 未来数据解密 | ❌ 可主动解密 | ✅ 不可解密 (需先完成新会话握手) |
| Server 长期密钥泄露 → 主动冒充 | ❌ 可冒充 | ✅ 不可冒充 (除非也攻破 CA) |
| Client 长期密钥泄露 → 历史数据解密 | ❌ Server→Client 方向可解密 | ✅ **两个方向均不可解密** |
| 会话 AEAD 密钥泄露 → 本会话数据解密 | N/A | ⚠️ 本会话内所有包可解密 |

**分析**：Layer 5 在**两个方向**都提供完全前向保密。因为 DH 双方均为临时会话密钥——`X25519(client_session_xsk, server_session_xpk)`——与长期身份密钥无关。Client 或 Server 长期密钥泄露不影响已结束的会话。

**会话内前向保密**：若 `session_aead_key` 在会话中途泄露（如内存读取），则该会话内所有包（含历史包）均可解密。这是去掉每包临时 DH 的权衡。对此的缓解：
- 会话密钥生命周期短（秒/分钟级），缩短暴露窗口
- 若攻击者已能读取进程内存，通常也能读到明文——会话内 PFS 的实用价值有限

### 5.2 安全属性总结

| 属性 | Layer 3/4 | Layer 5 | 说明 |
|---|---|---|---|
| 身份认证 | ✅ | ✅ | Ed25519 分离签名 + CA 证书链 |
| 握手互知身份 | ❌（Server 从首个数据包学） | ✅（CLIENT_HELLO 签名验证） | Server 握手阶段即知 client_ed_pk |
| 会话前向保密 | ❌ | ✅ | 长期密钥泄露 ≠ 历史会话解密 |
| 会话内每包前向保密 | ✅ | ❌ | 去掉每包临时 DH 的权衡 |
| 密钥泄露伪装抗性 | ❌ | ✅ | 无长期密钥参与加密 |
| 重放保护 | ❌ | ❌ | 均明确排除，由应用层处理 |
| 包开销 | 136 B | 104 B | **节省 32 B/包** |

### 5.3 威胁模型

| 攻击 | Layer 5 是否抵抗 | 说明 |
|---|---|---|
| 被动窃听 | ✅ | AEAD 加密 |
| 主动 MITM (握手阶段) | ✅ | CA + Server 签名链；Client 身份签名防止会话密钥替换 |
| 主动 MITM (通信阶段) | ✅ | Ed25519 签名 + AEAD |
| 握手阶段伪造 client 身份 | ✅ | CLIENT_HELLO 中 client_ed_pk 签名验证拒绝 |
| Server 长期密钥事后泄露 | ✅ | 会话密钥已丢弃 |
| Server 长期密钥在线泄露 + 主动 MITM | ❌ | 攻击者可生成假会话密钥并签名 |
| CA 密钥泄露 | ❌ | 整个信任链崩溃 |
| DoS (握手洪水) | ⚠️ 缓解 | 会话表上限 + 超时；握手签名验证有一定 CPU 成本 |
| 重放攻击 | ❌ | 协议不处理 |

---

## 六、DoS 防护设计

### 6.1 攻击面

1. **CPU**：X25519 密钥生成 ~30μs/次。百万级请求才消耗显著 CPU——不是主要瓶颈。
2. **Ed25519 验签**：`server_handshake` 中需验证 client 对 `client_session_xpk` 的 Ed25519 签名（~50μs）。攻击者发送无效 CLIENT_HELLO 也能触发验签——但验签失败时**不分配会话状态**，仅消耗 CPU。
3. **内存**：每会话状态 ~352 bytes (服务端结构体)。10 万恶意半开会话 ≈ 34 MB——可控但需设限。
4. **Ed25519 签名**：`server_handshake` 中 Server 对 `server_session_xpk` 的签名（~50μs）仅在 client 验签通过后才执行——不会被无效请求触发。

### 6.2 基本防护（内置）

```c
// 建议配置 (通过 #define 或运行时 API 设置)
#define NAION_CSM_SESS_MAX_SESSIONS      1024   // 全局最大会话数
#define NAION_CSM_SESS_HANDSHAKE_TIMEOUT 30     // 秒，握手未完成超时
#define NAION_CSM_SESS_IDLE_TIMEOUT      300    // 秒，会话空闲超时
```

库内部维护一个简单的会话计数器。达到 `MAX_SESSIONS` 后拒绝新的 `server_handshake` 调用（返回错误码 `NAION_CSM_ERR_STATE` 或新增 `NAION_CSM_ERR_RESOURCE_EXHAUSTED`）。

超时清理由调用者驱动：每次调用 `server_encrypt`/`server_decrypt` 时，库内部检查并清理过期会话。

### 6.3 增强防护（可选，Cookie 机制）

类似 DTLS HelloVerifyRequest：

```
Client                                    Server
  |                                         |
  |--- CLIENT_HELLO (xpk + ed_pk + sig) -->|
  |                                         | 生成 cookie:
  |                                         | cookie = BLAKE2b(server_secret ||
  |                                         |                  client_addr ||
  |                                         |                  client_xpk)
  |<-- COOKIE (cookie, 32 bytes) ----------| (无状态，不分配会话)
  |                                         |
  |--- CLIENT_HELLO (128 bytes) + cookie ->|
  |                                         | 验证 cookie:
  |                                         |   重新计算并比较
  |                                         |   通过 → 验 client 签名 → 分配会话
  |<-- SERVER_RESPONSE (192 bytes) --------|
```

Cookie 机制多增加 1 个往返，但彻底消除了状态耗尽攻击面。建议通过 `NAION_CSM_SESS_COOKIE` 编译时宏控制。

### 6.4 推荐策略

**分层防御**：
- 默认：基本防护（会话上限 + 超时）
- 高威胁环境：启用 Cookie 机制
- 应用层：额外限速（token bucket per IP）

---

## 七、与各层的集成

### 7.1 层依赖关系

```
Layer 1 (NAION_LAYER_SYMM)
  ↓
Layer 2 (NAION_LAYER_AEAD)
  ↓
Layer 3 (NAION_LAYER_CSM)
  ↓
Layer 4 (NAION_LAYER_CSM_CA)
  ↓
Layer 5 (NAION_LAYER_CSM_SESSION)  ← 新增
```

启用 Layer 5 自动启用 Layer 1-4。Layer 4 (CSM-CA) 独立可用。

### 7.2 宏控制

```c
#ifndef NAION_LAYER_CSM_SESSION
#define NAION_LAYER_CSM_SESSION 1   // 默认启用
#endif

#if NAION_LAYER_CSM_SESSION && !NAION_LAYER_CSM_CA
#undef  NAION_LAYER_CSM_CA
#define NAION_LAYER_CSM_CA 1        // 强制启用 Layer 4
#endif
```

### 7.3 API 命名前缀

```
naion_csm_sess_*
```

### 7.4 与 Layer 4 的对比

| 特性 | Layer 4 (CSM-CA) | Layer 5 (CSM-Session) |
|---|---|---|
| 握手机制 | 静态证书 (96B) | 双向身份验证 (CLIENT_HELLO 128B + SERVER_RESPONSE 192B) |
| Client 身份暴露时机 | 首个数据包（明文嵌入） | **CLIENT_HELLO**（签名验证） |
| 加密模型 | 每包临时 × 长期静态 DH | 会话共享密钥 → AEAD（无每包 DH） |
| 包格式 | `sig\|pk_e\|nonce\|mac\|ct` | `sig\|nonce\|mac\|ct` |
| 包开销 | 136 B | **104 B** |
| C→S 明文携带 client_ed_pk | ✅ 每包 32B | ❌ 握手后已掌握 |
| 解密顺序 (Server) | 先解密后验签 | **先验签后解密** |
| Server 状态 | 无状态 | 有状态 (会话表) |
| 完全前向保密 | ❌ | ✅ |
| 握手往返 | 0.5-RTT (纯响应) | 1-RTT |
| DoS 面 | 低 | 中 (需会话管理) |
| 适用场景 | 低并发、嵌入式、无状态 | 高安全需求、互联网通信 |

---

## 八、跨语言一致性

协议级变更需要在 3 个实现中保持一致：

| 实现 | 文件 | 状态 |
|---|---|---|
| C | `naion.h` | 本文档设计目标 |
| Python | `csm.py` (待确认) | 待同步 |
| Go | `csm.go` (待确认) | 待同步 |

跨语言一致性要求：
- 相同的 CLIENT_HELLO 格式 (128 bytes: `session_xpk(32) | ed_pk(32) | sig(64)`)
- 相同的 SERVER_RESPONSE 格式 (192 bytes 证书链)
- 相同的会话密钥派生方式 (X25519 DH → HChaCha20)
- 相同的 CSM 数据包格式 (`sig | nonce | mac | ct`，104 开销)
- 握手后两端明文均为纯 application_payload（不再携带 client_ed_pk）

---

## 九、实现清单（仅供参考，不在本次范围内）

1. `naion.h` 中新增 `#if NAION_LAYER_CSM_SESSION` 区块
2. 新增结构体 `naion_csm_sess_client` / `naion_csm_sess_server`
3. 新增内部辅助函数：`_naion_csm_sess_seal` / `_naion_csm_sess_open`（仅 AEAD，无 DH）
4. 实现握手机制：
   - `client_hello`: 生成会话 X25519 密钥对 + 对 `session_xpk` 做 Ed25519 签名
   - `server_handshake`: 验证 client 签名 → 生成服务端会话密钥对 → 构造证书链响应
   - `client_finish`: 验证 CA 证书链 → 计算会话密钥
5. 实现加密/解密函数（直接调用 session AEAD + Ed25519 签名，**两端均为先验签后解密**）
6. 实现会话表管理（计数器 + 超时）
7. 可选：Cookie DoS 防护
8. 可选：Nonce 计数器模式（替代随机 nonce）
9. 测试向量 (固定种子 + 固定 nonce → 确定性输出)
10. 跨语言互操作测试

---

## 十、参考

- Noise Protocol Framework — `Noise_IK` 模式
- DTLS 1.3 — HelloVerifyRequest cookie 机制
- Signal Protocol — X3DH (临时-临时-临时 DH)
- PROTOCOL.md — 当前 CSM/CSM-CA 协议规范
- naion.h — 当前实现
