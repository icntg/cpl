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

---

## 一、协议规范

### 1.1 握手流程

```
Client (持有 ca_ed_pk)                       Server (持有 ed_sk, ca_signature)
  |                                                    |
  | 1. 生成 client-session 密钥对:                       |
  |    client_session_xsk, client_session_xpk            |
  |    = X25519_keypair()                               |
  |                                                    |
  |--- CLIENT_HELLO ---------------------------------->|
  |    client_session_xpk (32 bytes)                    |
  |                                                    |
  |                           2. 验证 client_session_xpk |
  |                              (非全零，合法 X25519 点) |
  |                                                    |
  |                           3. 生成 server-session 密钥对:
  |                              server_session_xsk,
  |                              server_session_xpk
  |                              = X25519_keypair()
  |                                                    |
  |                           4. 构造 Server 响应:       |
  |                              cert = server_session_xpk(32)
  |                                   || sign(server_session_xpk, server_ed_sk)(64)
  |                                   || server_ed_pk(32)
  |                                   || ca_signature(64)
  |                              (共 192 bytes)
  |                                                    |
  |                           5. 计算会话共享密钥:        |
  |                              session_shared_key =
  |                              X25519(server_session_xsk,
  |                                     client_session_xpk)
  |                                                    |
  |<-- SERVER_RESPONSE (192 bytes) --------------------|
  |                                                    |
  | 6. 解析 cert，验证:                                  |
  |    a) Ed25519_verify_detached(                      |
  |         ca_signature, server_ed_pk, ca_ed_pk)       |
  |    b) Ed25519_verify_detached(                      |
  |         sig, server_session_xpk, server_ed_pk)      |
  |    任一失败 → 中止                                   |
  |                                                    |
  | 7. 计算会话共享密钥:                                  |
  |    session_shared_key =                             |
  |    X25519(client_session_xsk,                       |
  |           server_session_xpk)                       |
  |                                                    |
  | 8. 存储 server_ed_pk (用于后续 CSM 签名验证)         |
  |                                                    |
  |<====== CSM 加密通信 (使用会话密钥) =================>|
```

### 1.2 握手后 CSM 数据包格式（不变）

外部包格式与 Layer 3/4 完全一致：

```
signature(64) | session_x25519_pk(32) | nonce(24) | mac(16) | ciphertext(variable)
```

内部明文布局也保持不变：

```
Client→Server: client_ed25519_pk(32) || application_payload
Server→Client: application_payload
```

### 1.3 会话密钥在 CSM 中的使用方式

**关键变更**：每包临时-静态 DH 中的"静态密钥"替换为"会话临时密钥"。

| 方向 | 当前 Layer 3/4 | Layer 5 |
|---|---|---|
| Client 加密 | DH(client_ephemeral_sk, **server_static_xpk**) | DH(client_ephemeral_sk, **server_session_xpk**) |
| Server 解密 | DH(**server_static_xsk**, client_ephemeral_pk) | DH(**server_session_xsk**, client_ephemeral_pk) |
| Server 加密 | DH(server_ephemeral_sk, **client_static_xpk**) | DH(server_ephemeral_sk, **client_session_xpk**) |
| Client 解密 | DH(**client_static_xsk**, server_ephemeral_pk) | DH(**client_session_xsk**, server_ephemeral_pk) |

每包仍生成临时 X25519 密钥对，保留会话内的每包前向保密。会话密钥仅在握手时生成一次，会话结束后丢弃。

### 1.4 常量

```
NAION_CSM_SESS_CLIENT_HELLO_BYTES    = 32
NAION_CSM_SESS_SERVER_RESPONSE_BYTES = 192  (= 32 + 64 + 32 + 64)
NAION_CSM_SESS_SESSION_XSK_BYTES     = 32
NAION_CSM_SESS_SESSION_XPK_BYTES     = 32
NAION_CSM_SESS_SESSION_SHARED_BYTES  = 32
```

UDP 预算约束不变（≤1024 字节），握手响应 192 字节远低于此限制。

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

    // === 从 CSM 数据包学到的客户端身份 ===
    uint8_t client_ed_public_key[naion_sign_ed25519_PUBLICKEYBYTES]; // 32
    int client_key_verified;
} naion_csm_sess_server;
// 总大小: 32+64+32 + 64 + 32+32+32+32 + 32+int ≈ 352 bytes
```

### 2.3 Server 会话表（DoS 防护）

Server 端需要维护活跃会话表。建议的会话表条目结构（应用层管理，非库内实现）：

```
session_id (可选，由 client_session_xpk 标识)
├── client_session_xpk[32]     -- 会话标识符
├── server_session_xsk[32]     -- 服务端临时私钥 (敏感)
├── server_session_xpk[32]     -- 服务端临时公钥 (可重新计算)
├── session_shared_key[32]     -- 预计算 DH 结果 (敏感)
├── client_ed_public_key[32]   -- 学到的客户端身份 (初始为空)
├── client_key_verified: bool  -- 是否已验证客户端签名
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
// Client 生成会话临时密钥对，输出 client_session_xpk 发送给 Server
// out_client_hello: 32 bytes (client_session_xpk)
int naion_csm_sess_client_hello(
    naion_csm_sess_client *client,
    uint8_t out_client_hello[NAION_CSM_SESS_CLIENT_HELLO_BYTES]);

// === Step 2: Server Response ===
// Server 收到 client_session_xpk 后，生成自己的会话密钥对并构造响应
// client_hello: 32 bytes (从 Client 收到的 client_session_xpk)
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
// === 大小查询 (委托给 CSM 内部常量，与 Layer 3/4 相同) ===
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
// 加密前置条件: client_key_verified != 0
// 解密无前置条件 (首次解密即为学习客户端身份)
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

### 4.2 Server 响应构造

```
m1[0..31]   = server_session_xpk
m1[32..95]  = Ed25519_sign_detached(server_session_xpk, server_ed_sk)
m1[96..127] = server_ed_pk
m1[128..191]= ca_signature  (预置的 CA 对 server_ed_pk 的签名)
```

### 4.3 证书链验证（Client 端）

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

### 4.4 会话共享密钥派生

```
session_shared_key = X25519(my_session_xsk, peer_session_xpk)
// 32 字节 Curve25519 标量乘法结果
// Client: X25519(client_session_xsk, server_session_xpk)
// Server: X25519(server_session_xsk, client_session_xpk)
```

注意：`session_shared_key` 不直接用作 AEAD 密钥，而是作为预计算密钥 (`beforenm` 结果) 替代原 CSM 中的 `box_beforenm` 输出。

### 4.5 每包加密（内部复用 CSM）

```
// 以 Client 加密为例:
// 原 CSM:
//   beforenm_k = X25519(server_static_xsk, server_static_xpk)  // 实际上是 DH
//                → HChaCha20 → aead_key
// Layer 5:
//   beforenm_k = X25519(per_packet_ephemeral_sk, server_session_xpk)
//                → HChaCha20 → aead_key
// 注: server_session_xpk 是会话临时公钥，不是长期静态公钥
```

实际上，当前 CSM 的 `naion_csm_internal_seal` 内部调用 `naion_box_curve25519xchacha20poly1305_beforenm`，后者执行 DH + HChaCha20。Layer 5 的实现需要绕过 Ed25519→X25519 的身份密钥转换步骤，直接使用原生的 X25519 会话密钥。

**实现路径选择**：

- **方案 1**：在 `naion_csm_sess_*_encrypt/decrypt` 中手动执行 DH + seal/open，不委托给 CSM 内部函数（约 100 行重复代码）
- **方案 2**：重构 CSM 内部 `_seal` / `_open` 函数，接受已预计算的 `beforenm_k` 而非身份密钥（改动 CSM 内部但不改变外部行为）
- **方案 3**：创建临时的 `naion_csm_client`/`naion_csm_server` 结构体，将 X25519 会话密钥"伪装"成 Ed25519→X25519 转换结果填入

**推荐方案 2**：在 CSM 内部新增 `_naion_csm_internal_seal_with_x25519` / `_naion_csm_internal_open_with_x25519` 变体，接受原始 X25519 公钥/私钥而非 Ed25519 密钥。

### 4.6 Ed25519 签名仍使用身份密钥

重要：CSM 数据包上的 Ed25519 分离签名**仍使用长期身份密钥**（不是会话密钥）。会话密钥仅用于 X25519 DH 部分，身份密钥用于签名认证。两者的生命周期不同：

| 密钥 | 用途 | 生命周期 | 泄露后果 |
|---|---|---|---|
| Ed25519 身份密钥 | 数据包签名 + 证书签名 | 长期 (月/年) | 可冒充身份 |
| X25519 会话密钥 | 每包 DH | 会话 (秒/分) | 仅本会话可解密 |
| X25519 每包临时密钥 | 每包 DH 的一方 | 单包 | 仅本包可解密 |

---

## 五、安全分析

### 5.1 前向保密对比

| 场景 | Layer 3/4 | Layer 5 |
|---|---|---|
| Server 长期密钥泄露 → 历史数据解密 | ❌ 全部可解密 | ✅ 不可解密 (会话密钥已丢弃) |
| Server 长期密钥泄露 → 未来数据解密 | ❌ 可主动解密 | ✅ 不可解密 (需先完成新会话握手) |
| Server 长期密钥泄露 → 主动冒充 | ❌ 可冒充 | ✅ 不可冒充 (除非也攻破 CA) |
| Client 长期密钥泄露 → 历史 Server→Client 解密 | ❌ 全部可解密 | ❌ 同样可解密 (Client 会话密钥为临时，但 Client 长期密钥用于签名验证，不用于 DH) |

**注**：Layer 5 在 Client→Server 方向提供了严格的前向保密。Server→Client 方向：若 Client 长期密钥泄露，攻击者仍可通过密钥转换恢复 Client 的 X25519 私钥并解密历史 Server→Client 数据包（因为 DH 虽然用的是会话临时密钥，但... 等等）。

**修正**：Layer 5 中 Server→Client 方向使用的是 `DH(server_ephemeral_sk, client_session_xpk)`，而 `client_session_xpk` 是会话临时密钥。Client 长期密钥泄露不影响会话密钥。所以 Layer 5 在**两个方向**都提供完全前向保密。

### 5.2 安全属性总结

| 属性 | Layer 3/4 | Layer 5 | 说明 |
|---|---|---|---|
| 身份认证 | ✅ | ✅ | Ed25519 分离签名 + CA 证书链 |
| 每包前向保密 | ✅ 部分 | ✅ 完全 | Layer 5: 每包临时 × 会话临时 DH |
| 会话前向保密 | ❌ | ✅ | Server 长期密钥泄露 ≠ 历史会话解密 |
| 密钥泄露伪装抗性 | ❌ | ✅ | 无长期密钥参与 DH |
| 重放保护 | ❌ | ❌ | 均明确排除，由应用层处理 |
| 前向安全 (0-RTT) | N/A | N/A | 握手需 1-RTT |

### 5.3 威胁模型

| 攻击 | Layer 5 是否抵抗 | 说明 |
|---|---|---|
| 被动窃听 | ✅ | AEAD 加密 |
| 主动 MITM (握手阶段) | ✅ | CA + Server 签名链 |
| 主动 MITM (通信阶段) | ✅ | Ed25519 签名 + AEAD |
| Server 长期密钥事后泄露 | ✅ | 会话密钥已丢弃 |
| Server 长期密钥在线泄露 + 主动 MITM | ❌ | 攻击者可生成假会话密钥并签名 |
| CA 密钥泄露 | ❌ | 整个信任链崩溃 |
| DoS (握手洪水) | ⚠️ 缓解 | 会话表上限 + 超时 |
| 重放攻击 | ❌ | 协议不处理 |

---

## 六、DoS 防护设计

### 6.1 攻击面

1. **CPU**：X25519 密钥生成 ~30μs/次。百万级请求才消耗显著 CPU——不是主要瓶颈。
2. **内存**：每会话状态 ~352 bytes (服务端结构体)。10 万恶意半开会话 ≈ 34 MB——可控但需设限。
3. **Ed25519 签名**：`naion_csm_sess_server_handshake` 中包含一次 Ed25519 签名（对 server_session_xpk）。Ed25519 签名 ~50μs，与 X25519 密钥生成同量级。

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
Client                              Server
  |                                    |
  |--- CLIENT_HELLO (xpk) ----------->|
  |                                    | 生成 cookie:
  |                                    | cookie = BLAKE2b(server_secret ||
  |                                    |                  client_addr ||
  |                                    |                  client_xpk)
  |<-- COOKIE (cookie, 32 bytes) -----| (无状态，不分配会话)
  |                                    |
  |--- CLIENT_HELLO (xpk) + cookie -->|
  |                                    | 验证 cookie:
  |                                    |   重新计算并比较
  |                                    |   通过 → 分配会话 → 签名响应
  |<-- SERVER_RESPONSE (192 bytes) ---|
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
| 握手机制 | 静态证书 (96B) | 会话临时证书链 (192B) |
| DH 参与方 | 每包临时 × 长期静态 | 每包临时 × 会话临时 |
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
- 相同的 CLIENT_HELLO 格式 (32 bytes X25519 pk)
- 相同的 SERVER_RESPONSE 格式 (192 bytes 证书链)
- 相同的会话密钥派生方式 (X25519 DH)
- 相同的 CSM 数据包复用方式 (会话密钥替换静态密钥)

---

## 九、实现清单（仅供参考，不在本次范围内）

1. `naion.h` 中新增 `#if NAION_LAYER_CSM_SESSION` 区块
2. 新增结构体 `naion_csm_sess_client` / `naion_csm_sess_server`
3. 新增内部辅助函数：接受原始 X25519 密钥的 `_seal` / `_open` 变体
4. 实现握手机制 (client_hello / server_handshake / client_finish)
5. 实现加密/解密函数（委托给内部辅助函数）
6. 实现会话表管理（计数器 + 超时）
7. 可选：Cookie DoS 防护
8. 测试向量 (固定种子 + 固定临时密钥 → 确定性输出)
9. 跨语言互操作测试

---

## 十、参考

- Noise Protocol Framework — `Noise_IK` 模式
- DTLS 1.3 — HelloVerifyRequest cookie 机制
- Signal Protocol — X3DH (临时-临时-临时 DH)
- PROTOCOL.md — 当前 CSM/CSM-CA 协议规范
- naion.h — 当前实现
