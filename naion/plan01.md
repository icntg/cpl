# Naion 重构计划

## 背景

当前 naion 目录包含两个独立的单头文件库：`naion.h`（加密原语，4478行）和 `csm.h`（客户端/服务端安全通信，735行）。两者遵循 STB 风格的单头文件模式。

问题：
- 两个独立模块但 CSM 严重依赖 naion，分开维护增加复杂度
- XSalsa20 总是编译进去，无法裁剪
- CSM 使用 `malloc`/`free` 分配临时缓冲区，缺少统一的错误清理机制
- 缺少基于 CA 证书的握手功能——客户端必须预先知道服务端公钥

## 目标

1. **单模块**：只有一个 `naion.h`（可选 `naion.c`），CSM 功能合并进去
2. **四层可裁剪**：通过宏控制，默认全开
3. **XSalsa20 可选**：由 `NAION_XSALSA20` 宏控制，默认不编译。启用后保留运行时动态切换
4. **libsodium 兼容**：AEAD IETF、secretbox、box 三套 API 均与 libsodium 兼容

---

## 四层架构

```
Layer 1 (NAION_LAYER_SYMM)     — XChaCha20 流加密 + BLAKE2b 哈希 + 伪随机数
    ↓ 依赖
Layer 2 (NAION_LAYER_AEAD)     — XChaCha20-Poly1305 AEAD IETF (detached)
                                 + secretbox 封装 (mac||enc, 兼容 libsodium)
    ↓ 依赖
Layer 3 (NAION_LAYER_CSM)      — Ed25519 + X25519 + Box + CSM (客户端持有服务端公钥)
    ↓ 依赖
Layer 4 (NAION_LAYER_CSM_CA)   — CSM + CA 证书握手 (客户端仅持有 CA 公钥)
```

附加宏（独立于四层）：
```
NAION_XSALSA20 (默认 0)        — 启用 XSalsa20/Salsa20 内部实现
                                 + XSalsa20 secretbox/box + 运行时调度(gUseXChaCha20)
```

宏依赖关系：
```c
// 四层默认全开
#ifndef NAION_LAYER_SYMM
#define NAION_LAYER_SYMM 1
#endif
#ifndef NAION_LAYER_AEAD
#define NAION_LAYER_AEAD 1
#endif
#ifndef NAION_LAYER_CSM
#define NAION_LAYER_CSM 1
#endif
#ifndef NAION_LAYER_CSM_CA
#define NAION_LAYER_CSM_CA 1
#endif

// XSalsa20 默认关闭
#ifndef NAION_XSALSA20
#define NAION_XSALSA20 0
#endif

// 上层强制启用下层
#if NAION_LAYER_AEAD && !NAION_LAYER_SYMM
#undef  NAION_LAYER_SYMM
#define NAION_LAYER_SYMM 1
#endif
#if NAION_LAYER_CSM && !NAION_LAYER_AEAD
#undef  NAION_LAYER_AEAD
#define NAION_LAYER_AEAD 1
#endif
#if NAION_LAYER_CSM_CA && !NAION_LAYER_CSM
#undef  NAION_LAYER_CSM
#define NAION_LAYER_CSM 1
#endif
```

---

## 各层详细设计

### Layer 1 — NAION_LAYER_SYMM（对称加密 + 哈希 + 随机数）

**公共 API：**
- `naion_init()`, `naion_memzero()`, `naion_memcmp()`, `naion_is_zero()`
- `naion_set_random_provider()`, `naion_get_random_provider()`
- `naion_generichash_*` — BLAKE2b 哈希（一次性 + 增量）
- `naion_stream_xchacha20_*` — XChaCha20 流加密（keystream, xor, xor_ic）

**内部实现：**
- BLAKE2b 参考实现
- ChaCha20/HChaCha20/XChaCha20 核心
- 随机数提供者（Windows/Linux/POSIX 三层回退）

### Layer 2 — NAION_LAYER_AEAD（认证加密）

**公共 API：**

```c
// === 底层 AEAD (detached) ===
// 输出：nonce(24) + ciphertext + mac(16) 三者分离
// 与 libsodium crypto_aead_xchacha20poly1305_ietf_* 兼容
naion_aead_xchacha20poly1305_ietf_encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, k)
naion_aead_xchacha20poly1305_ietf_decrypt(m, &mlen, nsec, c, clen, ad, adlen, npub, k)
naion_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, &maclen, m, mlen, ad, adlen, nsec, npub, k)
naion_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)

// === 封装层 1: enc || mac (IETF 线格式) ===
// encrypt 已经是 enc||mac，与 libsodium 兼容

// === 封装层 2: mac || enc (secretbox 线格式) ===
// 与 libsodium crypto_secretbox_xchacha20poly1305_* 兼容
naion_secretbox_xchacha20poly1305_easy(c, m, mlen, n, k)       // → mac(16) || enc
naion_secretbox_xchacha20poly1305_open_easy(m, c, clen, n, k)
naion_secretbox_xchacha20poly1305_detached(c, mac, m, mlen, n, k)
naion_secretbox_xchacha20poly1305_open_detached(m, c, mac, clen, n, k)
```

**内部实现：**
- Poly1305 MAC 计算
- `verify16` 恒定时间比较
- `xchacha20_derive_subkey_nonce` — HChaCha20 子密钥派生
- AEAD 加密/解密组合与分离实现
- secretbox 基于 `box_curve25519xchacha20poly1305_easy_afternm`（与现有逻辑一致）

### Layer 3 — NAION_LAYER_CSM（Ed25519 + Box + CSM）

**公共 API：**

```c
// Ed25519 签名
naion_sign_ed25519_keypair(pk, sk)
naion_sign_ed25519_seed_keypair(pk, sk, seed)
naion_sign_ed25519(sm, &smlen, m, mlen, sk)
naion_sign_ed25519_open(m, &mlen, sm, smlen, pk)
naion_sign_ed25519_detached(sig, &siglen, m, mlen, sk)
naion_sign_ed25519_verify_detached(sig, m, mlen, pk)
naion_sign_ed25519_sk_to_seed / sk_to_pk / pk_to_curve25519 / sk_to_curve25519

// X25519 标量乘法
naion_scalarmult_curve25519(q, n, p)
naion_scalarmult_curve25519_base(q, n)

// KX 密钥交换
naion_kx_keypair / seed_keypair / client_session_keys / server_session_keys

// Box (XChaCha20-Poly1305)
// 与 libsodium crypto_box_curve25519xchacha20poly1305_* 兼容
naion_box_curve25519xchacha20poly1305_keypair / seed_keypair / beforenm
naion_box_curve25519xchacha20poly1305_easy / open_easy
naion_box_curve25519xchacha20poly1305_easy_afternm / open_easy_afternm
naion_box_curve25519xchacha20poly1305_seal / seal_open

// 通用 box 分发 (若 NAION_XSALSA20=0 则直接委托给 xchacha20)
naion_box_keypair / seed_keypair / beforenm
naion_box_easy / open_easy / easy_afternm / open_easy_afternm
naion_box_seal / seal_open
naion_box_seedbytes / publickeybytes / secretkeybytes / beforenmbytes / noncebytes / macbytes / sealbytes

// CSM 客户端/服务端 (原 csm.h)
naion_csm_init()
naion_csm_client_create / naion_csm_server_create
naion_csm_client_encrypt / naion_csm_client_decrypt
naion_csm_server_encrypt / naion_csm_server_decrypt
naion_csm_client_wipe / naion_csm_server_wipe
naion_csm_client_encrypt_size / ...decrypt_max_plaintext_size
naion_csm_server_encrypt_size / ...decrypt_max_plaintext_size
```

**内部实现：**
- SHA-512（Ed25519 → X25519 密钥转换用）
- X25519 域算术（TweetNaCl 风格）
- Ed25519 签名/验证/密钥转换
- Box XChaCha20 实现
- CSM 内部辅助函数（`naion_csm_internal_seal/open/sign/verify/randombytes`）
- 堆分配允许，使用 goto 标签统一清理：`__ERROR__` 释放错误路径资源，`__FREE__` 释放正常退出资源，返回前统一 `memzero` + `free`

#### XSalsa20 可选支持

当 `NAION_XSALSA20=1` 时：
- 编译 Salsa20 内部实现（`salsa20_quarterround/block`, `hsalsa20`, `xsalsa20_xor_ic`）
- 编译 XSalsa20 secretbox（`naion_secretbox_xsalsa20poly1305_*`）
- 编译 XSalsa20 box（`naion_box_curve25519xsalsa20poly1305_*`）
- `gUseXChaCha20` 全局变量和运行时调度生效——程序可动态选择 XChaCha20 或 XSalsa20

当 `NAION_XSALSA20=0`（默认）时：
- 上述所有 XSalsa20 代码都不编译
- `naion_box_*` 通用函数直接委托给 XChaCha20 版本（无运行时开销）
- `gUseXChaCha20` 变为编译时常量 1

### Layer 4 — NAION_LAYER_CSM_CA（CA 证书握手）

**设计思路：**

Layer 4 与 Layer 3 的核心区别是：客户端不预先持有服务端公钥，需要通过握手从服务端获取。握手只需一步——服务端返回经 CA 签名的证书。客户端用内置 CA 公钥验签后，即可使用 Layer 3 的 CSM 包格式进行后续通信。

服务端的密钥持有证明不需要单独的 `server_proof`——后续 CSM 通信中，服务端能正确解密客户端发来的 CSM 包并加密响应，这本身就证明了服务端持有对应私钥。

**证书结构（96 字节）：**

```
server_ed25519_public_key [32] | ca_signature [64]
```
CA 离线使用其 Ed25519 私钥对 `server_ed25519_public_key` 签名生成证书。证书预置在服务端。

**握手流程：**

```
1. Client → Server: 发起请求（传输层负责，不含密码学载荷）
2. Server → Client: m1 = server_ed_pk [32] | ca_signature [64]   (96 字节, 明文)
3. Client 验证:
   Ed25519_verify_detached(ca_signature, server_ed_pk, 32, ca_ed_pk)
   → 通过后存储 server_ed_pk，设置 server_key_verified = 1
4. 后续按 Layer 3 CSM 包格式通信（sig|xpk|nonce|mac|ciphertext）
```

**公共 API：**

```c
// === 数据结构 ===
typedef struct naion_csm_ca_client {
    uint8_t ed_seed[32];
    uint8_t ed_secret_key[64];
    uint8_t ed_public_key[32];
    uint8_t ca_ed_public_key[32];          // 内置 CA 公钥
    uint8_t server_ed_public_key[32];      // 握手后习得
    int server_key_verified;
} naion_csm_ca_client;

typedef struct naion_csm_ca_server {
    uint8_t ed_seed[32];
    uint8_t ed_secret_key[64];
    uint8_t ed_public_key[32];
    uint8_t ca_signature[64];              // 预计算: CA签名(server_ed_pk)
    uint8_t client_ed_public_key[32];      // 首个CSM包习得
    int client_key_verified;
} naion_csm_ca_server;

// === 初始化 ===
int naion_csm_ca_client_create(client, ed_seed[32], ca_ed_pk[32]);
int naion_csm_ca_server_create(server, ed_seed[32], ca_signature[64]);

// === 握手 ===
// 服务端：构造证书响应 m1
int naion_csm_ca_handshake_response(server, out_m1[96], cap, &len);
size_t naion_csm_ca_handshake_response_size(void);  // 96

// 客户端：验证 m1，成功后存储服务端公钥
int naion_csm_ca_handshake_verify(client, m1[96], len);

// === 握手后 CSM 通信 (与 Layer 3 相同包格式) ===
int naion_csm_ca_client_encrypt(client, plaintext, len, out, cap, &outlen);
int naion_csm_ca_client_decrypt(client, packet, len, out, cap, &outlen);
int naion_csm_ca_server_encrypt(server, plaintext, len, out, cap, &outlen);
int naion_csm_ca_server_decrypt(server, packet, len, out, cap, &outlen); // 非const: 习得客户端密钥
void naion_csm_ca_client_wipe(client);
void naion_csm_ca_server_wipe(server);
// ... size helpers
```

---

## 各层内容分配汇总

| 层 | API 声明区域 | 内部实现 |
|---|---|---|
| **L1** | `naion_init`, `naion_memzero/memcmp/is_zero`, 随机提供者, BLAKE2b generichash, XChaCha20 stream | BLAKE2b 核心, ChaCha20/HChaCha20/XChaCha20 核心, 随机提供者, memcmp/is_zero |
| **L2** | AEAD IETF (4个函数) + secretbox XChaCha20 (4个函数) | Poly1305, verify16, AEAD 组合/分离实现, secretbox 封装 (委托给 box_afternm) |
| **L3** | Ed25519 (10个), X25519 (2个), KX (4个), Box XChaCha20 (9个), Box 通用分发 (9个+7个查询), CSM (14个) | SHA-512, X25519域算术, Ed25519算术/签名, Box实现, CSM内部helper+公共API |
| **L4** | CSM CA client/server structs, 握手函数(2个: response + verify), CSM通信(4个), wipe(2个), size helpers | CA握手实现, CSM CA封装 (委托给共享内部helper) |
| **XSalsa20** (若 `NAION_XSALSA20=1`) | secretbox XSalsa20 (4个) + Box XSalsa20 (9个) | Salsa20核心(quarterround/block/hsalsa20/xsalsa20_xor_ic), XSalsa20 box/secretbox实现, gUseXChaCha20+运行时调度 |

---

## 实施步骤

### 步骤 1：添加宏骨架

在 `naion.h` 头部（版本号之后，任何 API 声明之前）添加所有 `NAION_LAYER_*` 和 `NAION_XSALSA20` 宏的默认值与依赖逻辑。

### 步骤 2：用宏包裹现有代码

- Salsa20 内部实现（L1935-2097）→ 用 `#if NAION_XSALSA20` 包裹
- XSalsa20 secretbox 声明（L153-184）→ `#if NAION_XSALSA20`
- XSalsa20 secretbox 实现（L3249-3339）→ `#if NAION_XSALSA20`
- XSalsa20 box 声明（L268-315）→ `#if NAION_XSALSA20`
- XSalsa20 box 实现（L3868-4143）→ `#if NAION_XSALSA20`
- `gUseXChaCha20`（L466）和运行时调度函数 → `#if NAION_XSALSA20`（否则常量 1）
- 通用 `naion_box_*` 分发函数 → 当 `NAION_XSALSA20=0` 时直接委托给 XChaCha20
- 其余 API 声明 / 实现各段按层包裹

### 步骤 3：整合 CSM 为 Layer 3

将 `csm.h` 的全部内容合并入 `naion.h`，统一命名：

| 当前 (csm.h) | 重构后 (naion.h) |
|---|---|
| `csm_client` / `csm_server` | `naion_csm_client` / `naion_csm_server` |
| `CSM_OK` / `CSM_ERR_*` | `NAION_CSM_OK` / `NAION_CSM_ERR_*` |
| `csm_*` 公共函数 | `naion_csm_*` |
| `csm__*` 内部函数 | `naion_csm_internal_*` (static) |
| `CSM__*` 常量 | `NAION_CSM_*` |

堆分配保留，使用统一的 goto 清理模式：

```c
int naion_csm_client_encrypt(...) {
    uint8_t *plain_payload = NULL;
    int ret = NAION_CSM_ERR_CRYPTO;

    plain_payload = (uint8_t *) malloc(plain_payload_len);
    if (plain_payload == NULL) goto __ERROR__;

    // ... 加密逻辑 ...
    ret = NAION_CSM_OK;
    goto __FREE__;

__ERROR__:
    // 错误路径：清理敏感数据
    if (plain_payload != NULL) naion_memzero(plain_payload, plain_payload_len);
__FREE__:
    // 默认退出路径：释放所有资源
    if (plain_payload != NULL) free(plain_payload);
    // 清理其他临时密钥缓冲区 ...
    return ret;
}
```

### 步骤 4：实现 Layer 4 CA 握手

- 在 Layer 3 CSM 实现之后添加 Layer 4 声明和实现
- 握手后的加密/解密委托给 CSM 内部辅助函数（操作原始密钥缓冲区）
- 参见上方握手协议设计

### 步骤 5：统一内存管理

- CSM 和 secretbox 中所有 `malloc`/`free` 保持不变
- 统一为 goto 清理模式：`__ERROR__` 标签处理错误释放，`__FREE__` 标签处理正常退出释放
- 所有退出路径在 `free` 前调用 `naion_memzero` 清理敏感数据
- 函数只有一个 `return` 语句在 `__FREE__` 标签之后

### 步骤 6：清理

- 删除 `csm.h` 和 `csm.c`
- 更新 `naion.c`（保持 `#define NAION_IMPLEMENTATION` + `#include "naion.h"`）
- 更新 `PROTOCOL.md`（添加 CA 握手协议说明）
- 更新 `CLAUDE.md`（新架构、宏用法、合并后的单头文件结构）

---

## 关键文件

| 文件 | 操作 |
|---|---|
| `naion.h` | 主要修改：添加分层宏、用宏包裹 XSalsa20、整合 CSM Layer 3、添加 CA 握手 Layer 4、统一 goto 清理模式 |
| `csm.h` | **删除** |
| `csm.c` | **删除** |
| `naion.c` | 微调（确保仍正常驱动实现） |
| `PROTOCOL.md` | 更新——添加 CA 握手协议 |
| `CLAUDE.md` | 更新——反映新架构 |

---

## 兼容性说明

**破坏性变更：**
- 所有 `csm_*` 符号重命名为 `naion_csm_*`
- `csm.h` 文件移除（需改为 `#include "naion.h"`）

**保持不变（向后兼容）：**
- 所有 `naion_generichash_*`
- 所有 `naion_stream_xchacha20_*`
- 所有 `naion_aead_xchacha20poly1305_ietf_*`
- 所有 `naion_secretbox_xchacha20poly1305_*`
- 所有 `naion_sign_ed25519_*`
- 所有 `naion_scalarmult_curve25519_*`、`naion_kx_*`
- 所有 `naion_box_curve25519xchacha20poly1305_*`
- 所有 `naion_box_*` 通用分发（`NAION_XSALSA20=0` 时直接委托 XChaCha20，行为不变）
- `NAION_IMPLEMENTATION` 模式
- `NAION_ENABLE_SODIUM_COMPAT_NAMES` 机制

**默认行为变化：**
- XSalsa20 默认不编译（`NAION_XSALSA20=0`）。需要 XSalsa20 时用户必须显式 `#define NAION_XSALSA20 1`（在 `#include "naion.h"` 之前）

---

## 验证

1. **编译矩阵**：
   - Layer 1 only: `gcc -DNAION_LAYER_AEAD=0 -DNAION_LAYER_CSM=0 -DNAION_LAYER_CSM_CA=0`
   - Layer 1+2: `gcc -DNAION_LAYER_CSM=0 -DNAION_LAYER_CSM_CA=0`
   - Layer 1-3: `gcc -DNAION_LAYER_CSM_CA=0`
   - 全部四层: `gcc`（默认全开）
   - 全部四层 + XSalsa20: `gcc -DNAION_XSALSA20=1`
2. **XSalsa20 开关**：验证 `NAION_XSALSA20=0` 时无 Salsa20 符号；`=1` 时运行时调度正常
3. **AEAD 兼容性**：`enc || mac` 和 `mac || enc` 两种格式分别与 libsodium 互通
4. **CSM 互通**：重构前后代码跨版本通信
5. **CA 握手**：端到端握手→加密→解密完整流程
