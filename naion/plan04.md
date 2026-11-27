# Naion Layer 3/4 — CSM Nonce 隐式化改进计划

> 状态：计划阶段（未实现）
> 日期：2026-11-24
> 影响：Layer 3 (CSM) / Layer 4 (CSM-CA) 线格式；naion.h / csm.py / csm.go 需同步
> 与 plan03 (Layer 5) 的关系：相互独立；见「五、与 Layer 5 的关系」——Layer 5 **不得**照搬本方案

---

## 〇、动机

当前 CSM/CSM-CA 数据包固定开销 136 字节：

```text
signature(64) | session_x25519_public_key(32) | nonce(24) | mac(16) | ciphertext(var)
```

在 1024 字节 UDP 预算下，每包 24 字节的 nonce 字段占了 2.3% 的载荷空间。
而协议本身的结构使这个字段成为冗余：

1. CSM 每个数据包都生成**全新的临时 X25519 密钥对**；
2. AEAD key = HChaCha20(X25519(ephemeral_sk, 对端静态公钥))，随临时密钥每包唯一；
3. nonce 的唯一性要求（同 key 下不得重用）已经被 key 的唯一性覆盖。

因此可以把在线传输的 nonce 字段删除，AEAD 调用改用固定的 24 字节全零 nonce，
每包节省 24 字节，无安全损失（论证见「二」）。

## 一、协议变更

### 1.1 新包布局（两个方向一致）

```text
signature(64) | session_x25519_public_key(32) | mac(16) | ciphertext(var)
```

- `signature`：Ed25519 detached signature，仍覆盖它之后的全部内容（规则不变，
  覆盖范围随 nonce 字段移除而相应缩小）。
- `session_x25519_public_key`：仍同时作为 AEAD associated data。
- `mac`：16 字节 Poly1305 标签，位置不变。
- AEAD 调用：`nonce = 24 × 0x00`（XChaCha20-Poly1305-IETF 接口不变，仅输入恒定）。

### 1.2 大小预算

```text
固定外层开销：136 → 112 bytes

最大 application payload：
- Client -> Server：1024 - 112 - 32 = 856 → 880 bytes
- Server -> Client：1024 - 112      = 888 → 912 bytes
```

参考常量更新（沿用 `naion.h` 现有的组合式定义，随宏分支去掉 nonce 项；宏定义与
迁移策略见「三、兼容性与迁移」）：

```c
#if NAION_CSM_IMPLICIT_NONCE
#define NAION_CSM_PACKET_OVERHEAD \
    (naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX + \
     naion_box_MACBYTES_MAX)                        /* 64+32+16 = 112，原 136 */
#else
#define NAION_CSM_PACKET_OVERHEAD \
    (naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX + \
     naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX)
#endif
/* NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES → 880 (原 856) */
/* NAION_CSM_MAX_SERVER_PAYLOAD_BYTES → 912 (原 888) */
```

## 二、安全论证

### 2.1 为什么零 nonce 不会构成重用

XChaCha20-Poly1305 的安全性要求 (key, nonce) 二元组不重用。本方案下：

- AEAD key 由每包随机生成的临时 X25519 私钥决定（32 字节随机标量）；
- 两个包 key 相同 ⟺ 临时私钥碰撞（概率量级 2^-250 以下）或 HChaCha20 输出碰撞
  （256-bit PRF，通用碰撞界 2^128 做不到）；
- 因此 (key, 0) 重用的概率等价于临时密钥随机碰撞概率，可忽略。

### 2.2 代价：从「双保险」降为「单前提」

旧格式中 24 字节随机 nonce 提供了一层**无状态误用抗性**：即使实现缺陷导致两包
密钥意外相同，随机 nonce 仍大概率不同。移除后，安全性完全耦合到下面这条协议
不变量上：

> **INVARIANT-1：CSM/CSM-CA 的每个数据包必须使用全新生成的临时 X25519 密钥对。
> 任何密钥复用场景（会话密钥、测试固定密钥）都不得套用本包格式。**

该前提必须写入 PROTOCOL.md，并落实为实现约束：

- RNG 失败时 encrypt 必须**拒绝发包**（返回错误），不得降级重用上一次的密钥材料；
- Debug 构建可加断言：本次临时公钥 ≠ 上一次（检测 RNG 退化）。

### 2.3 明确否决项（记录，避免重提）

- **省略 mac(16)**：否决。C→S 方向 Server 的验签公钥来自解密明文，Poly1305 是
  「验签公钥可信」的锚点，去掉即认证完全失效（可塑明文 + 自选验签锚）；S→C
  方向理论可行但失去廉价完整性过滤、双信任锚纵深与方向格式对称，收益仅
  16/888 ≈ 1.8%。
- **压缩 Ed25519 签名（64 → 32）**：需要非标准变体（R 参与哈希），不做。

## 三、兼容性与迁移

这是**线格式破坏性变更**：新旧格式的 sig/xpk 前缀相同，其后布局不同，旧实现
解析新包会把 `mac||ct` 的前 24 字节误当 nonce，静默错解。没有可协商的版本字段。

策略：

1. 编译期宏切换，默认保持旧格式：

```c
#ifndef NAION_CSM_IMPLICIT_NONCE
#define NAION_CSM_IMPLICIT_NONCE 0
#endif
```

2. 同一网络内收发两端（及全部三/四个实现）必须以相同取值构建；
3. 宏开启时，实现应更新所有长度校验（最小包长、payload 上限）；收到旧格式
   包按新格式解析必然 mac 校验失败，天然拒绝，不产生歧义；
4. 跨语言互操作测试通过后，视部署节奏把默认值翻转为 1 并更新 PROTOCOL.md
   （major 版本号标注线格式断代）。

## 四、实现清单

1. `naion.h`：
   - 新增 `NAION_CSM_IMPLICIT_NONCE` 宏（Layer 3/4 生效）；
   - CSM encrypt/decrypt 内部 body 布局调整 + 固定零 nonce；
   - 常量与最小包长校验随宏分支更新；
   - RNG 失败拒绝发包路径 + debug 断言。
2. `csm.py` / `csm.go`：同步宏/参数开关与布局。
3. PROTOCOL.md：包布局、大小预算、INVARIANT-1 前提声明、宏说明。
4. 测试：
   - 确定性向量（固定临时密钥 + 零 nonce）；
   - 新旧格式互斥性（宏开启时旧格式包必须被拒绝）；
   - 三实现互操作（同一宏取值下字节级一致）；
   - RNG 故障注入（encrypt 返回错误而非复用密钥）。
5. CLAUDE.md 常量与包格式描述处同步。

## 五、与 Layer 5（plan03）的关系

**本方案只适用于「每包全新密钥」的无状态 CSM 格式。**

plan03 的 Layer 5 数据包（`sig | nonce | mac | ct`，104 开销）使用**跨包复用的
会话共享密钥**——密钥不唯一，零 nonce 会立即构成重用，属于灾难性误用。Layer 5
若要压缩 nonce，应走其实现清单第 8 条：**计数器 nonce（隐式序号）**，与本方案的
安全前提不同，不可混淆。两方案并行推进时，PROTOCOL.md 中需分别注明各自的
nonce 唯一性依据。
