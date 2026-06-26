# Naion Go & Python 版本设计文档

> 设计目标：基于 C 版本 `naion.h`（单头文件 STB 风格），为 Go 和 Python 分别设计等价加密库。两者均为**单文件**实现。Go 尽量基于 `crypto/*` + `golang.org/x/crypto`，Python 基于 PyCryptodome 为主 + PyNaCl 补充。与 C 版本**字节级兼容**。

---

## 〇、单文件设计原则

参照 C 版本 `naion.h` 的单头文件模式，Go 和 Python 版本也采用单文件：

| 语言 | 文件名 | 使用方式 |
|---|---|---|
| C | `naion.h` | `#include "naion.h"` |
| Go | `naion.go` | `import "naion"` — 一个 `.go` 文件即一个包 |
| Python | `naion.py` | `import naion` — 单文件模块 |

单文件内按**段落（section）**组织，从上到下依次为：

```
  [常量] → [基础设施] → [RNG] → [BLAKE2b] → [XChaCha20] →
  [AEAD] → [Secretbox] → [Box afternm] → [X25519] → [KX] →
  [Box 非对称] → [Ed25519] → [CSM] → [CSM-CA] → [XSalsa20]
```

层与层之间有清晰的注释分隔符，例如 `// ==== Layer 2: AEAD ====`。

---

## 一、依赖映射

### 1.1 原语 → Go → Python 对照

| C 原语 | Go 库 | Python 库 | 备注 |
|---|---|---|---|
| `memzero` / `memcmp` | 手写 (~5行) | 手写 `bytes` 比较 + `bytearray` 清零 | Go: `subtle.ConstantTimeCompare` |
| RNG | `crypto/rand` | `os.urandom` | 标准库 |
| BLAKE2b | `golang.org/x/crypto/blake2b` | `hashlib.blake2b` (Python 3.6+ stdlib) | Go 需 x/crypto |
| XChaCha20 流 | `golang.org/x/crypto/chacha20` + HChaCha20 | `Crypto.Cipher.ChaCha20` + HChaCha20 | 均需手写 X 构造 |
| HChaCha20 | **手写** (~40行) | **手写** (~30行) | x/crypto 和 PyCryptodome 均不暴露 |
| XChaCha20-Poly1305 AEAD | `x/crypto/chacha20poly1305.NewX` | PyCryptodome `ChaCha20_Poly1305` + 手写 X 构造 | Go 直接支持 X 变体 |
| X25519 | `x/crypto/curve25519` | **PyNaCl** `nacl.bindings.crypto_scalarmult` | PyCryptodome 支持待验证，优先用 PyNaCl |
| Ed25519 | `crypto/ed25519` (Go 1.13+ stdlib) | **PyNaCl** `nacl.bindings.crypto_sign` | PyNaCl 与 libsodium 密钥格式一致 |
| Ed25519→X25519 转换 | 手写 (SHA-512 + clamp + 坐标转换) | **PyNaCl** `nacl.bindings.crypto_sign_ed25519_*_to_curve25519` | PyNaCl 直接提供，无需手写 |
| SHA-512 | `crypto/sha512` | `hashlib.sha512` | 仅用于 Ed→X 转换 |
| KX (BLAKE2b 推导) | `x/crypto/blake2b` | `hashlib.blake2b` | 32+32 字节 → rx/tx |

### 1.2 Go 依赖清单

**标准库（无需额外依赖）：**
- `crypto/ed25519` — Ed25519 签名/验证
- `crypto/sha512` — SHA-512
- `crypto/rand` — 安全随机数
- `crypto/subtle` — 常数时间比较
- `encoding/binary` — 小端序编解码

**golang.org/x/crypto（需 go.mod 引入）：**
- `blake2b` — BLAKE2b 哈希
- `chacha20poly1305` — XChaCha20-Poly1305 AEAD (NewX)
- `chacha20` — ChaCha20 原始流密码（用于 XChaCha20 流 + HChaCha20）
- `curve25519` — X25519 标量乘法

**go.mod:**
```
module naion
go 1.25.0
require golang.org/x/crypto v0.50.0
```

### 1.3 Python 依赖清单

**标准库（无需安装）：**
- `hashlib` — SHA-512, BLAKE2b (3.6+)
- `os` — urandom
- `struct` — 小端序 u32 编解码
- `ctypes` — 常数时间比较辅助

**PyCryptodome（pip install pycryptodome）：**
- `Crypto.Cipher.ChaCha20` — XChaCha20 流密码（需手写 X 构造）
- `Crypto.Cipher.ChaCha20_Poly1305` — AEAD（需手写 X 构造）
- `Crypto.Hash.BLAKE2b` — BLAKE2b（备选，stdlib hashlib 优先）

**PyNaCl（pip install pynacl）：**
- `nacl.bindings.crypto_sign_*` — Ed25519 签名、密钥转换
- `nacl.bindings.crypto_scalarmult_*` — X25519 标量乘法
- `nacl.bindings.crypto_sign_ed25519_*_to_curve25519` — Ed→X 密钥转换

---

## 二、Go 版本设计 — `naion.go`

### 2.1 文件内部组织

单文件 `naion.go`，按以下顺序组织：

```
naion.go
├── 文件头注释 + 包声明
├── import 块
│
├── ==== 常量 ====
│   ├── 版本字符串
│   ├── 各模块的 _BYTES 常量
│   ├── Box 上限常量
│   └── CSM/CSM-CA 常量
│
├── ==== 错误类型 ====
│   └── CSMError 类型 + 错误码常量
│
├── ==== 基础设施 ====
│   ├── randomProvider 变量 + Set/Get
│   ├── Init(), MemZero(), MemCmp(), IsZero(), Verify32()
│   └── 内置 RNG 实现（crypto/rand）
│
├── ==== HChaCha20（内部） ====
│   └── hChaCha20() 手写实现
│
├── ==== Layer 1: BLAKE2b ====
│   ├── GenericHashState 结构体 + 方法
│   └── GenericHash() 一次性函数
│
├── ==== Layer 1: XChaCha20 流密码 ====
│   ├── StreamXChaCha20()
│   ├── StreamXChaCha20XOR()
│   └── StreamXChaCha20XORIC()
│
├── ==== Layer 2: AEAD ====
│   ├── aeadEncrypt(), aeadDecrypt()
│   ├── ...Detached() 变体
│   └── 组合/分离格式转换
│
├── ==== Layer 2: Secretbox ====
│   └── Secretbox*() 委托给 afternm
│
├── ==== Layer 2: Box afternm ====
│   └── Box*AfterNM() 纯对称操作
│
├── ==== Layer 3: X25519 ====
│   └── ScalarMult*() 包装 curve25519
│
├── ==== Layer 3: KX ====
│   └── KX*() 密钥交换
│
├── ==== Layer 3: Box ====
│   ├── Box*Keypair(), Box*BeforeNM()
│   ├── Box*Easy(), Box*OpenEasy()
│   └── Box*Seal(), Box*SealOpen()
│
├── ==== Layer 3: Ed25519 ====
│   ├── Sign*Keypair(), Sign*SeedKeypair()
│   ├── Sign(), SignOpen(), SignDetached(), VerifyDetached()
│   ├── SKToSeed(), SKToPK()
│   └── PKToCurve25519(), SKToCurve25519()
│
├── ==== Layer 3: CSM ====
│   ├── CSMClient / CSMServer 结构体 + 方法
│   ├── CSMClientCreate() / CSMServerCreate()
│   └── EncryptSize() / DecryptMaxPlaintextSize()
│
├── ==== Layer 4: CSM-CA ====
│   ├── CSMCAClient / CSMCAServer 结构体 + 方法
│   ├── CSMCAClientCreate() / CSMCAServerCreate()
│   └── HandshakeResponse() / HandshakeVerify()
│
├── ==== XSalsa20（可选编译） ====
│   └── 通过构建标签 //go:build naion_xsalsa20
│
└── ==== 兼容别名 ====
    └── 通过构建标签 //go:build naion_compat
```

### 2.2 常量和类型

```go
package naion

import (...)

const VersionString = "naion/0.2 (Go)"

// ===== BLAKE2b =====
const (
    GenericHashBytes          = 32
    GenericHashBytesMin       = 16
    GenericHashBytesMax       = 64
    GenericHashKeyBytes       = 32
    GenericHashKeyBytesMin    = 16
    GenericHashKeyBytesMax    = 64
    GenericHashSaltBytes      = 16
    GenericHashPersonalBytes  = 16
)

// ===== XChaCha20 =====
const (
    StreamXChaCha20KeyBytes   = 32
    StreamXChaCha20NonceBytes = 24
)

// ===== AEAD =====
const (
    AEADXChaCha20Poly1305IETFKeyBytes  = 32
    AEADXChaCha20Poly1305IETFNSecBytes = 0
    AEADXChaCha20Poly1305IETFNPubBytes = 24
    AEADXChaCha20Poly1305IETFABytes    = 16
)

// ===== Secretbox =====
const (
    SecretboxXChaCha20Poly1305KeyBytes   = 32
    SecretboxXChaCha20Poly1305NonceBytes = 24
    SecretboxXChaCha20Poly1305MacBytes   = 16
)

// ===== Box =====
const (
    BoxCurve25519XChaCha20Poly1305SeedBytes       = 32
    BoxCurve25519XChaCha20Poly1305PublicKeyBytes   = 32
    BoxCurve25519XChaCha20Poly1305SecretKeyBytes   = 32
    BoxCurve25519XChaCha20Poly1305BeforeNMBytes    = 32
    BoxCurve25519XChaCha20Poly1305NonceBytes       = 24
    BoxCurve25519XChaCha20Poly1305MacBytes         = 16
    BoxCurve25519XChaCha20Poly1305SealBytes        = 48
)

// ===== X25519 =====
const (
    ScalarMultCurve25519Bytes       = 32
    ScalarMultCurve25519ScalarBytes = 32
)

// ===== KX =====
const (
    KXPublicKeyBytes  = 32
    KXSecretKeyBytes  = 32
    KXSeedBytes       = 32
    KXSessionKeyBytes = 32
)

// ===== Ed25519 =====
const (
    SignEd25519Bytes          = 64
    SignEd25519SeedBytes      = 32
    SignEd25519PublicKeyBytes = 32
    SignEd25519SecretKeyBytes = 64  // seed || pk
)

// ===== Box 上限 =====
const (
    BoxSeedBytesMax      = 32
    BoxPublicKeyBytesMax = 32
    BoxSecretKeyBytesMax = 32
    BoxBeforeNMBytesMax  = 32
    BoxNonceBytesMax     = 24
    BoxMacBytesMax       = 16
    BoxSealBytesMax      = 48
)

// ===== CSM =====
const (
    CSMPacketOverhead        = 136
    CSMClientPKBytes         = 32
    CSMMaxUDPDatagramBytes   = 1024
    CSMMaxClientPayloadBytes = 856
    CSMMaxServerPayloadBytes = 888
)

// ===== CSM-CA =====
const CSMCACertBytes = 96

// ===== CSM 错误码 =====
type CSMError int

const (
    CSMOK                CSMError = 0
    CSMErrInvalidArg     CSMError = -1
    CSMErrBufferTooSmall CSMError = -2
    CSMErrCrypto         CSMError = -3
    CSMErrVerifyFailed   CSMError = -4
    CSMErrState          CSMError = -5
    CSMErrRandomProvider CSMError = -6
    CSMErrNoData         CSMError = -7
)

func (e CSMError) Error() string

// ===== RNG =====
type RandomProvider func(buf []byte) error

// ===== 结构体 =====
type GenericHashState struct { h blake2b.Hasher; outLen int }

type CSMClient struct {
    EdSeed            [32]byte
    EdSecretKey       [64]byte
    EdPublicKey        [32]byte
    ServerEdPublicKey  [32]byte
}

type CSMServer struct {
    EdSeed                     [32]byte
    EdSecretKey                [64]byte
    EdPublicKey                 [32]byte
    ClientEdPublicKey           [32]byte
    ClientPublicKeyInitialized  bool
}

type CSMCAClient struct {
    EdSeed            [32]byte
    EdSecretKey       [64]byte
    EdPublicKey        [32]byte
    CAEdPublicKey      [32]byte
    ServerEdPublicKey  [32]byte
    ServerKeyVerified  bool
}

type CSMCAServer struct {
    EdSeed            [32]byte
    EdSecretKey       [64]byte
    EdPublicKey        [32]byte
    CASignature        [64]byte
    ClientEdPublicKey  [32]byte
    ClientKeyVerified  bool
}
```

### 2.3 API 签名

```go
// ===== 基础设施 =====
func Init() error
func MemZero(p []byte)
func MemCmp(a, b []byte) int
func IsZero(p []byte) bool
func Verify32(x, y *[32]byte) int
func SetRandomProvider(fn RandomProvider)
func GetRandomProvider() RandomProvider

// ===== HChaCha20（内部） =====
func hChaCha20(key *[32]byte, nonce *[16]byte) (out [32]byte)

// ===== BLAKE2b =====
func GenericHash(outLen int, in, key []byte) ([]byte, error)
func (st *GenericHashState) Init(key []byte, outLen int) error
func (st *GenericHashState) Write(p []byte) error
func (st *GenericHashState) Sum(outLen int) ([]byte, error)

// ===== XChaCha20 流 =====
func StreamXChaCha20(outLen int, nonce *[24]byte, key *[32]byte) ([]byte, error)
func StreamXChaCha20XOR(m []byte, nonce *[24]byte, key *[32]byte) ([]byte, error)
func StreamXChaCha20XORIC(m []byte, nonce *[24]byte, ic uint64, key *[32]byte) ([]byte, error)

// ===== AEAD (c = ciphertext || mac) =====
func AEADXChaCha20Poly1305IETFEncrypt(m, ad, npub, key []byte) ([]byte, error)
func AEADXChaCha20Poly1305IETFDecrypt(c, ad, npub, key []byte) ([]byte, error)
func AEADXChaCha20Poly1305IETFEncryptDetached(m, ad, npub, key []byte) ([]byte, [16]byte, error)
func AEADXChaCha20Poly1305IETFDecryptDetached(c []byte, mac *[16]byte, ad, npub, key []byte) ([]byte, error)

// ===== Secretbox =====
func SecretboxXChaCha20Poly1305Easy(m, nonce, key []byte) ([]byte, error)
func SecretboxXChaCha20Poly1305OpenEasy(c, nonce, key []byte) ([]byte, error)
func SecretboxXChaCha20Poly1305Detached(m, nonce, key []byte) ([]byte, [16]byte, error)
func SecretboxXChaCha20Poly1305OpenDetached(c []byte, mac *[16]byte, nonce, key []byte) ([]byte, error)

// ===== Box afternm =====
func BoxCurve25519XChaCha20Poly1305EasyAfterNM(m, nonce, k []byte) ([]byte, error)
func BoxCurve25519XChaCha20Poly1305OpenEasyAfterNM(c, nonce, k []byte) ([]byte, error)

// ===== X25519 =====
func ScalarMultCurve25519(n, p *[32]byte) (*[32]byte, error)
func ScalarMultCurve25519Base(n *[32]byte) (*[32]byte, error)

// ===== KX =====
func KXKeypair() (pk, sk [32]byte, err error)
func KXSeedKeypair(seed *[32]byte) (pk, sk [32]byte, err error)
func KXClientSessionKeys(clientPK, clientSK, serverPK *[32]byte) (rx, tx [32]byte, err error)
func KXServerSessionKeys(serverPK, serverSK, clientPK *[32]byte) (rx, tx [32]byte, err error)

// ===== Box 非对称 =====
func BoxCurve25519XChaCha20Poly1305Keypair() (pk, sk [32]byte, err error)
func BoxCurve25519XChaCha20Poly1305SeedKeypair(seed *[32]byte) (pk, sk [32]byte, err error)
func BoxCurve25519XChaCha20Poly1305BeforeNM(pk, sk *[32]byte) ([32]byte, error)
func BoxCurve25519XChaCha20Poly1305Easy(m, nonce []byte, pk, sk *[32]byte) ([]byte, error)
func BoxCurve25519XChaCha20Poly1305OpenEasy(c, nonce []byte, pk, sk *[32]byte) ([]byte, error)
func BoxCurve25519XChaCha20Poly1305Seal(m []byte, pk *[32]byte) ([]byte, error)
func BoxCurve25519XChaCha20Poly1305SealOpen(c []byte, pk, sk *[32]byte) ([]byte, error)

// ===== Ed25519 =====
func SignEd25519Keypair() (pk [32]byte, sk [64]byte, err error)
func SignEd25519SeedKeypair(seed *[32]byte) (pk [32]byte, sk [64]byte, err error)
func SignEd25519(m []byte, sk *[64]byte) ([]byte, error)
func SignEd25519Open(sm []byte, pk *[32]byte) ([]byte, error)
func SignEd25519Detached(m []byte, sk *[64]byte) ([64]byte, error)
func SignEd25519VerifyDetached(sig *[64]byte, m []byte, pk *[32]byte) bool
func SignEd25519SKToSeed(sk *[64]byte) [32]byte
func SignEd25519SKToPK(sk *[64]byte) [32]byte
func SignEd25519PKToCurve25519(edPK *[32]byte) ([32]byte, error)
func SignEd25519SKToCurve25519(edSK *[64]byte) ([32]byte, error)

// ===== CSM =====
func CSMInit() CSMError
func (c *CSMClient) Wipe()
func (s *CSMServer) Wipe()
func CSMClientCreate(edSeed, serverEdPK *[32]byte) (*CSMClient, CSMError)
func CSMServerCreate(edSeed *[32]byte) (*CSMServer, CSMError)
func CSMClientEncryptSize(plaintextLen int) int
func CSMClientDecryptMaxPlaintextSize(packetLen int) int
func CSMServerEncryptSize(plaintextLen int) int
func CSMServerDecryptMaxPlaintextSize(packetLen int) int
func (c *CSMClient) Encrypt(plaintext []byte) ([]byte, CSMError)
func (c *CSMClient) Decrypt(packet []byte) ([]byte, CSMError)
func (s *CSMServer) Decrypt(packet []byte) ([]byte, CSMError)
func (s *CSMServer) Encrypt(plaintext []byte) ([]byte, CSMError)

// ===== CSM-CA =====
func (c *CSMCAClient) Wipe()
func (s *CSMCAServer) Wipe()
func CSMCAClientCreate(edSeed, caEdPK *[32]byte) (*CSMCAClient, CSMError)
func CSMCAServerCreate(edSeed *[32]byte, caSignature *[64]byte) (*CSMCAServer, CSMError)
func CSMCAHandshakeResponseSize() int
func (s *CSMCAServer) HandshakeResponse() ([96]byte, CSMError)
func (c *CSMCAClient) HandshakeVerify(m1 []byte) CSMError
func CSMCAClientEncryptSize(n int) int
func CSMCAClientDecryptMaxPlaintextSize(n int) int
func CSMCAServerEncryptSize(n int) int
func CSMCAServerDecryptMaxPlaintextSize(n int) int
func (c *CSMCAClient) Encrypt(pt []byte) ([]byte, CSMError)
func (c *CSMCAClient) Decrypt(pkt []byte) ([]byte, CSMError)
func (s *CSMCAServer) Encrypt(pt []byte) ([]byte, CSMError)
func (s *CSMCAServer) Decrypt(pkt []byte) ([]byte, CSMError)
```

### 2.4 关键实现细节

#### HChaCha20（手写 ~40 行，文件内私有函数）

```go
// HChaCha20(key[32], nonce[16]) → out[32]
// 1. state[0..3]   = "expand 32-byte k" (0x61707865, 0x3320646e, ...)
// 2. state[4..11]  = key (8 × uint32 LE)
// 3. state[12..15] = nonce (4 × uint32 LE)
// 4. 20 rounds (10 double-rounds: QR 4 times + diagonal shift, twice)
// 5. Output: state[0..3] || state[12..15] (first + last 4 words, LE)
func hChaCha20(key *[32]byte, nonce *[16]byte) (out [32]byte)
```

#### Ed25519 → X25519 密钥转换

- `PKToCurve25519`: Go 标准库不暴露 Ed25519 点坐标，手写 GF(2^255-19) 上 `u = (1+y)/(1-y) mod p` 转换。或引入 `filippo.io/edwards25519` 库
- `SKToCurve25519`: `seed = edSK[0:32]` → `SHA-512(seed)` → clamp

#### XChaCha20 流密码

```go
func streamXChaCha20XOR(...) {
    subkey := hChaCha20(key, nonce[0:16])
    cipher, _ := chacha20.NewUnauthenticatedCipher(subkey[:], nonce[16:24])
    cipher.XORKeyStream(c, m)
}
```

### 2.5 错误处理

- 底层加密函数：`(result, error)`，Go 惯用风格
- CSM 函数：`CSMError` 类型，保持 C 错误码语义
- 签名验证：`bool`
- 注意：AEAD/secretbox/open 失败时，返回的缓冲区已清零

### 2.6 层控制

单文件不支持编译时分拆。策略：

- **默认全部编译**。Go 链接器会去除未使用函数，无二进制膨胀问题
- **XSalsa20**：通过构建标签 `//go:build naion_xsalsa20` 控制。由于单文件限制，XSalsa20 块放在文件末尾，用独立的构建标签文件 `xsalsa20.go`（XSalsa20 代码可独立为小文件，不违背"核心单文件"原则）。如果严格要求纯单文件，则 XSalsa20 默认包含在 naion.go 中
- **兼容别名**：通过 `//go:build naion_compat` 标签控制独立小文件 `compat.go`

推荐的最终文件方案：
- `naion.go` — 主文件，包含 Layer 1-4 全部 + XSalsa20
- `compat.go` — 可选，sodium 兼容别名（构建标签 `naion_compat`）

---

## 三、Python 版本设计 — `naion.py`

### 3.1 文件内部组织

单文件 `naion.py`，按以下顺序组织：

```
naion.py
├── 模块文档字符串
├── import（按需导入，延迟导入可选）
│
├── ==== 常量 ====
│   ├── 版本字符串
│   ├── 各模块 _BYTES 常量
│   ├── Box 上限常量
│   └── CSM/CSM-CA 常量
│
├── ==== 异常 ====
│   └── NaionError 基类 + CSMError 子类系列
│
├── ==== 基础设施 ====
│   ├── _random_provider 变量
│   ├── init(), memzero(), memcmp(), is_zero(), verify_32()
│   └── set_random_provider(), get_random_provider()
│
├── ==== HChaCha20（内部） ====
│   └── _hchacha20() 手写实现
│
├── ==== Layer 1: BLAKE2b ====
│   ├── GenericHashState 类
│   └── generichash() 一次性函数
│
├── ==== Layer 1: XChaCha20 流密码 ====
│   ├── stream_xchacha20()
│   ├── stream_xchacha20_xor()
│   └── stream_xchacha20_xor_ic()
│
├── ==== Layer 2: AEAD ====
│   ├── aead_xchacha20poly1305_ietf_encrypt()
│   ├── aead_xchacha20poly1305_ietf_decrypt()
│   └── ..._detached() 变体
│
├── ==== Layer 2: Secretbox ====
│   └── secretbox_*() 委托给 afternm
│
├── ==== Layer 2: Box afternm ====
│   └── box_*_afternm()
│
├── ==== Layer 3: X25519 ====
│   └── scalarmult_curve25519(), scalarmult_curve25519_base()
│
├── ==== Layer 3: KX ====
│   └── kx_*()
│
├── ==== Layer 3: Box ====
│   └── box_curve25519xchacha20poly1305_*()
│
├── ==== Layer 3: Ed25519 ====
│   ├── sign_ed25519_*()
│   └── pk_to_curve25519(), sk_to_curve25519()
│
├── ==== Layer 3: CSM ====
│   ├── CSMClient, CSMServer 类
│   └── 工厂函数 + 大小函数
│
├── ==== Layer 4: CSM-CA ====
│   ├── CSMCAClient, CSMCAServer 类
│   └── handshake_response() / handshake_verify()
│
└── ==== XSalsa20 ====
    └── secretbox_xsalsa20poly1305_*()
        box_curve25519xsalsa20poly1305_*()
        box_set_use_xchacha20() / box_get_use_xchacha20()
        box_keypair() 等分派函数（默认分派到 XChaCha20）
```

### 3.2 常量和类型

```python
# naion.py

VERSION_STRING = "naion/0.2 (Python)"

# ===== BLAKE2b =====
GENERICHASH_BYTES = 32
GENERICHASH_BYTES_MIN = 16
GENERICHASH_BYTES_MAX = 64
GENERICHASH_KEYBYTES = 32
GENERICHASH_KEYBYTES_MIN = 16
GENERICHASH_KEYBYTES_MAX = 64
GENERICHASH_SALTBYTES = 16
GENERICHASH_PERSONALBYTES = 16

# ===== XChaCha20 =====
STREAM_XCHACHA20_KEYBYTES = 32
STREAM_XCHACHA20_NONCEBYTES = 24

# ===== AEAD =====
AEAD_XCHACHA20POLY1305_IETF_KEYBYTES = 32
AEAD_XCHACHA20POLY1305_IETF_NSECBYTES = 0
AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24
AEAD_XCHACHA20POLY1305_IETF_ABYTES = 16

# ===== Secretbox =====
SECRETBOX_XCHACHA20POLY1305_KEYBYTES = 32
SECRETBOX_XCHACHA20POLY1305_NONCEBYTES = 24
SECRETBOX_XCHACHA20POLY1305_MACBYTES = 16

# ===== Box =====
BOX_CURVE25519XCHACHA20POLY1305_SEEDBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_BEFORENMBYTES = 32
BOX_CURVE25519XCHACHA20POLY1305_NONCEBYTES = 24
BOX_CURVE25519XCHACHA20POLY1305_MACBYTES = 16
BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES = 48

# ===== X25519 =====
SCALARMULT_CURVE25519_BYTES = 32
SCALARMULT_CURVE25519_SCALARBYTES = 32

# ===== KX =====
KX_PUBLICKEYBYTES = 32
KX_SECRETKEYBYTES = 32
KX_SEEDBYTES = 32
KX_SESSIONKEYBYTES = 32

# ===== Ed25519 =====
SIGN_ED25519_BYTES = 64
SIGN_ED25519_SEEDBYTES = 32
SIGN_ED25519_PUBLICKEYBYTES = 32
SIGN_ED25519_SECRETKEYBYTES = 64

# ===== Box 上限 =====
BOX_SEEDBYTES_MAX = 32
BOX_PUBLICKEYBYTES_MAX = 32
BOX_SECRETKEYBYTES_MAX = 32
BOX_BEFORENMBYTES_MAX = 32
BOX_NONCEBYTES_MAX = 24
BOX_MACBYTES_MAX = 16
BOX_SEALBYTES_MAX = 48

# ===== CSM =====
CSM_PACKET_OVERHEAD = 136
CSM_CLIENT_PK_BYTES = 32
CSM_MAX_UDP_DATAGRAM_BYTES = 1024
CSM_MAX_CLIENT_PAYLOAD_BYTES = 856
CSM_MAX_SERVER_PAYLOAD_BYTES = 888

# ===== CSM-CA =====
CSM_CA_CERT_BYTES = 96
```

### 3.3 异常层次

```python
class NaionError(Exception):
    """所有 Naion 错误的基类"""
    pass

class NaionCryptoError(NaionError):
    """加密操作失败"""
    pass

class NaionArgumentError(NaionError, ValueError):
    """参数无效"""
    pass

class NaionBufferError(NaionError):
    """缓冲区过小"""
    pass

class NaionStateError(NaionError):
    """状态错误"""
    pass

class NaionRandomProviderError(NaionError):
    """随机数提供者失败"""
    pass

# CSM 异常（含 C 兼容错误码）
class CSMError(NaionError):
    code = 0

class CSMInvalidArgumentError(CSMError, NaionArgumentError):
    code = -1

class CSMBufferTooSmallError(CSMError, NaionBufferError):
    code = -2

class CSMCryptoError(CSMError, NaionCryptoError):
    code = -3

class CSMVerifyFailedError(CSMError, NaionCryptoError):
    code = -4

class CSMStateError(CSMError, NaionStateError):
    code = -5

class CSMRandomProviderError(CSMError, NaionRandomProviderError):
    code = -6

class CSMNoDataError(CSMError, NaionArgumentError):
    code = -7
```

### 3.4 API 签名

```python
# ===== 基础设施 =====
def init() -> None: ...
def memzero(buf: bytearray) -> None: ...
def memcmp(a: bytes, b: bytes) -> int: ...
def is_zero(buf: bytes) -> bool: ...
def verify_32(x: bytes, y: bytes) -> int: ...
def set_random_provider(fn) -> None: ...
def get_random_provider(): ...

# ===== BLAKE2b =====
def generichash(data: bytes, *, outlen: int = 32,
                key: bytes = None) -> bytes: ...

class GenericHashState:
    def __init__(self, *, key: bytes = None, outlen: int = 32) -> None: ...
    def update(self, data: bytes) -> None: ...
    def final(self) -> bytes: ...

# ===== XChaCha20 流 =====
def stream_xchacha20(length: int, nonce: bytes, key: bytes) -> bytes: ...
def stream_xchacha20_xor(m: bytes, nonce: bytes, key: bytes) -> bytes: ...
def stream_xchacha20_xor_ic(m: bytes, nonce: bytes, ic: int, key: bytes) -> bytes: ...

# ===== AEAD =====
def aead_xchacha20poly1305_ietf_encrypt(
    m: bytes, ad: bytes, npub: bytes, key: bytes,
    nsec: bytes = b''
) -> bytes: ...  # c || mac

def aead_xchacha20poly1305_ietf_decrypt(
    c: bytes, ad: bytes, npub: bytes, key: bytes,
    nsec: bytes = b''
) -> bytes: ...  # 失败抛出 NaionCryptoError

def aead_xchacha20poly1305_ietf_encrypt_detached(
    m: bytes, ad: bytes, npub: bytes, key: bytes,
    nsec: bytes = b''
) -> tuple[bytes, bytes]: ...  # (c, mac)

def aead_xchacha20poly1305_ietf_decrypt_detached(
    c: bytes, mac: bytes, ad: bytes, npub: bytes, key: bytes,
    nsec: bytes = b''
) -> bytes: ...

# ===== Secretbox =====
def secretbox_xchacha20poly1305_easy(
    m: bytes, nonce: bytes, key: bytes
) -> bytes: ...  # mac || ct

def secretbox_xchacha20poly1305_open_easy(
    c: bytes, nonce: bytes, key: bytes
) -> bytes: ...

def secretbox_xchacha20poly1305_detached(
    m: bytes, nonce: bytes, key: bytes
) -> tuple[bytes, bytes]: ...

def secretbox_xchacha20poly1305_open_detached(
    c: bytes, mac: bytes, nonce: bytes, key: bytes
) -> bytes: ...

# ===== Box afternm =====
def box_curve25519xchacha20poly1305_easy_afternm(
    m: bytes, nonce: bytes, k: bytes
) -> bytes: ...

def box_curve25519xchacha20poly1305_open_easy_afternm(
    c: bytes, nonce: bytes, k: bytes
) -> bytes: ...

# ===== X25519 =====
def scalarmult_curve25519(n: bytes, p: bytes) -> bytes: ...
def scalarmult_curve25519_base(n: bytes) -> bytes: ...

# ===== KX =====
def kx_keypair() -> tuple[bytes, bytes]: ...
def kx_seed_keypair(seed: bytes) -> tuple[bytes, bytes]: ...
def kx_client_session_keys(client_pk: bytes, client_sk: bytes,
                            server_pk: bytes) -> tuple[bytes, bytes]: ...
def kx_server_session_keys(server_pk: bytes, server_sk: bytes,
                            client_pk: bytes) -> tuple[bytes, bytes]: ...

# ===== Box 非对称 =====
def box_curve25519xchacha20poly1305_keypair() -> tuple[bytes, bytes]: ...
def box_curve25519xchacha20poly1305_seed_keypair(seed: bytes) -> tuple[bytes, bytes]: ...
def box_curve25519xchacha20poly1305_beforenm(pk: bytes, sk: bytes) -> bytes: ...
def box_curve25519xchacha20poly1305_easy(m: bytes, nonce: bytes,
                                          pk: bytes, sk: bytes) -> bytes: ...
def box_curve25519xchacha20poly1305_open_easy(c: bytes, nonce: bytes,
                                               pk: bytes, sk: bytes) -> bytes: ...
def box_curve25519xchacha20poly1305_seal(m: bytes, pk: bytes) -> bytes: ...
def box_curve25519xchacha20poly1305_seal_open(c: bytes, pk: bytes,
                                               sk: bytes) -> bytes: ...

# ===== Ed25519 =====
def sign_ed25519_keypair() -> tuple[bytes, bytes]: ...   # (pk[32], sk[64])
def sign_ed25519_seed_keypair(seed: bytes) -> tuple[bytes, bytes]: ...
def sign_ed25519(m: bytes, sk: bytes) -> bytes: ...      # sig || m
def sign_ed25519_open(sm: bytes, pk: bytes) -> bytes: ... # m
def sign_ed25519_detached(m: bytes, sk: bytes) -> bytes: ...
def sign_ed25519_verify_detached(sig: bytes, m: bytes, pk: bytes) -> bool: ...
def sign_ed25519_sk_to_seed(sk: bytes) -> bytes: ...
def sign_ed25519_sk_to_pk(sk: bytes) -> bytes: ...
def sign_ed25519_pk_to_curve25519(ed_pk: bytes) -> bytes: ...
def sign_ed25519_sk_to_curve25519(ed_sk: bytes) -> bytes: ...

# ===== CSM =====
class CSMClient:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    server_ed_public_key: bytes

    def __init__(self, ed_seed: bytes, server_ed_pk: bytes) -> None: ...
    def wipe(self) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, packet: bytes) -> bytes: ...
    @staticmethod
    def encrypt_size(plaintext_len: int) -> int: ...
    @staticmethod
    def decrypt_max_plaintext_size(packet_len: int) -> int: ...

class CSMServer:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    client_ed_public_key: bytes | None
    client_public_key_initialized: bool

    def __init__(self, ed_seed: bytes) -> None: ...
    def wipe(self) -> None: ...
    def decrypt(self, packet: bytes) -> bytes: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    @staticmethod
    def encrypt_size(plaintext_len: int) -> int: ...
    @staticmethod
    def decrypt_max_plaintext_size(packet_len: int) -> int: ...

# ===== CSM-CA =====
class CSMCAClient:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    ca_ed_public_key: bytes
    server_ed_public_key: bytes | None
    server_key_verified: bool

    def __init__(self, ed_seed: bytes, ca_ed_pk: bytes) -> None: ...
    def wipe(self) -> None: ...
    def handshake_verify(self, m1: bytes) -> None: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, packet: bytes) -> bytes: ...
    @staticmethod
    def encrypt_size(plaintext_len: int) -> int: ...
    @staticmethod
    def decrypt_max_plaintext_size(packet_len: int) -> int: ...

class CSMCAServer:
    ed_seed: bytes
    ed_secret_key: bytes
    ed_public_key: bytes
    ca_signature: bytes
    client_ed_public_key: bytes | None
    client_key_verified: bool

    def __init__(self, ed_seed: bytes, ca_signature: bytes) -> None: ...
    def wipe(self) -> None: ...
    def handshake_response(self) -> bytes: ...
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, packet: bytes) -> bytes: ...
    @staticmethod
    def encrypt_size(plaintext_len: int) -> int: ...
    @staticmethod
    def decrypt_max_plaintext_size(packet_len: int) -> int: ...
```

### 3.5 关键实现细节

#### HChaCha20（手写 ~30 行，模块级私有函数）

```python
# _hchacha20(key: bytes[32], nonce: bytes[16]) -> bytes[32]
# 1. struct.unpack 16 个 uint32 LE
# 2. 20 rounds (10 double-rounds)
# 3. struct.pack output[0:4] + output[12:16]
def _hchacha20(key: bytes, nonce: bytes) -> bytes:
    ...
```

#### Ed25519 — 使用 PyNaCl

```python
# PyNaCl 的 nacl.bindings 与 libsodium 共享密钥格式，字节兼容
import nacl.bindings

def sign_ed25519_keypair():
    # nacl.bindings.crypto_sign_keypair() 返回 (pk[32], sk[64])
    # sk 格式为 seed || pk，与 C 版本一致
    ...

def sign_ed25519_detached(m, sk):
    return nacl.bindings.crypto_sign(m, sk)[:64]

def sign_ed25519_verify_detached(sig, m, pk):
    try:
        nacl.bindings.crypto_sign_open(sig + m, pk)
        return True
    except nacl.exceptions.BadSignatureError:
        return False
```

#### Ed25519 → X25519 转换 — 直接用 PyNaCl

```python
def sign_ed25519_pk_to_curve25519(ed_pk):
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed_pk)

def sign_ed25519_sk_to_curve25519(ed_sk):
    return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(ed_sk)
```

#### X25519 — 使用 PyNaCl

```python
def scalarmult_curve25519(n, p):
    return nacl.bindings.crypto_scalarmult(n, p)

def scalarmult_curve25519_base(n):
    return nacl.bindings.crypto_scalarmult_base(n)
```

#### XChaCha20-Poly1305 — 使用 PyCryptodome + 手写 X 构造

```python
from Crypto.Cipher import ChaCha20_Poly1305

def _xchacha20_poly1305_encrypt(key, nonce, plaintext, aad):
    subkey = _hchacha20(key, nonce[:16])
    subnonce = b'\x00' * 4 + nonce[16:24]  # IETF 12-byte
    cipher = ChaCha20_Poly1305.new(key=subkey, nonce=subnonce)
    cipher.update(aad)
    ct, mac = cipher.encrypt_and_digest(plaintext)
    return ct, mac
```

#### BLAKE2b — 使用 stdlib hashlib

```python
import hashlib

def generichash(data, *, outlen=32, key=None):
    h = hashlib.blake2b(data, key=key, digest_size=outlen)
    return h.digest()
```

### 3.6 依赖导入策略

```python
# naion.py 顶部集中导入
import os
import struct
import hashlib
import hmac

# PyCryptodome（用于 ChaCha20 流密码 + AEAD）
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305

# PyNaCl（用于 Ed25519 + X25519 + Ed→X 转换）
import nacl.bindings
import nacl.exceptions
```

### 3.7 层控制

Python 单文件通过**模块级布尔开关**控制层：

```python
# 在 import naion 之后、调用任何函数之前设置
import naion
naion.LAYER_AEAD = False   # 禁用 Layer 2+
naion.LAYER_CSM = False    # 禁用 Layer 3+
naion.LAYER_CSM_CA = False # 禁用 Layer 4
naion.XSALSA20 = True      # 启用 XSalsa20（默认 False）
```

默认所有层启用。禁用上层会阻止对应函数被调用（调用时抛出 `NaionStateError`）。这种方式在运行时工作，但不会像 C 宏那样在编译时移除代码。

---

## 四、CSM 协议要点（跨语言一致性关键）

### 4.1 包布局（不可变更）

```
字节 0-63:    Ed25519 分离签名    (64)
字节 64-95:   session_x25519_公钥 (32)
字节 96-119:  XChaCha20 随机数    (24)
字节 120-135: Poly1305 MAC 标签   (16)
字节 136+:    密文               (变长)
```

- AEAD AAD = `session_x25519_public_key`（包字节 64-95）
- 客户端→服务端明文 = `client_ed25519_pk(32) || payload`
- 服务端→客户端明文 = `payload`

### 4.2 加密流程（客户端）

```
1. server_xpk = EdPK→X25519(server_ed_pk)
2. session_xsk, session_xpk = X25519_keypair()
3. shared = X25519(session_xsk, server_xpk)
4. nonce = random(24)
5. aead_key = HChaCha20(shared, nonce[0:16])
6. aad = session_xpk
7. plaintext_wire = client_ed_pk || payload
8. ct, mac = XChaCha20-Poly1305-IETF_encrypt(aead_key, nonce, plaintext_wire, aad)
9. body = session_xpk || nonce || mac || ct
10. sig = Ed25519_sign(client_ed_sk, body)
11. packet = sig || body
```

### 4.3 验证规则

| 规则 | 错误 |
|---|---|
| 总包长度 < 136 | 拒绝 |
| Ed25519 签名验证失败 | `ERR_VERIFY_FAILED` |
| AEAD MAC 验证失败 | `ERR_CRYPTO` |
| 客户端包解密后明文 < 32 字节 | `ERR_CRYPTO` |
| 服务端未学习客户端公钥时 encrypt | `ERR_STATE` |
| 明文超过方向性最大 payload | 拒绝 |
| 零长度 payload | `ERR_NO_DATA` |

---

## 五、XSalsa20 可选模块

### Go

放在 `naion.go` 末尾（或独立 `xsalsa20.go` + 构建标签）。提供：

```go
var gUseXChaCha20 bool = true

// secretbox XSalsa20 变体
func SecretboxXSalsa20Poly1305Easy(...)
func SecretboxXSalsa20Poly1305OpenEasy(...)
func SecretboxXSalsa20Poly1305Detached(...)
func SecretboxXSalsa20Poly1305OpenDetached(...)

// box XSalsa20 变体
func BoxCurve25519XSalsa20Poly1305Keypair() ...
func BoxCurve25519XSalsa20Poly1305SeedKeypair(...) ...
func BoxCurve25519XSalsa20Poly1305BeforeNM(...) ...
func BoxCurve25519XSalsa20Poly1305Easy(...) ...
func BoxCurve25519XSalsa20Poly1305OpenEasy(...) ...
func BoxCurve25519XSalsa20Poly1305EasyAfterNM(...) ...
func BoxCurve25519XSalsa20Poly1305OpenEasyAfterNM(...) ...
func BoxCurve25519XSalsa20Poly1305Seal(...) ...
func BoxCurve25519XSalsa20Poly1305SealOpen(...) ...

// 运行时选择器
func BoxSetUseXChaCha20(use bool)
func BoxGetUseXChaCha20() bool
func BoxKeypair() ([32]byte, [32]byte, error)           // 分派
func BoxSeedKeypair(seed *[32]byte) ([32]byte, [32]byte, error)
func BoxBeforeNM(pk, sk *[32]byte) ([32]byte, error)
func BoxEasy(m, nonce []byte, pk, sk *[32]byte) ([]byte, error)
func BoxOpenEasy(c, nonce []byte, pk, sk *[32]byte) ([]byte, error)
func BoxEasyAfterNM(m, nonce, k []byte) ([]byte, error)
func BoxOpenEasyAfterNM(c, nonce, k []byte) ([]byte, error)
func BoxSeal(m []byte, pk *[32]byte) ([]byte, error)
func BoxSealOpen(c []byte, pk, sk *[32]byte) ([]byte, error)
```

### Python

放在 `naion.py` 末尾（可通过 `XSALSA20 = False` 控制是否暴露）：

```python
XSALSA20 = False  # 模块级开关
_g_use_xchacha20 = True

# 仅在 XSALSA20=True 时暴露
def secretbox_xsalsa20poly1305_easy(m, nonce, key): ...
def box_curve25519xsalsa20poly1305_keypair(): ...

# 运行时选择器（始终可用）
def box_set_use_xchacha20(use: bool) -> None: ...
def box_get_use_xchacha20() -> bool: ...
def box_keypair() -> tuple[bytes, bytes]: ...   # 根据 _g_use_xchacha20 分派
def box_easy(m, nonce, pk, sk) -> bytes: ...
# ...
```

---

## 六、测试策略

### 6.1 必须覆盖的测试

| # | 测试类别 | 范围 |
|---|---|---|
| ~4 | 基础设施 | memcmp, is_zero, verify_32, memzero |
| ~7 | BLAKE2b | 一次性、确定性、流式、key、salt、personal、错误参数 |
| ~5 | XChaCha20 流 | 密钥流、确定性、xor 往返、xor_ic、错误 |
| ~10 | AEAD | 往返、篡改 ct/mac、错误 AD、分离模式、错误参数 |
| ~8 | Secretbox | 往返、篡改、分离模式、空消息、错误 |
| ~5 | Box afternm | 往返、篡改、错误 |
| ~5 | X25519 | RFC 7748 向量、DH 一致性、小阶点、错误 |
| ~6 | KX | 随机/种子 keypair、session keys、确定性 |
| ~10 | Box 非对称 | keypair、beforenm、easy 往返、seal、错误 |
| ~10 | Ed25519 | keypair、分离/组合签名、确定性、sk→pk→curve、错误 |
| ~12 | CSM | 完整往返、篡改（10 个偏移）、状态错误、大小、NULL |
| ~12 | CSM-CA | 握手、篡改证书、错误 CA、握手后 CSM、状态 |
| ~4 | 跨语言 | Go↔C 互操作、Python↔C 互操作 |

### 6.2 Go 测试

单文件 `naion_test.go`，与 `naion.go` 同目录。`go test` 运行。

### 6.3 Python 测试

单文件 `test_naion.py`，与 `naion.py` 同目录。`pytest test_naion.py` 运行。

### 6.4 互操作测试

1. C 版本用固定种子产生已知测试向量
2. Go/Python 用相同种子产生相同密文包
3. Go/Python 解密 C 产生的包
4. C 解密 Go/Python 产生的包

---

## 七、设计决策汇总

| 决策 | 选择 | 理由 |
|---|---|---|
| Go 文件结构 | 单文件 `naion.go` | 与 C 单头文件风格一致 |
| Python 文件结构 | 单文件 `naion.py` | 与 C 单头文件风格一致 |
| Go RNG | `crypto/rand` | stdlib |
| Go Ed25519 | `crypto/ed25519` | stdlib (Go 1.13+) |
| Go X25519 | `x/crypto/curve25519` | API 接近 sodium |
| Go Ed→X 转换 | 手写 GF(2^255-19) 坐标转换 | stdlib 不暴露点坐标 |
| Go BLAKE2b | `x/crypto/blake2b` | 官方维护 |
| Go XChaCha20-Poly1305 | `x/crypto/chacha20poly1305.NewX` | 直接支持 X 变体 |
| Go HChaCha20 | **手写 ~40 行** | x/crypto 不暴露 |
| Go 层控制 | 默认全部编译 + XSalsa20 构建标签 | Go 链接器去除未用代码 |
| Python RNG | `os.urandom` | stdlib |
| Python Ed25519 | **PyNaCl** `nacl.bindings.crypto_sign` | 与 libsodium 密钥格式字节兼容 |
| Python X25519 | **PyNaCl** `nacl.bindings.crypto_scalarmult` | 与 libsodium 字节兼容 |
| Python Ed→X 转换 | **PyNaCl** `nacl.bindings.crypto_sign_ed25519_*_to_curve25519` | 直接提供，无需手写 |
| Python BLAKE2b | `hashlib.blake2b` | stdlib (Python 3.6+) |
| Python XChaCha20-Poly1305 | 手写 X 构造 + **PyCryptodome** `ChaCha20_Poly1305` | PyCryptodome 不直接支持 X 变体 |
| Python XChaCha20 流 | **PyCryptodome** `ChaCha20` + 手写 X 构造 | |
| Python HChaCha20 | **手写 ~30 行** | PyCryptodome 不暴露 |
| Python 层控制 | 模块级布尔开关 | Python 无编译时宏 |
| Go CSM 错误 | `CSMError` 类型 | 保持 C 错误码语义 |
| Python CSM 错误 | 异常层次 + `.code` 属性 | Python 惯用，同时保持 C 兼容 |
| Go 密钥格式 | `*[32]byte` / `*[64]byte` | 编译时数组保证大小 |
| Python 密钥格式 | `bytes` | 原生不可变类型 |

---

## 八、最终文件清单

```
naion/
├── naion.h          # C 参考实现（已有）
├── naion.c          # C 驱动文件（已有）
├── naion.go         # ← Go 单文件实现
├── compat.go        #   Go 兼容别名（可选，构建标签）
├── go.mod           #   Go 模块定义（已有，需确认）
├── go.sum           #   Go 依赖校验
├── naion_test.go    #   Go 测试
├── naion.py         # ← Python 单文件实现
├── test_naion.py    #   Python 测试
├── plan02.md        #   本设计文档
├── PROTOCOL.md      #   协议规范（已有）
└── test/
    └── test.c       #   C 测试（已有）
```
