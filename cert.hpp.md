# cpl/cert.hpp - Ed25519 证书链与配置 jwt 校验

## 文件概述
此文件校验服务器下发的配置令牌。令牌是一个 jwt 形式的字符串 `header_b64.payload_b64.signature_b64`（base64url 编码，不带填充）。header 的 `x5c` 里恰好带一张 DER 编码的 X.509 证书。终端内嵌一把根 Ed25519 公钥，只有当证书由这个根签发、并且 jwt 由证书里的公钥签名时，才接受这个令牌。

此文件不打开文件，不读取时钟，也不调用任何平台接口。调用方提供当前时间，所以全部函数都是纯函数，可以在多个线程里同时调用。

规则依据 `client/DESIGN_terminal_groups.md` 第 4.3.1 节。

## 规则

规则按下面的顺序检查，第一个被违反的规则决定错误码。

| 规则 | 内容 |
|---|---|
| R1 | 令牌恰好有三段。header 是 JSON 对象，`alg` 是 `EdDSA`，`x5c` 是恰好带一个字符串的数组。payload 是 JSON 对象，含 `group`（字符串）、`serial`、`iat`、`exp`（整数）和 `config`（对象） |
| R2 | 每一段都能按 base64url 解码，证书是合法的 DER，并且符合固定的证书模板 |
| R3 | 证书的两个算法标识和主体公钥的算法都是 Ed25519（1.3.101.112），不带参数 |
| R4 | 证书在 tbsCertificate 上的签名能用根公钥验证通过 |
| R5 | `notBefore - 86400 <= now <= notAfter` |
| R6 | 第三段解码后是 64 字节，并且是证书公钥对原文 `header_b64.payload_b64` 的有效 Ed25519 签名 |
| R8 | `iat - 86400 <= now <= exp` |

已经安装到本地的配置永久有效，所以加载本地配置时用 `VerifyConfigJwt(..., SkipTime)` 再校验一次，这一次不检查 R5 和 R8。

## 主要功能

### 1. 命名空间结构

```
cpl::cert
├── Certificate          解析出来的证书
├── VerifiedJwt          校验通过的 jwt
├── TimeCheck            EnforceTime / SkipTime
├── ParseCertificate()   解析证书
├── VerifyIssuedBy()     R4 + R5
├── VerifyConfigJwt()    R1 到 R6 和 R8
└── impl                 内部实现
```

### 2. 数据结构

```cpp
struct Certificate {
    Stream tbs;                          // tbsCertificate 的 DER 编码
    Stream signature;                    // 签名字节
    std::array<uint8_t, 32> publicKey{}; // 主体公钥
    int64_t notBefore = 0;               // Unix 秒（UTC）
    int64_t notAfter = 0;                // Unix 秒（UTC）
};

struct VerifiedJwt {
    std::string payloadJson;  // 解码后的 payload
    std::string group;        // payload.group
    int64_t serial = 0;       // payload.serial
};
```

### 3. ParseCertificate

```cpp
Result<Certificate> ParseCertificate(const uint8_t *der, const size_t size);
```

解析一张 Ed25519 X.509 证书的 DER 编码，执行 R2 和 R3 的结构检查，取出公钥和有效期。这个函数不验证签名。

DER 读取器接受长度的短格式和长格式（最多四个八位组），拒绝不定长格式、过长的长度编码、被截断的元素、高标签号格式，以及证书后面的多余字节。

可选元素 `issuerUniqueID` 和 `subjectUniqueID` 是原始类型，它们的内容八位组不按 DER 元素读取。

失败时错误码是 `CertParseError`，错误原因里写明是 R2 还是 R3。当主体公钥的算法不是 Ed25519 时，公钥长度不是 32 字节这一情况归到 R3；其余情况归到 R2。

### 4. VerifyIssuedBy

```cpp
Int32Result VerifyIssuedBy(const Certificate &cert, const uint8_t issuerPublicKey[32], const int64_t nowUnix);
```

执行 R4 和 R5。成功时返回 0，失败时返回第一个被违反的规则（`RuleViolatedBase + 4` 或 `+ 5`）。

### 5. VerifyConfigJwt

```cpp
Result<VerifiedJwt> VerifyConfigJwt(const std::string &jwt, const uint8_t rootPublicKey[32],
                                    const int64_t nowUnix, const int32_t check = EnforceTime);
```

按顺序执行 R1 到 R6 和 R8。成功时返回解码后的 payload；失败时返回 `RuleViolatedBase + <规则号>`。

`check` 的类型是 `int32_t`，因为 C 风格的调用方也使用这个头文件。只有 `SkipTime` 不检查时间规则，其它值都等同于 `EnforceTime`。

header 段或 payload 段不能解码时按 R2 报告。这两个段是在检查 R1 的过程中读取的，不能解码的段才是失败的根源。

## 错误码

| 错误码 | 值 | 含义 |
|---|---|---|
| `CertParseError` | `0x40000001` | DER 不合法，或证书不符合模板 |
| `JwtFormatError` | `0x40000002` | 不是三段，或 base64url、JSON 不合法 |
| `RuleViolatedBase` | `0x40000100` | 加上规则号（1 到 8）就是被违反的规则 |

`ParseCertificate` 的每一个失败都用 `CertParseError` 报告，它的原因里写明 R2 或 R3。`VerifyIssuedBy` 报告 `RuleViolatedBase + 4` 或 `+ 5`。`VerifyConfigJwt` 对每一个失败都报告 `RuleViolatedBase + <规则号>`。

每一个错误原因都以源文件位置结尾，形式是 `<文件:行号>`，例如 `</src/cpl/cert.hpp:509>`。

## 依赖关系

- `base.hpp`：`Result`、`MakeErr`、`Error`。
- `naion.hpp`：`naion_sign_ed25519_verify_detached`。
- `vendor/nlohmann/json/json.hpp`：解析 header 和 payload。

## 使用场景

### 1. 接收服务器下发的新配置

```cpp
const auto verified = cpl::cert::VerifyConfigJwt(jwt, rootKey, now, cpl::cert::EnforceTime);
if (!verified) {
    // 拒收：沿用本地旧配置，并且记录 verified.error()。
}
```

### 2. 加载本地的配置文件

```cpp
const auto verified = cpl::cert::VerifyConfigJwt(jwt, rootKey, now, cpl::cert::SkipTime);
```

本地已经安装的配置永久有效，所以不检查任何时间窗。

## 注意事项

- 时间窗一律使用调用方提供的本地时钟。终端时钟错乱的结果是拒收新配置，本地的旧配置不受影响。
- 证书模板只接受 Ed25519 证书。其它算法的证书在 R3 被拒绝，所以弱算法证书不能通过校验。
- 时间窗在两端各留一天的余量（86400 秒），所以证书签发时刻和 jwt 签发时刻附近的时钟偏差不会造成误拒。
- 源码是 C++11，可以在 g++ 和 MSVC v141（Windows XP 目标）下编译。

## 测试

测试文件是 `test/test_cert.cpp`，共 28 个用例。固定的测试向量来自 `test/cert_vectors.inc`，这个文件由 `test/gen_cert_vectors.go` 生成：

```
go run test/gen_cert_vectors.go > test/cert_vectors.inc
```

生成器的每一个密钥都由固定的种子推导，每一张证书的序列号和有效期都固定，所以输出可以重现。生成器会自己检查输出（证书链签名、令牌签名），发现坏的向量时以状态 1 退出。

测试覆盖四类样本：通过、过期、篡改、伪造。另外还在运行时拼装带缺陷的证书，因为 `ParseCertificate` 不验证签名。
