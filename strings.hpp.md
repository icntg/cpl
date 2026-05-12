# cpl/strings.hpp - 字符串处理工具

## 文件概述
此文件定义了 CPL 库的字符串处理工具函数，包括格式化、编码转换、字符串操作等功能。

## 主要功能

### 1. 命名空间结构
```
cpl::strings
├── VFormat() (可变参数格式化）
├── Format() (字符串格式化）
├── WStringToUTF16LEBytes() (宽字符串转字节）
├── UTF16LEBytesToWString() (字节转宽字符串）
├── Trim() (去除空白）
├── Split() (字符串分割）
├── Join() (字符串连接）
├── IsDigital() (是否数字）
├── Upper()/ToUpper() (转大写）
├── Lower()/ToLower() (转小写）
├── StartsWith() (是否以...开头）
├── EndsWith() (是否以...结尾）
├── StrInStr() (子字符串查找）
├── FromWString() (宽字符串转窄字符串）
├── FromString() (窄字符串转宽字符串）
├── ReplaceAll() (替换所有）
├── SerializeWString() (序列化宽字符串）
└── DeserializeStream() (反序列化字节流）
```

### 2. 格式化函数

#### 2.1 VFormat (可变参数版本）

**功能**: 格式化字符串（可变参数版本）

**重载**:

**窄字符串版本**:
```cpp
inline int32_t VFormat(
    _Out_ size_t &nWritten,
    _Out_ std::string &out,
    _In_ const char *tpl,
    _In_ va_list ap
)
```

**宽字符串版本**:
```cpp
inline int32_t VFormat(
    _Out_ size_t &nWritten,
    _Out_ std::wstring &out,
    _In_ const wchar_t *tpl,
    _In_ va_list ap
)
```

**参数**:
- `nWritten`: 输出写入的字符数
- `out`: 输出格式化后的字符串
- `tpl`: 格式化模板
- `ap`: 可变参数列表

**返回值**: 0: 成功

**实现原理**:
```cpp
// 动态调整缓冲区大小
do {
    len = len << 1u;  // 缓冲区大小翻倍
    buffer.resize(len);
    nWritten = vsnprintf(buffer.data(), len, tpl, ap);
} while (nWritten >= len - 1);
```

#### 2.2 Format (简化版本)

**功能**: 字符串格式化（简化版本）

**重载 1**: 带输出参数
```cpp
inline int32_t Format(
    _Out_ size_t &nWritten,
    _Out_ std::string &out,
    _In_ const char *tpl,
    ...
)
```

**重载 2**: 返回字符串
```cpp
inline std::string Format(const char *tpl, ...)
```

**宽字符串版本**:
```cpp
inline std::wstring Format(const wchar_t *tpl, ...)
```

**参数**:
- `nWritten`: 输出写入的字符数
- `out`: 输出格式化后的字符串
- `tpl`: 格式化模板
- `...`: 可变参数

**返回值**:
- 带输出参数版本: 0: 成功
- 返回字符串版本: 格式化后的字符串
- 异常: 格式化失败时抛出 `std::runtime_error`

**使用示例**:
```cpp
// 简单格式化
std::string s = cpl::strings::Format("Hello %s", "World");
// "Hello World"

// 带输出参数
size_t nWritten;
std::string out;
cpl::strings::Format(nWritten, out, "Value: %d", 42);
// "Value: 42"

// 宽字符串
std::wstring ws = cpl::strings::Format(L"你好 %s", L"世界");
// L"你好 世界"
```

### 3. 编码转换

#### 3.1 WStringToUTF16LEBytes

**功能**: 宽字符串转换为 UTF-16LE 字节流

**函数签名**:
```cpp
inline Stream WStringToUTF16LEBytes(const std::wstring &ws)
```

**参数**:
- `ws`: 宽字符串

**返回值**: UTF-16LE 字节流（`std::vector<uint8_t>`）

**实现**:
```cpp
const auto *pData = reinterpret_cast<const uint8_t *>(ws.c_str());
const size_t byteCount = ws.length() * sizeof(wchar_t);
return Stream{pData, pData + byteCount};
```

**使用示例**:
```cpp
std::wstring ws = L"测试";
Stream bytes = cpl::strings::WStringToUTF16LEBytes(ws);
// [0x6D 0x4B, 0xD5 0x8B] (UTF-16LE)
```

#### 3.2 UTF16LEBytesToWString

**功能**: UTF-16LE 字节流转换为宽字符串

**函数签名**:
```cpp
inline std::wstring UTF16LEBytesToWString(const Stream &stream)
```

**参数**:
- `stream`: 字节流

**返回值**: 宽字符串

**检查**:
- 字节流长度必须为偶数
- 否则返回空字符串

**使用示例**:
```cpp
Stream bytes = {0x6D, 0x4B, 0xD5, 0x8B};
std::wstring ws = cpl::strings::UTF16LEBytesToWString(bytes);
// L"测试"
```

#### 3.3 FromWString

**功能**: 宽字符串转换为窄字符串（多字节）

**重载**:

**带输出参数**:
```cpp
inline int32_t FromWString(
    const std::wstring &s,
    std::string &out,
    const UINT CodePage = CP_ACP
)
```

**返回字符串**:
```cpp
inline std::string FromWString(
    const std::wstring &s,
    const UINT CodePage = CP_ACP
)
```

**参数**:
- `s`: 宽字符串
- `out`: 输出窄字符串
- `CodePage`: 代码页（默认 CP_ACP）

**返回值**:
- ERROR_SUCCESS: 成功
- ERROR_NOT_ENOUGH_MEMORY: 内存不足
- 其他: Windows API 错误码

**使用示例**:
```cpp
std::wstring ws = L"测试";
std::string s = cpl::strings::FromWString(ws);
// "测试" (根据系统代码页）
```

#### 3.4 FromString

**功能**: 窄字符串转换为宽字符串

**重载**:

**带输出参数**:
```cpp
inline int32_t FromString(
    const std::string &s,
    std::wstring &out,
    const UINT CodePage = CP_ACP
)
```

**返回字符串**:
```cpp
inline std::wstring FromString(
    const std::string &s,
    const UINT CodePage = CP_ACP
)
```

**参数**:
- `s`: 窄字符串
- `out`: 输出宽字符串
- `CodePage`: 代码页（默认 CP_ACP）

**返回值**:
- ERROR_SUCCESS: 成功
- ERROR_NOT_ENOUGH_MEMORY: 内存不足
- 其他: Windows API 错误码

**使用示例**:
```cpp
std::string s = "测试";
std::wstring ws = cpl::strings::FromString(s);
// L"测试"
```

### 4. 字符串操作

#### 4.1 Trim

**功能**: 去除字符串两端的空白字符

**函数签名**:
```cpp
inline std::string Trim(const std::string &str)
```

**参数**:
- `str`: 原始字符串

**返回值**: 去除空白后的字符串

**空白字符**: 空格、制表符、换行符、回车符、换页符、垂直制表符

**使用示例**:
```cpp
std::string s = "  hello  ";
std::string trimmed = cpl::strings::Trim(s);
// "hello"
```

#### 4.2 Split

**功能**: 字符串分割

**函数签名**:
```cpp
inline std::vector<std::string> Split(
    const std::string &str,
    const std::string &delim
)
```

**参数**:
- `str`: 原始字符串
- `delim`: 分隔符

**返回值**: 分割后的字符串数组（空字符串会被过滤）

**使用示例**:
```cpp
std::string s = "a,b,c";
auto tokens = cpl::strings::Split(s, ",");
// ["a", "b", "c"]

// 带空格
std::string s2 = "a, b, c";
auto tokens2 = cpl::strings::Split(s2, ",");
// ["a", " b", " c"] (保留空格）
```

#### 4.3 Join

**功能**: 字符串连接

**函数签名**:
```cpp
inline std::string Join(
    const std::vector<std::string> &array,
    const std::string &delim
)
```

**参数**:
- `array`: 字符串数组
- `delim`: 分隔符

**返回值**: 连接后的字符串

**特殊情况**:
- 空数组: 返回 `""`
- 单元素: 返回该元素（不加分隔符）

**使用示例**:
```cpp
std::vector<std::string> arr = {"a", "b", "c"};
std::string s = cpl::strings::Join(arr, ",");
// "a,b,c"

// 单元素
std::vector<std::string> arr2 = {"a"};
std::string s2 = cpl::strings::Join(arr2, ",");
// "a"
```

#### 4.4 ReplaceAll

**功能**: 替换所有出现的子字符串

**函数签名**:
```cpp
inline std::string ReplaceAll(
    const std::string &str,
    const std::string &from,
    const std::string &to
)
```

**参数**:
- `str`: 原始字符串
- `from`: 要替换的子字符串
- `to`: 替换为的字符串

**返回值**: 替换后的字符串

**实现**:
```cpp
std::vector<std::string> t = Split(str, from);
return Join(t, to);
```

**使用示例**:
```cpp
std::string s = "hello world";
std::string result = cpl::strings::ReplaceAll(s, " ", "_");
// "hello_world"
```

### 5. 字符串检查

#### 5.1 IsDigital

**功能**: 检查字符串是否全是数字

**函数签名**:
```cpp
inline bool IsDigital(const std::string &s)
```

**参数**:
- `s`: 要检查的字符串

**返回值**:
- true: 全是数字
- false: 包含非数字字符

**使用示例**:
```cpp
cpl::strings::IsDigital("123");   // true
cpl::strings::IsDigital("12a");   // false
cpl::strings::IsDigital("");      // true
```

#### 5.2 StartsWith

**功能**: 检查字符串是否以指定前缀开头

**函数签名**:
```cpp
inline bool StartsWith(const std::string &str, const std::string &prefix)
```

**参数**:
- `str`: 原始字符串
- `prefix`: 前缀

**返回值**:
- true: 以指定前缀开头
- false: 不是

**使用示例**:
```cpp
cpl::strings::StartsWith("hello world", "hello");  // true
cpl::strings::StartsWith("hello world", "world");  // false
```

#### 5.3 EndsWith

**功能**: 检查字符串是否以指定后缀结尾

**函数签名**:
```cpp
inline bool EndsWith(const std::string &str, const std::string &suffix)
```

**参数**:
- `str`: 原始字符串
- `suffix`: 后缀

**返回值**:
- true: 以指定后缀结尾
- false: 不是

**使用示例**:
```cpp
cpl::strings::EndsWith("file.txt", ".txt");  // true
cpl::strings::EndsWith("file.txt", ".exe");  // false
```

### 6. 大小写转换

#### 6.1 Upper / ToUpper

**功能**: 转换为大写

**In-place 版本**:
```cpp
inline void Upper(std::string &str)
```

**返回新字符串版本**:
```cpp
inline std::string ToUpper(const std::string &str)
```

**参数**:
- `str`: 要转换的字符串

**实现**:
```cpp
for (auto i = 0; i < str.length(); i++) {
    auto ch = str[i];
    if (ch <= 'z' && ch >= 'a') {
        str[i] = static_cast<char>(ch - ('a' - 'A'));
    }
}
```

**使用示例**:
```cpp
std::string s = "hello";
cpl::strings::Upper(s);  // s = "HELLO"

std::string s2 = "world";
std::string s3 = cpl::strings::ToUpper(s2);  // s3 = "WORLD", s2 = "world"
```

#### 6.2 Lower / ToLower

**功能**: 转换为小写

**In-place 版本**:
```cpp
inline void Lower(std::string &str)
```

**返回新字符串版本**:
```cpp
inline std::string ToLower(const std::string &str)
```

**参数**:
- `str`: 要转换的字符串

**使用示例**:
```cpp
std::string s = "HELLO";
cpl::strings::Lower(s);  // s = "hello"

std::string s2 = "WORLD";
std::string s3 = cpl::strings::ToLower(s2);  // s3 = "world", s2 = "WORLD"
```

#### 6.3 Upper (单字符)

**功能**: 转换单个字符为大写

**函数签名**:
```cpp
inline char Upper(const char c)
```

**参数**:
- `c`: 字符

**返回值**: 大写字符

**使用示例**:
```cpp
char c = 'a';
char upper = cpl::strings::Upper(c);  // 'A'
```

### 7. 字符串查找

#### 7.1 StrInStr

**功能**: 在字符串中查找子字符串（不区分大小写）

**函数签名**:
```cpp
inline char *StrInStr(const char *mainStr, const char *subStr)
```

**参数**:
- `mainStr`: 主字符串
- `subStr`: 子字符串

**返回值**:
- 找到: 子字符串首次出现的位置指针
- 未找到: `nullptr`
- 空子字符串: 返回 `mainStr`

**特点**: 不区分大小写

**使用示例**:
```cpp
const char *s = "Hello World";
const char *sub = "hello";
char *pos = cpl::strings::StrInStr(s, sub);
// 返回 "Hello World" 中的 "Hello"
```

### 8. 序列化

#### 8.1 SerializeWString

**功能**: 序列化宽字符串为字节流

**函数签名**:
```cpp
inline Stream SerializeWString(const std::wstring &s)
```

**参数**:
- `s`: 宽字符串

**返回值**: 字节流（包含字符串内容和空终止符）

**实现**:
```cpp
const size_t byteCount = s.size() * sizeof(wchar_t);
const Stream stream(
    reinterpret_cast<const uint8_t *>(s.data()),
    reinterpret_cast<const uint8_t *>(s.data()) + byteCount
);
return stream;
```

**使用示例**:
```cpp
std::wstring ws = L"测试";
Stream stream = cpl::strings::SerializeWString(ws);
```

#### 8.2 DeserializeStream

**功能**: 从字节流反序列化宽字符串

**函数签名**:
```cpp
inline std::wstring DeserializeStream(const Stream &stream)
```

**参数**:
- `stream`: 字节流

**返回值**: 宽字符串

**使用示例**:
```cpp
Stream bytes = {0x6D, 0x4B, 0xD5, 0x8B, 0x00, 0x00};
std::wstring ws = cpl::strings::DeserializeStream(bytes);
// L"测试"
```

## 依赖关系
- `base.hpp`: 基础定义
- `string`: STL 字符串
- `vector`: STL 向量
- `cstdint`: 整型类型
- `cstdlib`: C 标准库
- `cstdarg`: 可变参数
- `new`: 动态内存
- `cstring`: C 字符串
- `cerrno`: 错误码
- `stdexcept`: 标准异常

## 关键设计决策

1. **动态缓冲区**:
   - 格式化时自动调整缓冲区大小
   - 避免固定大小限制
   - 双倍增长策略

2. **编码转换**:
   - 使用 Windows API
   - 支持多种代码页
   - 默认使用 CP_ACP

3. **字符串操作**:
   - 基于 STL
   - 返回新字符串（不修改原字符串）
   - 提供 in-place 版本

4. **序列化**:
   - 宽字符串序列化为 UTF-16LE
   - 保留字节序
   - 包含空终止符

## 注意事项
- `Format()` 失败时抛出异常
- 编码转换依赖系统代码页
- `StrInStr()` 不区分大小写
- `Split()` 过滤空字符串
- `Join()` 单元素不加分隔符

## 使用示例

### 格式化字符串
```cpp
// 简单格式化
std::string s = cpl::strings::Format("Hello %s, age %d", "Alice", 30);
// "Hello Alice, age 30"

// 宽字符串格式化
std::wstring ws = cpl::strings::Format(L"你好 %s", L"世界");
// L"你好 世界"
```

### 字符串操作
```cpp
// 去除空白
std::string s = "  hello  ";
std::string trimmed = cpl::strings::Trim(s);
// "hello"

// 分割字符串
std::string s = "a,b,c";
auto tokens = cpl::strings::Split(s, ",");
// ["a", "b", "c"]

// 连接字符串
std::vector<std::string> arr = {"a", "b", "c"};
std::string joined = cpl::strings::Join(arr, ",");
// "a,b,c"

// 替换字符串
std::string s = "hello world";
std::string replaced = cpl::strings::ReplaceAll(s, " ", "_");
// "hello_world"
```

### 大小写转换
```cpp
// 转大写
std::string s = "hello";
cpl::strings::Upper(s);  // "HELLO"

std::string s2 = cpl::strings::ToUpper("world");
// "WORLD"

// 转小写
std::string s = "HELLO";
cpl::strings::Lower(s);  // "hello"

std::string s2 = cpl::strings::ToLower("WORLD");
// "world"
```

### 字符串检查
```cpp
// 检查数字
cpl::strings::IsDigital("123");   // true
cpl::strings::IsDigital("12a");   // false

// 检查前缀
cpl::strings::StartsWith("hello world", "hello");  // true
cpl::strings::StartsWith("hello world", "world");  // false

// 检查后缀
cpl::strings::EndsWith("file.txt", ".txt");  // true
cpl::strings::EndsWith("file.txt", ".exe");  // false
```

### 编码转换
```cpp
// 宽字符串转窄字符串
std::wstring ws = L"测试";
std::string s = cpl::strings::FromWString(ws);
// "测试"

// 窄字符串转宽字符串
std::string s = "测试";
std::wstring ws = cpl::strings::FromString(s);
// L"测试"

// 宽字符串转字节流
std::wstring ws = L"测试";
Stream bytes = cpl::strings::WStringToUTF16LEBytes(ws);
// [0x6D 0x4B, 0xD5 0x8B]

// 字节流转宽字符串
Stream bytes = {0x6D, 0x4B, 0xD5 0x8B, 0x00 0x00};
std::wstring ws = cpl::strings::UTF16LEBytesToWString(bytes);
// L"测试"
```

### 序列化
```cpp
// 序列化宽字符串
std::wstring ws = L"测试";
Stream stream = cpl::strings::SerializeWString(ws);

// 反序列化字节流
std::wstring ws2 = cpl::strings::DeserializeStream(stream);