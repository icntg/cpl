# cpl/win32/network.hpp - 网络操作工具

## 文件概述
此文件定义了 Windows 平台的网络操作工具，包括 HTTP POST 请求、UDP 发送和网络地址转换等功能。

## 设计原则
- 简化网络操作
- 支持加密传输
- RAII 模式管理资源
- 统一的错误处理

## 主要功能

### 1. utility 命名空间 - 网络工具函数

#### 1.1 inet_ntop - 网络地址转字符串

**功能**: 将 `sockaddr_in` 结构转换为点分十进制 IP 字符串

**函数签名**:
```cpp
inline std::string inet_ntop(const struct sockaddr_in &addr)
```

**参数**:
- `addr`: `sockaddr_in` 结构

**返回值**: IP 字符串（如 "192.168.1.1"）

**实现逻辑**:
```cpp
1. 提取 IP 地址字节
2. 格式化为点分十进制
3. 返回字符串
```

**使用示例**:
```cpp
sockaddr_in addr;
addr.sin_addr.s_addr = inet_addr("192.168.1.1");

std::string ip = inet_ntop(addr);
// ip = "192.168.1.1"
```

#### 1.2 inet_pton - 字符串转网络地址

**功能**: 将点分十进制 IP 字符串转换为 `sockaddr_in` 结构

**函数签名**:
```cpp
inline int32_t inet_pton(_Out_ struct sockaddr_in &addr, const std::string &ip)
```

**参数**:
- `addr`: 输出 `sockaddr_in` 结构
- `ip`: IP 字符串（如 "192.168.1.1"）

**返回值**:
- 0: 成功
- -1: 格式无效

**实现逻辑**:
```cpp
1. 解析 IP 字符串（4 个八位组）
2. 组合成 32 位整数（主机字节序）
3. 转换为网络字节序
4. 填充 sockaddr_in 结构
```

**使用示例**:
```cpp
sockaddr_in addr;
int32_t ret = inet_pton(addr, "192.168.1.1");

if (ret == 0) {
    // 转换成功
    // addr.sin_addr.s_addr = 0xC0A80101
}
```

### 2. win32 命名空间 - Windows 网络函数

#### 2.1 HTTPPost - HTTP POST 请求

**功能**: 发送 HTTP POST 请求并返回响应

**函数签名**:
```cpp
inline Stream HTTPPost(
    _In_ const std::string &url,
    _In_ Stream &data
)
```

**参数**:
- `url`: 请求 URL
- `data`: POST 数据

**返回值**: 响应数据（Stream 类型）

**实现逻辑**:
```cpp
1. 检查 WinINet API 可用性
2. 解析 URL（主机名、路径、端口）
3. 创建 Internet 会话
4. 连接到服务器
5. 创建 HTTP 请求
6. 发送 POST 数据
7. 读取响应
8. 关闭所有句柄
```

**HTTP 头部**:
```cpp
Content-Type: application/x-www-form-urlencoded
```

**使用示例**:
```cpp
// 准备数据
std::string postData = "key=value&name=test";
Stream data(postData.begin(), postData.end());

// 发送 POST 请求
Stream response = HTTPPost("http://example.com/api", data);

// 处理响应
std::string resp(response.begin(), response.end());
std::cout << resp << std::endl;
```

**错误处理**:
- URL 解析失败 → 抛出 `std::invalid_argument`
- API 不可用 → 抛出 `std::runtime_error`
- 网络错误 → 抛出 `std::runtime_error`

#### 2.2 UDPSend - UDP 数据发送

**功能**: 发送 UDP 数据包

**函数签名**:
```cpp
inline int32_t UDPSend(
    _In_ const std::string &host,
    _In_ const uint16_t port,
    _In_ const Stream &data,
    _In_ const bool initWSAData = true
)
```

**参数**:
- `host`: 目标主机 IP
- `port`: 目标端口
- `data`: 要发送的数据
- `initWSAData`: 是否初始化 WSA（默认 true）

**返回值**:
- ERROR_SUCCESS: 成功
- 其他: 错误码

**实现逻辑**:
```cpp
1. 检查 Ws2_32 API 可用性
2. 初始化 Winsock（如果需要）
3. 创建 UDP 套接字
4. 设置目标地址
5. 发送数据
6. 关闭套接字
7. 清理 Winsock（如果需要）
```

**使用示例**:
```cpp
// 准备数据
std::string message = "Hello, UDP!";
Stream data(message.begin(), message.end());

// 发送 UDP 数据
int32_t ret = UDPSend("192.168.1.100", 8080, data);

if (ret == ERROR_SUCCESS) {
    // 发送成功
}
```

**多次发送**:
```cpp
// 只初始化一次
int32_t ret = UDPSend("192.168.1.100", 8080, data, true);
ret = UDPSend("192.168.1.100", 8080, data, false);
ret = UDPSend("192.168.1.100", 8080, data, false);
```

**错误处理**:
- WSA 初始化失败 → 抛出异常
- 套接字创建失败 → 抛出异常
- 发送失败 → 抛出异常

### 3. wrapper 命名空间 - 包装函数

#### 3.1 UDPSend - UDP 发送（带加密）

**功能**: 发送 UDP 数据包（可选加密）

**函数签名**:
```cpp
inline int32_t UDPSend(
    const std::string &host,
    const UINT16 port,
    const Stream &data,
    crypto::stl::ISync *cryptoProvider = nullptr
)
```

**参数**:
- `host`: 目标主机 IP
- `port`: 目标端口
- `data`: 要发送的数据
- `cryptoProvider`: 加密提供者（可选，默认 nullptr）

**返回值**:
- ERROR_SUCCESS: 成功
- 其他: 错误码

**实现逻辑**:
```cpp
1. 如果有加密提供者，加密数据
2. 调用 win32::UDPSend 发送
```

**使用示例**:

**明文发送**:
```cpp
std::string message = "Hello, UDP!";
Stream data(message.begin(), message.end());

UDPSend("192.168.1.100", 8080, data);
```

**加密发送**:
```cpp
std::string message = "Secret message";
Stream data(message.begin(), message.end());

AES256Crypto crypto(key, iv);
UDPSend("192.168.1.100", 8080, data, &crypto);
```

#### 3.2 HTTPPost - HTTP POST 请求（带加密）

**功能**: 发送 HTTP POST 请求（可选加密）

**函数签名**:
```cpp
inline Stream HTTPPost(
    _In_ const std::string &url,
    const Stream &data,
    crypto::stl::ISync *cryptoProvider = nullptr
)
```

**参数**:
- `url`: 请求 URL
- `data`: POST 数据
- `cryptoProvider`: 加密提供者（可选，默认 nullptr）

**返回值**: 响应数据（Stream 类型）

**实现逻辑**:
```cpp
1. 如果有加密提供者，加密数据
2. Base64 编码
3. 调用 win32::HTTPPost 发送
4. 返回响应
```

**使用示例**:

**明文发送**:
```cpp
std::string postData = "key=value";
Stream data(postData.begin(), postData.end());

Stream response = HTTPPost("http://example.com/api", data);
```

**加密发送**:
```cpp
std::string postData = "secret=data";
Stream data(postData.begin(), postData.end());

AES256Crypto crypto(key, iv);
Stream response = HTTPPost("http://example.com/api", data, &crypto);
```

## 依赖关系
- `sys.hpp`: 系统函数
- `api.hpp`: API 动态加载

## 使用场景

### 1. HTTP API 调用

```cpp
// 准备数据
std::string json = "{\"name\":\"test\",\"value\":123}";
Stream data(json.begin(), json.end());

// 发送 POST 请求
Stream response = HTTPPost("http://api.example.com/data", data);

// 处理响应
std::string resp(response.begin(), response.end());
ParseJSON(resp);
```

### 2. UDP 广播

```cpp
// 准备消息
std::string message = "DISCOVERY";
Stream data(message.begin(), message.end());

// 发送到广播地址
UDPSend("255.255.255.255", 9999, data);
```

### 3. UDP 通信

```cpp
// 客户端
std::string message = "Hello, Server!";
Stream data(message.begin(), message.end());

UDPSend("192.168.1.100", 8080, data);
```

### 4. 加密 UDP 通信

```cpp
// 创建加密器
AES256Crypto crypto(key, iv);

// 加密发送
std::string message = "Secret data";
Stream data(message.begin(), message.end());

UDPSend("192.168.1.100", 8080, data, &crypto);
```

### 5. 加密 HTTP 请求

```cpp
// 创建加密器
AES256Crypto crypto(key, iv);

// 加密发送
std::string json = "{\"secret\":\"data\"}";
Stream data(json.begin(), json.end());

Stream response = HTTPPost("http://api.example.com/upload", data, &crypto);
```

### 6. 批量 UDP 发送

```cpp
// 初始化 Winsock 一次
std::vector<std::pair<std::string, std::string>> targets = {
    {"192.168.1.1", "Hello, 1!"},
    {"192.168.1.2", "Hello, 2!"},
    {"192.168.1.3", "Hello, 3!"}
};

bool first = true;
for (const auto &[host, msg] : targets) {
    Stream data(msg.begin(), msg.end());
    UDPSend(host, 8080, data, first);
    first = false;
}
```

## 性能优化

### 1. 重用 WSA 初始化

```cpp
// 只初始化一次
UDPSend(host, port, data1, true);  // 初始化 WSA
UDPSend(host, port, data2, false); // 复用
UDPSend(host, port, data3, false); // 复用
```

### 2. 批量发送

```cpp
// 使用单个 HTTP 连接
// 注意：当前实现每次都创建新连接
// 可以扩展为长连接复用
```

### 3. 缓存加密器

```cpp
// 缓存加密器
static AES256Crypto crypto(key, iv);

// 复用加密器
for (const auto &data : dataList) {
    HTTPPost(url, data, &crypto);
}
```

## 错误处理

### 1. HTTP 错误

```cpp
try {
    Stream response = HTTPPost("http://example.com/api", data);
} catch (const std::invalid_argument &e) {
    // URL 格式错误
    std::cerr << "Invalid URL: " << e.what() << std::endl;
} catch (const std::runtime_error &e) {
    // 网络错误
    std::cerr << "Network error: " << e.what() << std::endl;
}
```

### 2. UDP 错误

```cpp
try {
    UDPSend("192.168.1.100", 8080, data);
} catch (const std::runtime_error &e) {
    // 发送失败
    std::cerr << "UDP error: " << e.what() << std::endl;
}
```

### 3. 加密错误

```cpp
try {
    UDPSend(host, port, data, &crypto);
} catch (const std::exception &e) {
    // 加密或发送失败
    std::cerr << "Error: " << e.what() << std::endl;
}
```

## 注意事项

### 1. WSA 初始化

- 默认每次调用都初始化 WSA
- 批量发送时只初始化一次
- 必须在退出前清理

### 2. HTTP 连接

- 每次请求创建新连接
- 不支持连接复用
- 不支持 HTTPS

### 3. UDP 可靠性

- UDP 不保证数据到达
- 不保证数据顺序
- 可能丢包

### 4. 加密

- 加密会增加数据大小
- 加密会增加延迟
- 必须同步密钥

### 5. 线程安全

- 当前实现不是线程安全
- 多线程使用需要外部同步
- WSA 初始化需要谨慎

## 最佳实践

### 1. 错误处理

```cpp
try {
    Stream response = HTTPPost(url, data);
} catch (const std::exception &e) {
    LOG_E("HTTP error: %s", e.what());
    return false;
}
```

### 2. 资源管理

```cpp
// 使用 RAII
{
    // 发送数据
    UDPSend(host, port, data);
} // 自动清理
```

### 3. 加密通信

```cpp
// 始终加密敏感数据
if (IsSensitive(data)) {
    HTTPPost(url, data, &crypto);
} else {
    HTTPPost(url, data);
}
```

### 4. 性能优化

```cpp
// 重用 WSA 初始化
static bool wsaInitialized = false;
static std::mutex wsaMutex;

std::lock_guard<std::mutex> lock(wsaMutex);
UDPSend(host, port, data, !wsaInitialized);
wsaInitialized = true;
```

### 5. 日志记录

```cpp
// 记录网络操作
LOG_I("Sending UDP to %s:%d", host.c_str(), port);
UDPSend(host, port, data);
LOG_I("UDP sent successfully");
```

## 扩展性

### 1. 添加 HTTPS 支持

```cpp
inline Stream HTTPSPost(
    _In_ const std::string &url,
    _In_ Stream &data
) {
    // 使用 WinHTTP 或 OpenSSL
    // 实现 HTTPS 支持
}
```

### 2. 添加 UDP 接收

```cpp
inline Stream UDPRecv(
    _In_ const uint16_t port,
    _In_ const size_t maxSize
) {
    // 接收 UDP 数据
    // 返回数据和发送者地址
}
```

### 3. 添加连接池

```cpp
class HTTPConnectionPool {
public:
    HTTPConnectionPool(const std::string &host, uint16_t port);
    Stream SendRequest(const Stream &data);
private:
    std::vector<HINTERNET> connections_;
};
```

### 4. 添加超时控制

```cpp
inline int32_t UDPSendEx(
    _In_ const std::string &host,
    _In_ const uint16_t port,
    _In_ const Stream &data,
    _In_ const DWORD timeout
) {
    // 设置发送超时
    // 超时后返回错误
}
```

## 实际应用（IFW 项目）

### 1. 配置同步

```cpp
// 同步配置到服务器
Stream config = config::config->Serialize();
HTTPPost("http://server.example.com/sync", config);
```

### 2. 日志上报

```cpp
// 上报日志到服务器
Stream logs = CollectLogs();
HTTPPost("http://server.example.com/logs", logs);
```

### 3. 心跳检测

```cpp
// 发送心跳包
std::string heartbeat = "HEARTBEAT";
Stream data(heartbeat.begin(), heartbeat.end());

UDPSend("server.example.com", 9999, data);
```

### 4. 规则更新

```cpp
// 从服务器获取规则
Stream request("GET_RULES");
Stream response = HTTPPost("http://server.example.com/rules", request);

ParseRules(response);
```

### 5. 告警通知

```cpp
// 发送告警通知
std::string alert = "ALERT: Intrusion detected";
Stream data(alert.begin(), alert.end());

UDPSend("alert.example.com", 5555, data);
```

### 6. 加密通信

```cpp
// 加密上报数据
AES256Crypto crypto(key, iv);
Stream data = CollectSensitiveData();

HTTPPost("https://server.example.com/upload", data, &crypto);
```

## 调试技巧

### 1. 验证 HTTP 请求

```cpp
// 发送请求
Stream response = HTTPPost(url, data);

// 检查响应
std::string resp(response.begin(), response.end());
LOG_I("Response: %s", resp.c_str());
```

### 2. 验证 UDP 发送

```cpp
// 发送数据
int32_t ret = UDPSend(host, port, data);

// 检查返回值
if (ret == ERROR_SUCCESS) {
    LOG_I("UDP sent successfully");
} else {
    LOG_E("UDP send failed: %ld", ret);
}
```

### 3. 捕获网络包

```cpp
// 使用 Wireshark 或 tcpdump
// 捕获网络包验证发送
```

### 4. 模拟网络错误

```cpp
// 使用错误的地址测试错误处理
try {
    UDPSend("192.168.999.999", 8080, data);
} catch (const std::exception &e) {
    LOG_I("Caught expected error: %s", e.what());
}
```

## 总结

### 推荐使用顺序

1. **HTTP API**: `wrapper::HTTPPost()` (支持加密）
2. **UDP 通信**: `wrapper::UDPSend()` (支持加密）
3. **地址转换**: `utility::inet_ntop()` / `utility::inet_pton()`
4. **底层控制**: `win32::HTTPPost()` / `win32::UDPSend()`

### 关键要点

- 使用 wrapper 函数支持加密
- HTTP 用于可靠传输
- UDP 用于快速传输
- WSA 初始化需要谨慎
- 错误处理必须完善
- 加密敏感数据
- 记录网络操作
- 测试网络连接