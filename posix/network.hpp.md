# cpl/posix/network.hpp - POSIX 平台的 HTTP 客户端与 UDP 发送

## 文件概述
此文件是 `win32/network.hpp` 在 POSIX 系统上的对应实现。它在普通套接字之上提供两个操作：一次 HTTP 请求和一个 UDP 数据报。整个文件在 Windows 上是空的。

调用方是一个系统服务，它必须在每一种网络故障下继续运行。所以此文件遵守下面的约束：

- 连接、发送和接收各有一个基于单调时钟的截止时间，任何等待都不从头重新开始（包括被信号打断的情况）。
- 每一个文件描述符在每一条路径上都会被关闭。
- 没有全局状态，也没有静态状态，所以任意多个线程可以同时调用。
- 没有异常从这些函数里逸出。
- 响应体分段读取，从不预先按声明的大小分配内存。

这里没有限制的一件事是域名解析。解析由 `getaddrinfo()` 完成，耗时取决于系统的解析器。字面地址不会到达域名服务器，所以立即完成。

## 主要功能

### 1. 命名空间结构

```
cpl::sys::network::wrapper
├── Errors          本文件专用的错误码
├── HttpResponse    一次 HTTP 响应
├── HttpOptions     一次请求的时间和大小限制
├── HttpRequest()   一次明文 HTTP 请求
├── UdpSend()       一个 UDP 数据报
└── impl            内部实现
```

### 2. HttpRequest

```cpp
Result<HttpResponse> HttpRequest(const std::string &url, const Stream &body,
                                 const char *method = "POST",
                                 const HttpOptions &options = HttpOptions());
```

执行一次明文 HTTP 请求并返回响应。状态码 400 或 500 是成功的结果（带响应体）；只有传输问题和协议问题才是错误。

```cpp
struct HttpResponse {
    int status = 0;                                    // HTTP 状态码
    std::vector<std::pair<std::string, std::string>> headers;  // 小写的 header 名
    Stream body;                                       // 响应体
};

struct HttpOptions {
    uint32_t connectTimeoutMs = 10000;   // 所有解析出的地址的连接尝试共用一个截止时间
    uint32_t sendTimeoutMs = 30000;      // 整个请求的发送
    uint32_t recvTimeoutMs = 60000;      // 整个响应，从第一个字节到最后一个字节
    size_t maxBodyBytes = 256 * 1024;    // 响应体的上限，不预先分配
    const char *contentType = "application/octet-stream";
};
```

值为 0 的超时取默认值。

### 3. UdpSend

```cpp
Int32Result UdpSend(const std::string &host, const uint16_t port, const Stream &data,
                    const uint32_t timeoutMs = 5000);
```

向 `host` 发送一个 UDP 数据报。`host` 可以是点分的 IPv4 地址、IPv6 地址（带或不带方括号）或域名。值为 0 的超时表示不设发送超时。

## 支持的 HTTP 范围

- 只支持 `http://`。`https://` 和其它方案在发起连接之前就被拒绝，与 Windows XP 的传输约束一致。
- 方法名转成大写后发送。`GET` 不带请求体。
- 响应体按 `Content-Length` 读取；没有 `Content-Length` 时，连接关闭即响应结束（HTTP/1.0 的做法）。
- 支持 `Transfer-Encoding: chunked`。其它传输编码是错误。
- `204`、`304` 和 `HEAD` 的响应没有响应体，即使连接仍然保持打开。
- 中间响应（例如 `100 Continue`）被跳过，返回最终的响应。
- 不跟随重定向。`3xx` 作为一个普通的响应返回，由调用方处理。
- header 块的上限是 16 KB。

## 错误

| 错误码 | 含义 |
|---|---|
| `ResolveFailed` | `getaddrinfo()` 没有找到地址 |
| `ConnectFailed` | 连接被拒绝、不可达或超时 |
| `SendFailed` | 发送请求或数据报失败 |
| `ReceiveFailed` | `poll()` 或 `recv()` 失败 |
| `ReceiveTimedOut` | 响应没有在期限内到达 |
| `IncompleteResponse` | 对端在响应完整之前关闭了连接 |
| `MalformedResponse` | 违反这里接受的 HTTP 语法 |
| `BodyTooLarge` | 响应体超过 `maxBodyBytes` |
| `InternalError` | 捕获了一个异常 |

调用方给错的参数报告为 `cpl::Error::InvalidArgument`，分配失败报告为 `cpl::Error::OutOfMemory`。每一个错误原因都以源文件位置结尾。

## 依赖关系

- `base.hpp`：`Result`、`MakeErr`。
- POSIX 套接字接口：`socket`、`connect`、`poll`、`recv`、`send`、`getaddrinfo`。

## 使用场景

### 1. 心跳

```cpp
cpl::sys::network::wrapper::HttpOptions options;
options.connectTimeoutMs = 10000;
options.recvTimeoutMs = 60000;
const auto response = cpl::sys::network::wrapper::HttpRequest(url, packet, "POST", options);
```

### 2. 发送告警

```cpp
cpl::sys::network::wrapper::UdpSend(host, port, packet, 3000);
```

## 注意事项

- 向一个已经被对端关闭的连接写入时，得到的是一个错误，不是 `SIGPIPE`。
- 接收阶段被信号打断不会破坏请求：等待继续，直到期限到达。
- 域名解析不受这里的截止时间约束。调用方应当尽量传字面地址。

## 测试

测试文件是 `test/test_posix_network.cpp`，共 25 个用例，整个文件在 Windows 上被跳过。

每一个用例在本进程的一个线程上启动一个按脚本应答的 TCP 服务器或一个 UDP 接收端，绑定到环回接口的临时端口，所以测试不依赖网络。每一个用例有一个看门狗，一个用例卡住时它终止整个测试进程，所以卡住的用例不会阻塞一次测试运行。

测试覆盖：带请求体的 `POST`、`400` 和 `500`、分块传输、HTTP/1.0 的结束方式、超过上限的响应体、畸形的响应、过大的 header 块、中途关闭的连接、关闭的端口、不应答的服务器、`GET`、`204`、`304`、`HEAD`、中间响应、域名解析、IPv6 字面地址、8 MB 的请求体、发送超时、已关闭的连接、信号打断、多线程并发，以及 `UdpSend` 的投递、拒绝和无法解析的域名。
