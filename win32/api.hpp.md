# cpl/win32/api.hpp - Windows API 动态加载封装

## 文件概述
此文件定义了 Windows DLL 动态加载的封装类，通过动态加载机制访问 Windows API 函数。

**注意**: 此文件由 `api_gen.py` 自动生成，请勿直接编辑。

## 设计原则
- 动态加载 Windows DLL
- 避免静态链接依赖
- 支持多 DLL 版本（通过 DLL_NAMES 尝试）
- 统一的加载/卸载接口

## 主要功能

### 1. 命名空间结构
```
cpl::sys::api
├── Crypt32 (加密库）
├── AdvAPI32 (高级服务）
├── bcrypt (下一代加密 API）
├── Ws2_32 (Windows Sockets）
├── WinINet (Internet 客户端）
├── IPv4 (IPv4 协议支持）
├── IPv6 (IPv6 协议支持）
├── PsAPI (进程状态）
├── NtDLL (Native API）
├── UserEnv (用户环境）
├── Kernel32 (内核库）
├── User32 (用户界面）
├── WtsAPI32 (终端服务）
├── MsImg32 (图像处理）
└── OpenSSL (加密库）
```

### 2. DynamicModule 基类

**继承**: `api::DynamicModule`

**公共接口**:
```cpp
virtual int32_t Load() = 0;
virtual int32_t Unload() = 0;
```

**加载流程**:
1. 遍历 DLL_NAMES 列表
2. 尝试加载每个 DLL
3. 加载成功后，加载所需的函数
4. 加载失败，尝试下一个 DLL
5. 所有 DLL 都失败，抛出异常

### 3. DLL 模块详解

#### 3.1 Crypt32::DynamicModule

**DLL 名称**: Crypt32.dll

**功能**: 加密相关 API

**导出函数**:
```cpp
CryptBinaryToStringA CryptBinaryToStringA;
```

**函数说明**:
- `CryptBinaryToStringA`: 将二进制数据转换为格式化字符串（ANSI 版本）

**使用场景**: 证书编码、密钥导出

#### 3.2 AdvAPI32::DynamicModule

**DLL 名称**: AdvAPI32.dll

**功能**: 高级服务 API（加密、注册表、服务等）

**导出函数**:
```cpp
RtlGenRandom RtlGenRandom;
CryptAcquireContextA CryptAcquireContextA;
CryptReleaseContext CryptReleaseContext;
CryptGenRandom CryptGenRandom;
CryptImportKey CryptImportKey;
CryptDestroyKey CryptDestroyKey;
CryptSetKeyParam CryptSetKeyParam;
CryptEncrypt CryptEncrypt;
CryptDecrypt CryptDecrypt;
CryptCreateHash CryptCreateHash;
CryptDestroyHash CryptDestroyHash;
CryptSetHashParam CryptSetHashParam;
CryptGetHashParam CryptGetHashParam;
CryptHashData CryptHashData;
```

**函数分类**:

**随机数生成**:
- `RtlGenRandom`: 系统随机数生成器
- `CryptGenRandom`: CryptoAPI 随机数生成

**加密/解密**:
- `CryptAcquireContextA`: 获取加密上下文
- `CryptReleaseContext`: 释放加密上下文
- `CryptImportKey`: 导入密钥
- `CryptDestroyKey`: 销毁密钥
- `CryptSetKeyParam`: 设置密钥参数
- `CryptEncrypt`: 加密数据
- `CryptDecrypt`: 解密数据

**哈希**:
- `CryptCreateHash`: 创建哈希对象
- `CryptDestroyHash`: 销毁哈希对象
- `CryptSetHashParam`: 设置哈希参数
- `CryptGetHashParam`: 获取哈希参数
- `CryptHashData`: 更新哈希数据

**使用场景**:
- 对称加密（AES, 3DES）
- 哈希计算（MD5, SHA1, SHA256）
- 随机数生成

#### 3.3 bcrypt::DynamicModule

**DLL 名称**: bcrypt.dll

**功能**: 下一代加密 API (CNG)

**导出函数**:
```cpp
BCryptGenRandom BCryptGenRandom;
```

**函数说明**:
- `BCryptGenRandom`: CNG 随机数生成器

**使用场景**: 安全随机数生成

#### 3.4 Ws2_32::DynamicModule

**DLL 名称**: Ws2_32.dll

**功能**: Windows Sockets 2.0 API

**导出函数**:
```cpp
WSAStartup WSAStartup;
WSACleanup WSACleanup;
WSAGetLastError WSAGetLastError;
socket socket;
htons htons;
inet_addr inet_addr;
sendto sendto;
closesocket closesocket;
setsockopt setsockopt;
bind bind;
recvfrom recvfrom;
ntohs ntohs;
ioctlsocket ioctlsocket;
```

**函数分类**:

**初始化/清理**:
- `WSAStartup`: 初始化 Winsock
- `WSACleanup`: 清理 Winsock
- `WSAGetLastError`: 获取最后错误码

**Socket 操作**:
- `socket`: 创建 socket
- `closesocket`: 关闭 socket
- `bind`: 绑定 socket 到地址
- `sendto`: 发送 UDP 数据
- `recvfrom`: 接收 UDP 数据
- `setsockopt`: 设置 socket 选项
- `ioctlsocket`: 控制 socket 模式

**地址转换**:
- `htons`: 主机字节序转网络字节序（short）
- `ntohs`: 网络字节序转主机字节序（short）
- `inet_addr`: 点分十进制转网络地址

**使用场景**:
- UDP 通信
- 网络编程
- Socket 编程

#### 3.5 WinINet::DynamicModule

**DLL 名称**: WinINet.dll

**功能**: Internet 客户端 API（HTTP/FTP）

**导出函数**:
```cpp
InternetOpenA InternetOpenA;
InternetConnectA InternetConnectA;
HttpOpenRequestA HttpOpenRequestA;
HttpSendRequestA HttpSendRequestA;
InternetReadFile InternetReadFile;
InternetCloseHandle InternetCloseHandle;
InternetCrackUrlA InternetCrackUrlA;
```

**函数分类**:

**连接管理**:
- `InternetOpenA`: 初始化 Internet 会话
- `InternetConnectA`: 建立连接（HTTP/FTP）
- `InternetCloseHandle`: 关闭 Internet 句柄

**HTTP 操作**:
- `HttpOpenRequestA`: 创建 HTTP 请求句柄
- `HttpSendRequestA`: 发送 HTTP 请求
- `InternetReadFile`: 读取数据

**URL 处理**:
- `InternetCrackUrlA`: 解析 URL

**使用场景**:
- HTTP 客户端
- 文件下载
- Web 请求

#### 3.6 IPv4::DynamicModule

**DLL 名称**: Iphlpapi.dll

**功能**: IPv4 协议支持

**导出函数**:
```cpp
GetAdaptersInfo GetAdaptersInfo;
GetAdaptersAddresses GetAdaptersAddresses;
GetIpForwardTable GetIpForwardTable;
DeleteIpForwardEntry DeleteIpForwardEntry;
CreateIpForwardEntry CreateIpForwardEntry;
```

**函数分类**:

**适配器信息**:
- `GetAdaptersInfo`: 获取适配器信息（IPv4）
- `GetAdaptersAddresses`: 获取适配器地址（IPv4/IPv6）

**路由表**:
- `GetIpForwardTable`: 获取 IP 路由表
- `DeleteIpForwardEntry`: 删除路由条目
- `CreateIpForwardEntry`: 创建路由条目

**使用场景**:
- 网络适配器枚举
- 路由表管理
- 网络配置

#### 3.7 IPv6::DynamicModule

**DLL 名称**: Iphlpapi.dll

**功能**: IPv6 协议支持

**导出函数**:
```cpp
GetIpForwardTable2 GetIpForwardTable2;
DeleteIpForwardEntry2 DeleteIpForwardEntry2;
FreeMibTable FreeMibTable;
```

**函数分类**:

**路由表**:
- `GetIpForwardTable2`: 获取 IP 路由表（v2）
- `DeleteIpForwardEntry2`: 删除路由条目（v2）

**内存管理**:
- `FreeMibTable`: 释放 MIB 表

**使用场景**:
- IPv6 路由表管理
- 网络配置

#### 3.8 PsAPI::DynamicModule

**DLL 名称**: Psapi.dll

**功能**: 进程状态 API

**导出函数**:
```cpp
GetModuleFileNameExA GetModuleFileNameExA;
EnumProcesses EnumProcesses;
EnumProcessModules EnumProcessModules;
EnumProcessModulesEx EnumProcessModulesEx;
```

**函数分类**:

**进程信息**:
- `EnumProcesses`: 枚举所有进程
- `GetModuleFileNameExA`: 获取模块文件名

**模块枚举**:
- `EnumProcessModules`: 枚举进程模块
- `EnumProcessModulesEx`: 枚举进程模块（扩展版）

**使用场景**:
- 进程枚举
- 模块枚举
- 进程监控

#### 3.9 NtDLL::DynamicModule

**DLL 名称**: ntdll.dll

**功能**: Native API（内核模式）

**导出函数**:
```cpp
NtSuspendProcess NtSuspendProcess;
NtResumeProcess NtResumeProcess;
NtTerminateProcess NtTerminateProcess;
NtQueryInformationProcess NtQueryInformationProcess;
RtlGetVersion RtlGetVersion;
```

**函数分类**:

**进程控制**:
- `NtSuspendProcess`: 挂起进程
- `NtResumeProcess`: 恢复进程
- `NtTerminateProcess`: 终止进程

**进程信息**:
- `NtQueryInformationProcess`: 查询进程信息

**系统信息**:
- `RtlGetVersion`: 获取操作系统版本

**使用场景**:
- 进程控制
- 系统版本检测
- 高级进程操作

#### 3.10 UserEnv::DynamicModule

**DLL 名称**: Userenv.dll

**功能**: 用户环境 API

**导出函数**:
```cpp
CreateEnvironmentBlock CreateEnvironmentBlock;
DestroyEnvironmentBlock DestroyEnvironmentBlock;
```

**函数分类**:

**环境块**:
- `CreateEnvironmentBlock`: 创建环境块
- `DestroyEnvironmentBlock`: 销毁环境块

**使用场景**:
- 用户环境管理
- 进程启动环境

#### 3.11 Kernel32::DynamicModule

**DLL 名称**: Kernel32.dll

**功能**: 内核 API

**导出函数**:
```cpp
ProcessIdToSessionId ProcessIdToSessionId;
WTSGetActiveConsoleSessionId WTSGetActiveConsoleSessionId;
QueryFullProcessImageNameA QueryFullProcessImageNameA;
```

**函数分类**:

**会话管理**:
- `ProcessIdToSessionId`: 获取进程会话 ID
- `WTSGetActiveConsoleSessionId`: 获取活动控制台会话 ID

**进程信息**:
- `QueryFullProcessImageNameA`: 查询完整进程映像名

**使用场景**:
- 会话管理
- 进程信息查询

#### 3.12 User32::DynamicModule

**DLL 名称**: User32.dll

**功能**: 用户界面 API

**导出函数**:
```cpp
SendMessageTimeoutA SendMessageTimeoutA;
```

**函数说明**:
- `SendMessageTimeoutA`: 发送消息（带超时）

**使用场景**:
- 窗口消息
- 跨进程通信

#### 3.13 WtsAPI32::DynamicModule

**DLL 名称**: Wtsapi32.dll

**功能**: 终端服务 API

**导出函数**:
```cpp
WTSQueryUserToken WTSQueryUserToken;
```

**函数说明**:
- `WTSQueryUserToken`: 查询用户令牌

**使用场景**:
- 终端服务
- 远程桌面
- 用户会话

#### 3.14 MsImg32::DynamicModule

**DLL 名称**: Msimg32.dll

**功能**: 图像处理 API

**导出函数**:
```cpp
GradientFill GradientFill;
```

**函数说明**:
- `GradientFill`: 渐变填充

**使用场景**:
- 图形渲染
- 界面美化

#### 3.15 OpenSSL::DynamicModule

**DLL 名称**: libeay32.dll / libssl32.dll

**功能**: OpenSSL 加密库

**导出函数**: 无

**说明**: 仅用于检查 OpenSSL 是否可用

**使用场景**: OpenSSL 加密支持

### 4. Modules 类

**功能**: 集中管理所有 DLL 模块

**成员变量**:
```cpp
Crypt32::DynamicModule Crypt32{};
AdvAPI32::DynamicModule AdvAPI32{};
bcrypt::DynamicModule bcrypt{};
Ws2_32::DynamicModule Ws2_32{};
WinINet::DynamicModule WinINet{};
IPv4::DynamicModule IPv4{};
IPv6::DynamicModule IPv6{};
PsAPI::DynamicModule PsAPI{};
NtDLL::DynamicModule NtDLL{};
UserEnv::DynamicModule UserEnv{};
Kernel32::DynamicModule Kernel32{};
User32::DynamicModule User32{};
WtsAPI32::DynamicModule WtsAPI32{};
MsImg32::DynamicModule MsImg32{};
OpenSSL::DynamicModule OpenSSL{};
```

### 5. GetInstance() 单例

**功能**: 获取所有已加载模块的单例实例

**签名**:
```cpp
static const Modules *GetInstance()
```

**返回值**: 指向 Modules 实例的指针

**加载流程**:
1. 首次调用时，创建静态 Modules 对象
2. 加载所有 DLL 模块
3. 返回实例指针
4. 后续调用返回同一个实例

**使用示例**:
```cpp
// 获取 API 模块实例
const auto *api = cpl::sys::api::GetInstance();

// 使用加密 API
auto ctx = api->AdvAPI32.CryptAcquireContextA(...);

// 使用 Socket API
auto sock = api->Ws2_32.socket(...);

// 使用进程 API
api->PsAPI.EnumProcesses(...);
```

## 依赖关系
- `sys.hpp`: 系统基类和定义

## 使用场景

### 1. 初始化 API 模块
```cpp
// 获取单例（自动加载所有 DLL）
const auto *api = cpl::sys::api::GetInstance();
```

### 2. 使用加密 API
```cpp
// 生成随机数
HCRYPTPROV hProv;
BYTE buffer[32];
api->AdvAPI32.CryptGenRandom(
    hProv, 
    32, 
    buffer
);
```

### 3. 使用网络 API
```cpp
// 初始化 Winsock
WSADATA wsaData;
api->Ws2_32.WSAStartup(MAKEWORD(2, 2), &wsaData);

// 创建 socket
SOCKET sock = api->Ws2_32.socket(
    AF_INET, 
    SOCK_DGRAM, 
    IPPROTO_UDP
);

// 绑定 socket
sockaddr_in addr{};
addr.sin_family = AF_INET;
addr.sin_port = api->Ws2_32.htons(8080);
addr.sin_addr.s_addr = api->Ws2_32.inet_addr("0.0.0.0");
api->Ws2_32.bind(sock, (sockaddr*)&addr, sizeof(addr));

// 发送数据
api->Ws2_32.sendto(sock, buffer, len, 0, ...);
```

### 4. 使用进程 API
```cpp
// 枚举进程
DWORD processes[1024];
DWORD bytesReturned;
api->PsAPI.EnumProcesses(
    processes, 
    sizeof(processes), 
    &bytesReturned
);

// 获取进程映像名
CHAR imagePath[MAX_PATH];
api->PsAPI.GetModuleFileNameExA(
    hProcess, 
    NULL, 
    imagePath, 
    MAX_PATH
);
```

### 5. 使用 HTTP API
```cpp
// 初始化 WinINet
HINTERNET hInternet = api->WinINet.InternetOpenA(
    "MyApp", 
    INTERNET_OPEN_TYPE_DIRECT, 
    NULL, NULL, 0
);

// 建立连接
HINTERNET hConnect = api->WinINet.InternetConnectA(
    hInternet, 
    "example.com", 
    INTERNET_DEFAULT_HTTP_PORT, 
    NULL, NULL, 
    INTERNET_SERVICE_HTTP, 
    0, 0
);

// 创建请求
HINTERNET hRequest = api->WinINet.HttpOpenRequestA(
    hConnect, 
    "GET", 
    "/path", 
    NULL, NULL, NULL, 
    0, 0
);

// 发送请求
api->WinINet.HttpSendRequestA(
    hRequest, 
    NULL, 0, 
    NULL, 0
);

// 读取响应
BYTE buffer[4096];
DWORD bytesRead;
api->WinINet.InternetReadFile(
    hRequest, 
    buffer, 
    sizeof(buffer), 
    &bytesRead
);
```

## 关键设计决策

1. **动态加载**:
   - 避免静态链接依赖
   - 支持多 DLL 版本
   - 失败时尝试备用 DLL

2. **统一接口**:
   - 所有模块继承自 `DynamicModule`
   - 统一的 Load/Unload 接口
   - 便于扩展

3. **单例模式**:
   - `GetInstance()` 返回单例
   - 所有模块自动加载
   - 避免重复加载

4. **自动生成**:
   - 由 `api_gen.py` 生成
   - 避免手动维护
   - 易于更新

## 注意事项

1. **不要直接编辑**:
   - 此文件由 `api_gen.py` 自动生成
   - 修改应通过 Python 脚本
   - 修改会被覆盖

2. **DLL 加载顺序**:
   - 按顺序尝试 DLL_NAMES
   - 第一个成功的 DLL 被使用
   - 所有 DLL 失败则抛出异常

3. **函数指针**:
   - 所有函数通过指针调用
   - 调用前检查是否为 null
   - 确保 DLL 已加载

4. **内存管理**:
   - 使用 `GetInstance()` 获取单例
   - 不要手动删除实例
   - 由系统自动管理

5. **线程安全**:
   - `GetInstance()` 是线程安全的
   - 函数指针调用需自行同步
   - 避免多线程同时调用

## 错误处理

1. **DLL 加载失败**:
   - 抛出 `std::exception`
   - 尝试下一个 DLL
   - 所有 DLL 失败则终止

2. **函数加载失败**:
   - 抛出 `std::exception`
   - 可选参数控制是否必需
   - `LoadFunction(..., false)` 可选

3. **运行时错误**:
   - 检查函数指针是否为 null
   - 使用 `GetLastError()` 获取错误
   - 处理返回值

## 性能考虑

1. **首次加载开销**:
   - 首次调用 `GetInstance()` 加载所有 DLL
   - 后续调用无开销
   - 建议程序启动时调用

2. **函数调用开销**:
   - 通过函数指针调用
   - 相比直接调用有轻微开销
   - 使用内联无法优化

3. **内存占用**:
   - 所有 DLL 常驻内存
   - 即使不使用也占用
   - 考虑按需加载

## 扩展性

1. **添加新 DLL**:
   - 在 `api_gen.py` 中添加配置
   - 重新生成此文件
   - 更新文档

2. **添加新函数**:
   - 在对应模块中添加函数指针
   - 在 `Load()` 中加载函数
   - 在 `Unload()` 中清理函数

3. **自定义 DLL**:
   - 创建新的命名空间
   - 继承 `DynamicModule`
   - 实现 `Load()` 和 `Unload()`