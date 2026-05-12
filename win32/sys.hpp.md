# cpl/win32/sys.hpp - Windows API 动态加载框架

## 文件概述
此文件定义了 Windows API 动态加载框架，支持运行时加载 DLL 和函数指针，提高兼容性和灵活性。

## 设计原则
- 动态加载 DLL，避免静态依赖
- 缓存已加载的模块和函数
- 支持可选加载（失败不抛出异常）
- 统一的错误处理

## 主要功能

### 1. 辅助函数

#### LOG_D()

**功能**: 调试日志输出

**参数**:
- `tpl`: 格式化字符串
- `...`: 可变参数

**行为**: 仅在 DEBUG 模式下编译
- 使用 `OutputDebugStringA()` 输出
- 格式化失败时抛出异常

**使用示例**:
```cpp
LOG_D("Loading module: %s", dllName.data());
```

#### FormatError()

**功能**: 格式化错误代码为描述字符串

**函数签名**:
```cpp
inline std::string FormatError(const DWORD errorCode)
```

**参数**:
- `errorCode`: Windows 错误代码

**返回值**: 错误描述字符串

**实现**:
```cpp
1. 调用 FormatMessageA()
2. 移除末尾的 \r\n
3. 返回错误描述
```

**使用示例**:
```cpp
DWORD e = GetLastError();
std::string err = FormatError(e);
// err = "系统找不到指定的文件。"
```

### 2. 动态模块管理

#### DynamicModule 类

**功能**: 动态加载和管理 DLL 模块

**继承**: `cpl::base::IContext`

**成员变量**:
```cpp
std::string szDllName{};              // DLL 名称
bool bModuleNecessary{true};          // 是否必须加载
HMODULE hModule = nullptr;             // 模块句柄
```

**方法**:

**构造函数**:
```cpp
explicit DynamicModule(const bool bModuleNecessary = true)
```

**参数**:
- `bModuleNecessary`: 模块是否必须加载（默认 true）

**IsLoaded()**:
```cpp
bool IsLoaded() override
```

**返回值**: 模块是否已加载

**Load()**:
```cpp
int32_t Load() override
```

**功能**: 加载 DLL 模块

**实现逻辑**:
```cpp
1. 检查模块是否已加载
2. 检查全局缓存
3. 调用 LoadLibraryA() 加载
4. 缓存模块句柄
5. 失败时抛出异常（如果 bModuleNecessary=true）
```

**返回值**:
- 0: 成功
- 异常: 失败

**Unload()**:
```cpp
int32_t Unload() override
```

**功能**: 卸载 DLL 模块

**实现逻辑**:
```cpp
1. 调用 FreeLibrary()
2. 清理模块句柄
3. 失败时抛出异常
```

**返回值**:
- 0: 成功
- 异常: 失败

**LoadFunction()**:
```cpp
template<typename FuncPtrType>
INT32 LoadFunction(
    _Out_ FuncPtrType &out,
    _In_ const char *functionName,
    _In_ const bool bFunctionNecessary = true
)
```

**参数**:
- `out`: 输出函数指针
- `functionName`: 函数名称
- `bFunctionNecessary`: 函数是否必须加载（默认 true）

**实现逻辑**:
```cpp
1. 构造缓存键: "DLL_NAME.FUNCTION_NAME" (大写）
2. 检查全局缓存
3. 调用 GetProcAddress() 加载函数
4. 缓存函数指针
5. 失败时抛出异常（如果 bFunctionNecessary=true）
```

**返回值**:
- 0: 成功
- 1: 已缓存
- 异常: 失败

**使用示例**:
```cpp
DynamicModule module("kernel32.dll");
module.Load();

typedef BOOL (WINAPI*QueryPerformanceCounter)(LARGE_INTEGER*);
QueryPerformanceCounter func;
module.LoadFunction(func, "QueryPerformanceCounter");

LARGE_INTEGER counter;
func(&counter);
```

### 3. 全局缓存

#### 模块缓存
```cpp
static std::unordered_map<std::string, HMODULE> Win32APIModMap{};
```

**用途**: 缓存已加载的 DLL 模块

**键**: DLL 名称（大写）
**值**: 模块句柄

#### 函数缓存
```cpp
static std::unordered_map<std::string, void *> Win32APIFuncMap{};
```

**用途**: 缓存已加载的函数指针

**键**: "DLL_NAME.FUNCTION_NAME" (大写)
**值**: 函数指针

### 4. Windows API 命名空间

#### 4.1 Crypt32

**DLL 名称**: `Crypt32.dll`

**函数类型**:
```cpp
typedef BOOL (WINAPI*CryptBinaryToStringA)(
    _In_ const BYTE *pbBinary,
    _In_ DWORD cbBinary,
    _In_ DWORD dwFlags,
    _Out_opt_ LPSTR pszString,
    _Inout_ DWORD *pcchString
);
```

**用途**: 加密二进制转换

#### 4.2 AdvAPI32

**DLL 名称**: `AdvAPI32.dll`

**函数类型**:
```cpp
// 随机数生成
typedef BOOLEAN (WINAPI*RtlGenRandom)(
    _Out_ PVOID RandomBuffer,
    _In_ ULONG RandomBufferLength
);

// 加密上下文
typedef BOOL (WINAPI*CryptAcquireContextA)(
    HCRYPTPROV *phProv,
    LPCSTR szContainer,
    LPCSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags
);

typedef BOOL (WINAPI*CryptReleaseContext)(
    HCRYPTPROV hProv,
    DWORD dwFlags
);

// 随机数生成
typedef BOOL (WINAPI*CryptGenRandom)(
    HCRYPTPROV hProv,
    DWORD dwLen,
    BYTE *pbBuffer
);

// 密钥管理
typedef BOOL (WINAPI*CryptImportKey)(
    _In_ HCRYPTPROV hProv,
    _In_ const BYTE *pbData,
    _In_ DWORD dwDataLen,
    _In_ HCRYPTKEY hPubKey,
    _In_ DWORD dwFlags,
    _Out_ HCRYPTKEY *phKey
);

typedef BOOL (WINAPI*CryptDestroyKey)(
    _In_ HCRYPTKEY hKey
);

typedef BOOL (WINAPI*CryptSetKeyParam)(
    _In_ HCRYPTKEY hKey,
    _In_ DWORD dwParam,
    _In_ const BYTE *pbData,
    _In_ DWORD dwFlags
);

// 加密/解密
typedef BOOL (WINAPI*CryptEncrypt)(
    _In_ HCRYPTKEY hKey,
    _In_ HCRYPTHASH hHash,
    _In_ BOOL Final,
    _In_ DWORD dwFlags,
    _Inout_ BYTE *pbData,
    _Inout_ DWORD *pdwDataLen,
    _In_ DWORD dwBufLen
);

typedef BOOL (WINAPI*CryptDecrypt)(
    _In_ HCRYPTKEY hKey,
    _In_ HCRYPTHASH hHash,
    _In_ BOOL Final,
    _In_ DWORD dwFlags,
    _Inout_ BYTE *pbData,
    _Inout_ DWORD *pdwDataLen
);

// 哈希
typedef BOOL (WINAPI*CryptCreateHash)(
    _In_ HCRYPTPROV hProv,
    _In_ ALG_ID Algid,
    _In_ HCRYPTKEY hKey,
    _In_ DWORD dwFlags,
    _Out_ HCRYPTHASH *phHash
);

typedef BOOL (WINAPI*CryptDestroyHash)(
    _In_ HCRYPTHASH hHash
);

typedef BOOL (WINAPI*CryptSetHashParam)(
    _In_ HCRYPTHASH hHash,
    _In_ DWORD dwParam,
    _In_ const BYTE *pbData,
    _In_ DWORD dwFlags
);

typedef BOOL (WINAPI*CryptGetHashParam)(
    _In_ HCRYPTHASH hHash,
    _In_ DWORD dwParam,
    _Out_ BYTE *pbData,
    _Inout_ DWORD *pdwDataLen,
    _In_ DWORD dwFlags
);

typedef BOOL (WINAPI*CryptHashData)(
    _In_ HCRYPTHASH hHash,
    _In_ const BYTE *pbData,
    _In_ DWORD dwDataLen,
    _In_ DWORD dwFlags
);
```

**用途**: 加密服务提供者 API

#### 4.3 bcrypt

**DLL 名称**: `bcrypt.dll`

**函数类型**:
```cpp
typedef NTSTATUS (WINAPI*BCryptGenRandom)(
    _Inout_ BCRYPT_ALG_HANDLE hAlgorithm,
    _Inout_ PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _In_ ULONG dwFlags
);
```

**用途**: CNG (Cryptography API: Next Generation)

#### 4.4 Ws2_32

**DLL 名称**: `Ws2_32.dll`

**函数类型**:
```cpp
typedef int (WINAPI*WSAStartup)(
    _In_ WORD wVersionRequested,
    _Out_ LPWSADATA lpWSAData
);

typedef int (WINAPI*WSACleanup)();

typedef int (WINAPI*WSAGetLastError)();

typedef SOCKET (WINAPI*socket)(
    _In_ int af,
    _In_ int type,
    _In_ int protocol
);

typedef u_short (WINAPI*htons)(
    _In_ u_short host_short
);

typedef unsigned long (WINAPI*inet_addr)(
    const char *cp
);

typedef int (WINAPI*sendto)(
    _In_ SOCKET s,
    _In_ const char *buf,
    _In_ int len,
    _In_ int flags,
    _In_ const sockaddr *to,
    _In_ int to_len
);

typedef int (WINAPI*closesocket)(_In_ SOCKET s);

typedef int (WINAPI*setsockopt)(
    _In_ SOCKET s,
    _In_ int level,
    _In_ int opt_name,
    _In_ const char *opt_val,
    _In_ int opt_len
);

typedef int (WINAPI*bind)(
    _In_ SOCKET s,
    _In_ const sockaddr *name,
    _In_ int namelen
);

typedef int (WINAPI*recvfrom)(
    _In_ SOCKET s,
    _Out_ char *buf,
    _In_ int len,
    _In_ int flags,
    _Out_ sockaddr *from,
    _Inout_opt_ int *from_len
);

typedef u_short (WINAPI*ntohs)(
    _In_ u_short net_short
);

typedef int (WINAPI *ioctlsocket)(
    _In_ SOCKET s,
    _In_ long cmd,
    _Inout_ u_long *argp
);
```

**用途**: Windows Sockets API

#### 4.5 WinINet

**DLL 名称**: `WinINet.dll`

**函数类型**:
```cpp
typedef HINTERNET (WINAPI*InternetOpenA)(
    LPCSTR lpszAgent,
    DWORD dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD dwFlags
);

typedef HINTERNET (WINAPI*InternetConnectA)(
    HINTERNET hInternet,
    LPCSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR lpszUserName,
    LPCSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

typedef HINTERNET (WINAPI*HttpOpenRequestA)(
    HINTERNET hConnect,
    LPCSTR lpszVerb,
    LPCSTR lpszObjectName,
    LPCSTR lpszVersion,
    LPCSTR lpszReferrer,
    LPCSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

typedef BOOL (WINAPI*HttpSendRequestA)(
    HINTERNET hRequest,
    LPCSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
);

typedef BOOL (WINAPI*InternetReadFile)(
    _In_ HINTERNET hFile,
    _Out_ LPVOID lpBuffer,
    _In_ DWORD dwNumberOfBytesToRead,
    _Out_ LPDWORD lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI*InternetCloseHandle)(
    HINTERNET hInternet
);

typedef BOOL (WINAPI*InternetCrackUrlA)(
    __in_ecount(dwUrlLength) LPCSTR lpszUrl,
    __in DWORD dwUrlLength,
    __in DWORD dwFlags,
    __inout LPURL_COMPONENTSA lpUrlComponents
);
```

**用途**: HTTP/FTP 协议

#### 4.6 IPv4 (IpHlpAPI)

**DLL 名称**: `IpHlpAPI.dll`

**函数类型**:
```cpp
typedef ULONG (WINAPI*GetAdaptersInfo)(
    PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);

typedef ULONG (WINAPI*GetAdaptersAddresses)(
    _In_ ULONG Family,
    _In_ ULONG Flags,
    _In_ PVOID Reserved,
    _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses,
    _Inout_ PULONG SizePointer
);

typedef DWORD (WINAPI*GetIpForwardTable)(
    PMIB_IPFORWARDTABLE pIpForwardTable,
    PULONG pdwSize,
    BOOL bOrder
);

typedef DWORD (WINAPI*DeleteIpForwardEntry)(
    PMIB_IPFORWARDROW pRoute
);

typedef DWORD (WINAPI*CreateIpForwardEntry)(
    PMIB_IPFORWARDROW pRoute
);
```

**用途**: IP 帮助 API (IPv4)

#### 4.7 IPv6 (IpHlpAPI)

**DLL 名称**: `IpHlpAPI.dll`

**自定义结构**:
```cpp
typedef struct sockaddr_in6 {
    ADDRESS_FAMILY sin6_family;
    USHORT sin6_port;
    ULONG sin6_flowinfo;
    IN6_ADDR sin6_addr;
    union {
        ULONG sin6_scope_id;
        SCOPE_ID sin6_scope_struct;
    };
} SOCKADDR_IN6;

typedef union ST_SOCKADDR_INET {
    SOCKADDR_IN Ipv4;
    SOCKADDR_IN6 Ipv6;
    ADDRESS_FAMILY si_family;
} SOCKADDR_INET;

typedef struct ST_IP_ADDRESS_PREFIX {
    SOCKADDR_INET Prefix;
    UINT8 PrefixLength;
} IP_ADDRESS_PREFIX;

typedef struct ST_MIB_IPFORWARD_ROW2 {
    NET_LUID InterfaceLuid;
    NET_IFINDEX InterfaceIndex;
    IP_ADDRESS_PREFIX DestinationPrefix;
    SOCKADDR_INET NextHop;
    UCHAR SitePrefixLength;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG Metric;
    NL_ROUTE_PROTOCOL Protocol;
    BOOLEAN Loopback;
    BOOLEAN AutoconfigureAddress;
    BOOLEAN Publish;
    BOOLEAN Immortal;
    ULONG Age;
    NL_ROUTE_ORIGIN Origin;
} MIB_IPFORWARD_ROW2;

typedef struct ST_MIB_IPFORWARD_TABLE2 {
    ULONG NumEntries;
    MIB_IPFORWARD_ROW2 Table[ANY_SIZE];
} MIB_IPFORWARD_TABLE2;
```

**用途**: IP 帮助 API (IPv6)

#### 4.8 PsAPI

**DLL 名称**: `Kernel32.dll`, `PsAPI.dll`

**函数类型**:
```cpp
typedef DWORD (WINAPI*GetModuleFileNameExA)(
    _In_ HANDLE hProcess,
    _In_opt_ HMODULE hModule,
    _Out_ LPSTR lpFilename,
    _In_ DWORD nSize
);

typedef BOOL (WINAPI*EnumProcesses)(
    _Out_ DWORD *lpidProcess,
    _In_ DWORD cb,
    _Out_ LPDWORD lpcbNeeded
);

typedef BOOL (WINAPI*EnumProcessModules)(
    _In_ HANDLE hProcess,
    _Out_ HMODULE *lphModule,
    _In_ DWORD cb,
    _Out_ LPDWORD lpcbNeeded
);

typedef BOOL (WINAPI*EnumProcessModulesEx)(
    _In_ HANDLE hProcess,
    _Out_ HMODULE *lphModule,
    _In_ DWORD cb,
    _Out_ LPDWORD lpcbNeeded,
    _In_ DWORD dwFilterFlag
);
```

**用途**: 进程状态 API

**注意**: 
- XP: PsAPI.dll
- Vista+: Kernel32.dll

#### 4.9 NtDLL

**DLL 名称**: `NtDLL.dll`

**函数类型**:
```cpp
typedef BOOL (WINAPI*NtSuspendProcess)(HANDLE hProcess);

typedef BOOL (WINAPI*NtResumeProcess)(HANDLE hProcess);

typedef BOOL (WINAPI*NtTerminateProcess)(HANDLE hProcess, UINT);

typedef __kernel_entry NTSTATUS (WINAPI*NtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS (WINAPI*RtlGetVersion)(
    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
);
```

**用途**: Native API

#### 4.10 UserEnv

**DLL 名称**: `UserEnv.dll`

**函数类型**:
```cpp
typedef BOOL (WINAPI*CreateEnvironmentBlock)(
    _Out_ LPVOID *lpEnvironment,
    _In_opt_ HANDLE hToken,
    _In_ BOOL bInherit
);

typedef BOOL (WINAPI*DestroyEnvironmentBlock)(
    _In_ LPVOID lpEnvironment
);
```

**用途**: 用户环境管理

#### 4.11 Kernel32

**DLL 名称**: `Kernel32.dll`

**函数类型**:
```cpp
typedef BOOL (WINAPI*ProcessIdToSessionId)(
    _In_ DWORD dwProcessId,
    _Out_ DWORD *pSessionId
);

typedef DWORD (WINAPI*WTSGetActiveConsoleSessionId)();

typedef BOOL (WINAPI*QueryFullProcessImageNameA)(
    _In_ HANDLE hProcess,
    _In_ DWORD dwFlags,
    _Out_ LPSTR lpExeName,
    _Inout_ PDWORD lpdwSize
);
```

**用途**: 内核 API

#### 4.12 User32

**DLL 名称**: `User32.dll`

**函数类型**:
```cpp
typedef LRESULT (WINAPI*SendMessageTimeoutA)(
    _In_ HWND hWnd,
    _In_ UINT Msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam,
    _In_ UINT fuFlags,
    _In_ UINT uTimeout,
    _Out_opt_ PDWORD_PTR lpdwResult
);
```

**用途**: 用户界面 API

#### 4.13 WtsAPI32

**DLL 名称**: `WtsAPI32.dll`

**函数类型**:
```cpp
typedef BOOL (WINAPI *WTSQueryUserToken)(
    _In_ ULONG SessionId,
    _Out_ PHANDLE phToken
);
```

**用途**: 终端服务 API

#### 4.14 MsImg32

**DLL 名称**: `MsImg32.dll`

**函数类型**:
```cpp
typedef BOOL (WINAPI *GradientFill)(
    _In_ HDC hdc,
    _In_ PTRIVERTEX pVertex,
    _In_ ULONG nVertex,
    _In_ PVOID pMesh,
    _In_ ULONG nMesh,
    _In_ ULONG ulMode
);
```

**用途**: 图形 API

#### 4.15 OpenSSL

**DLL 名称**: `libcrypto.dll`, `libeay32.dll`

**用途**: OpenSSL 加密库

## 依赖关系
- `base.hpp`: 基础定义
- `strings.hpp`: 字符串处理

## 使用示例

### 1. 加载模块

```cpp
// 创建模块
cpl::sys::api::DynamicModule kernel32("kernel32.dll");

// 加载模块
kernel32.Load();

// 使用模块
typedef BOOL (WINAPI*QueryPerformanceCounter)(LARGE_INTEGER*);
QueryPerformanceCounter func;
kernel32.LoadFunction(func, "QueryPerformanceCounter");

LARGE_INTEGER counter;
func(&counter);

// 卸载模块
kernel32.Unload();
```

### 2. 可选模块

```cpp
// 创建可选模块（加载失败不抛出异常）
cpl::sys::api::DynamicModule module("optional.dll", false);

try {
    module.Load();
    
    // 使用模块
    typedef void (*OptionalFunc)();
    OptionalFunc func;
    module.LoadFunction(func, "OptionalFunction", false);
    
    if (func) {
        func();
    }
} catch (...) {
    // 模块加载失败，继续执行
    LOG_D("Optional module not available");
}
```

### 3. 格式化错误

```cpp
DWORD e = GetLastError();
std::string err = cpl::sys::FormatError(e);
LOG_D("Error: %s", err.data());
```

## 关键设计决策

### 1. 动态加载

**优点**:
- 减少静态依赖
- 提高兼容性
- 按需加载

**缺点**:
- 运行时开销
- 错误处理复杂

### 2. 全局缓存

**优点**:
- 避免重复加载
- 共享模块
- 提高性能

**缺点**:
- 内存占用
- 卸载困难

### 3. 可选加载

**优点**:
- 优雅降级
- 兼容性高
- 灵活性强

**缺点**:
- 功能受限
- 代码复杂

## 注意事项

1. **DLL 位置**:
   - 确保 DLL 在系统路径或程序目录
   - 使用绝对路径或相对路径

2. **函数指针**:
   - 必须匹配函数签名
   - 使用正确的调用约定

3. **错误处理**:
   - 检查所有返回值
   - 处理加载失败
   - 提供备选方案

4. **内存管理**:
   - 及时卸载不用的模块
   - 避免内存泄漏
   - 注意模块卸载时机

5. **线程安全**:
   - 全局缓存不是线程安全
   - 需要外部同步
   - 使用临界区保护

6. **版本兼容**:
   - 某些 API 在不同版本有差异
   - 检查系统版本
   - 提供多个 DLL 选项

## 性能优化

1. **延迟加载**:
   ```cpp
   // 按需加载
   if (!module.IsLoaded()) {
       module.Load();
   }
   ```

2. **静态实例**:
   ```cpp
   // 使用单例
   static cpl::sys::api::DynamicModule module("kernel32.dll");
   module.Load();
   ```

3. **缓存函数**:
   ```cpp
   // 缓存函数指针
   static QueryPerformanceCounter func = nullptr;
   if (!func) {
       module.LoadFunction(func, "QueryPerformanceCounter");
   }
   ```

## 调试技巧

1. **启用调试日志**:
   ```cpp
   LOG_D("Loading module: %s", dllName.data());
   ```

2. **检查错误**:
   ```cpp
   try {
       module.Load();
   } catch (const std::exception &e) {
       std::string err = FormatError(GetLastError());
       LOG_D("Error: %s", err.data());
   }
   ```

3. **验证加载**:
   ```cpp
   if (module.IsLoaded()) {
       // 模块已加载
   }
   ```

## 最佳实践

1. **错误处理**:
   - 检查所有返回值
   - 提供有意义的错误信息
   - 优雅降级

2. **资源管理**:
   - 使用 RAII
   - 及时释放资源
   - 避免重复加载

3. **兼容性**:
   - 检查系统版本
   - 提供多个 DLL 选项
   - 处理 API 差异

4. **性能**:
   - 延迟加载
   - 缓存函数指针
   - 使用静态实例