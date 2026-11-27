# cpl/plugin_loader.hpp - 插件加载器

## 文件概述
此文件定义了 ifw 插件的共享库加载器。一个插件就是一个共享库（Linux 上的 `.so`，Windows 上的 DLL），
导出两个 C 符号 `IfwPluginQuery` 与 `IfwPluginRun`，声明见 `plugins.hpp`。
在 32 位 x86 的 Windows 上，MSVC 把 `__stdcall` 函数导出成带修饰的名字（`_IfwPluginQuery@4`），
除非插件的工程带有模块定义文件。加载器同时接受两种名字，所以插件工程不需要这个文件（见"入口符号的名字"）。

本文件提供两类能力：
- `Loader`：独占一个已打开的共享库，用 RAII 管理句柄（POSIX 上是 `dlopen` 句柄，Windows 上是模块句柄）；
- `LoadPlugin`：打开插件、解析两个入口符号、调用 `IfwPluginQuery` 并核对插件是否按 `IFW_PLUGIN_API_VERSION` 构建。

平台无关：POSIX 上使用 `dlopen` / `dlsym` / `dlclose`，Windows 上使用 `LoadLibraryA` / `GetProcAddress` / `FreeLibrary`。

## 主要功能

### 1. 命名空间结构
```
cpl::plugin
├── impl (内部实现，调用方不直接使用)
│   ├── Win32ErrorText() (Win32 错误码的系统文本，仅 Windows)
│   └── QueryPlugin() (调用 IfwPluginQuery 并校验应答)
├── Loader (独占一个已打开的共享库，不可拷贝，可移动)
│   ├── Open() (打开共享库)
│   ├── Symbol<Fn>() (解析符号)
│   ├── Close() (关闭共享库)
│   ├── IsOpen() (是否有已打开的库)
│   └── Path() (传给 Open() 的路径)
├── EntrySymbolNames() (一个入口符号可能有的导出名字)
├── EntrySymbol<Fn>() (按这些名字解析入口符号)
├── PluginEntry (一个已加载的插件：query / run / info)
└── LoadPlugin() (加载插件的完整流程)
```

### 2. Loader 类

**功能**: 独占一个已打开的共享库。不可拷贝，可移动；析构时如果库仍然打开，就关闭它。

**成员变量**:
```cpp
void *handle_{nullptr};   // 原始句柄，各平台的类布局一致
std::string path_{};      // 传给 Open() 的路径，未打开时为空
```

**构造与特殊成员**:
```cpp
Loader() = default;                            // 未打开
~Loader();                                     // 库仍打开时关闭它
Loader(const Loader &) = delete;               // 不可拷贝
Loader &operator=(const Loader &) = delete;
Loader(Loader &&other) noexcept;               // 移动构造
Loader &operator=(Loader &&other) noexcept;    // 移动赋值
```

移动之后目标对象持有句柄，源对象处于未打开状态（`IsOpen()` 为 false，`Path()` 为空），
源对象析构时不会关闭被移走的库，并且可以重新 `Open()`。
移动赋值到已有库打开的对象上时，先关闭它自己原来打开的库。自移动赋值不做任何事。

#### 2.1 Open - 打开共享库

**功能**: 打开共享库：POSIX 上是 `dlopen(path, RTLD_NOW | RTLD_LOCAL)`，Windows 上是 `LoadLibraryA(path)`。

**函数签名**:
```cpp
inline Int32Result Open(const std::string &path)
```

**参数**:
- `path`: 共享库的路径（建议传绝对路径，见注意事项）

**返回值**:
- 0: 成功，库已打开
- `cpl::Error::InvalidArgument`: 已有库处于打开状态（先调用 `Close()`），或路径为空
- `cpl::Error::FileOpen`: 打开失败，原因文本带有 `dlerror()` 或 `GetLastError()` 的系统文本

**实现逻辑**:
1. 已有库打开则失败，已打开的库不受影响
2. 路径为空则失败
3. 先保存路径：整个函数里唯一可能抛出异常的一步是字符串分配（`std::bad_alloc`），
   此时还没有拿到句柄，异常不会泄漏共享库
4. `dlopen` / `LoadLibraryA`
5. 失败：取 `dlerror()` / `GetLastError()` 的文本写进错误原因，清空路径，loader 回到未打开状态
6. 成功：保存句柄

**使用示例**:
```cpp
cpl::plugin::Loader loader{};
const auto r0 = loader.Open("/opt/ifw/plugins/demo/plugin.so");
if (!r0) {
    // r0.error().Code.i64 == cpl::Error::FileOpen
    // r0.error().Reason 含有 dlopen 的系统文本
}
```

#### 2.2 Symbol - 解析符号

**功能**: 在已打开的库中解析一个符号。库未打开或符号不存在时失败。

**函数签名**:
```cpp
template<typename Fn>
Result<Fn> Symbol(const char *name)
```

**参数**:
- `Fn`: 函数指针类型，例如 `ifw_plugin_query_fn` 或 `size_t (*)(const char *)`
- `name`: C 符号名（`dlsym` / `GetProcAddress` 看到的名字，不含 C++ 修饰）

**返回值**:
- 成功: `Fn` 类型的函数指针
- `cpl::Error::InvalidArgument`: 库未打开，或符号名为空
- `cpl::Error::UnavailableAPI`: 符号不存在，原因文本含有符号名与 `dlerror()` / `GetLastError()` 的系统文本

**实现逻辑**:
1. 检查库是否已打开、符号名是否为空
2. POSIX: 先调用一次 `dlerror()` 清掉遗留的错误，再 `dlsym`，再用 `dlerror()` 判断本次查找的结果
3. Windows: `GetProcAddress`，失败时用 `GetLastError()` 取错误码与系统文本
4. 查找失败不影响已打开的库，之后仍然可以继续解析其它符号

**使用示例**:
```cpp
const auto strlenFn = loader.Symbol<size_t (*)(const char *)>("strlen");
if (strlenFn) {
    const size_t n = strlenFn.value()("plugin_loader");   // 13
}
```

#### 2.3 Close - 关闭共享库

**功能**: 库打开时关闭它。连续调用两次是安全的。

**函数签名**:
```cpp
inline void Close()
```

**实现逻辑**:
1. 先取出句柄并清空成员（句柄置空、路径清空）
2. 句柄为空则直接返回，所以第二次调用不做任何事
3. 否则 `dlclose` / `FreeLibrary`

#### 2.4 IsOpen / Path - 状态查询

```cpp
inline bool IsOpen() const;             // 是否有已打开的库
inline const std::string &Path() const; // 传给 Open() 的路径，未打开时为空
```

### 3. PluginEntry 结构

**功能**: 一个已加载的插件：两个入口函数与 `IfwPluginQuery` 的应答。

```cpp
struct PluginEntry {
    ifw_plugin_query_fn query = nullptr;
    ifw_plugin_run_fn run = nullptr;
    IfwPluginInfo info{};
};
```

**说明**:
- `info.name` 与 `info.version` 指向插件内部的字符串，只在加载它的 `Loader` 保持打开期间有效；
- `query` 与 `run` 同样只在 `Loader` 保持打开期间可以调用。

### 4. LoadPlugin - 加载插件

**功能**: 打开插件、解析两个入口符号、调用 `IfwPluginQuery`，并核对插件是否按 `IFW_PLUGIN_API_VERSION` 构建。
任何失败都会把 loader 重新关闭。

**函数签名**:
```cpp
inline Result<PluginEntry> LoadPlugin(Loader &loader, const std::string &path)
```

**参数**:
- `loader`: 调用方持有的加载器。成功时它保持打开（返回的指针指向的代码归它所有）；失败时它被关闭
- `path`: 插件共享库的路径

**返回值**:
- 成功: `PluginEntry`
- 失败:

| 情况 | 错误码 (`error().Code.i64`) | 原因文本要点 |
|---|---|---|
| 共享库打不开 | `cpl::Error::FileOpen` | 路径 + `dlopen` / `LoadLibraryA` 的系统文本 |
| loader 已经打开着 | `cpl::Error::InvalidArgument` | `already has an open library` |
| 缺少入口符号 | `cpl::Error::UnavailableAPI` | 缺失的符号名（`IfwPluginQuery` 或 `IfwPluginRun`） |
| `IfwPluginQuery` 返回非 `IFW_PLUGIN_OK` | 插件返回的 `IfwPluginResult` 值 | `returned [x], expected [0]` |
| API 版本不一致 | `IFW_PLUGIN_ERROR_INCOMPATIBLE_API` | `reported [0x...], expected [0x...]` |

**实现逻辑**:
1. 建立 RAII 守卫：离开作用域时若没有成功，就调用 `loader.Close()`。
   即使中途抛出异常（例如字符串分配失败），共享库也不会泄漏
2. `loader.Open(path)`
3. 用 `EntrySymbol` 解析 `IFW_PLUGIN_QUERY_SYMBOL`（`IfwPluginQuery`）
4. 用 `EntrySymbol` 解析 `IFW_PLUGIN_RUN_SYMBOL`（`IfwPluginRun`）
5. `impl::QueryPlugin`：
   - 把 `IfwPluginInfo` 清零，写入主程序期望的值：`cb = sizeof(IfwPluginInfo)`、
     `plugin_api_version = IFW_PLUGIN_API_VERSION`（与 Windows 客户端加载器的准备方式一致，
     插件靠 `cb` 判断自己可以写入多少）
   - 调用 `query(&info)`
   - 返回值不是 `IFW_PLUGIN_OK` 则失败
   - `info.plugin_api_version` 不等于 `IFW_PLUGIN_API_VERSION` 则失败
6. 成功：填充 `PluginEntry`，loader 保持打开

**使用示例**:
```cpp
cpl::plugin::Loader loader{};
const auto plugin = cpl::plugin::LoadPlugin(loader, "/opt/ifw/plugins/demo/plugin.so");
if (!plugin) {
    // 失败：loader 已被关闭
    // plugin.error().Code   错误码，见上表
    // plugin.error().Reason 错误原因
    return;
}

// loader 仍然打开着，下面的指针才有效
IfwPluginHostApi hostApi{};
hostApi.cb = sizeof(hostApi);
hostApi.api_version = IFW_PLUGIN_API_VERSION;

IfwPluginContext ctx{};
ctx.cb = sizeof(ctx);
ctx.host_api_version = IFW_PLUGIN_API_VERSION;
ctx.plugin_path = "/opt/ifw/plugins/demo/plugin.so";
ctx.config_json = configJson.c_str();
ctx.host_api = &hostApi;

const int rc = plugin.value().run(&ctx);   // IFW_PLUGIN_OK 为成功

loader.Close();   // 之后 plugin.value() 里的指针不再有效
```

### 5. 入口符号的名字

**功能**: 给出一个入口符号可能有的导出名字，并且按这些名字解析它。

**函数签名**:
```cpp
inline std::vector<std::string> EntrySymbolNames(const char *name);

template<typename Fn>
inline Result<Fn> EntrySymbol(Loader &loader, const char *name);
```

**名字的顺序**:
1. ABI 规定的名字，例如 `IfwPluginQuery`
2. 只在 32 位 x86 的 Windows 上：带修饰的名字 `_IfwPluginQuery@4`。
   它的结尾是参数的字节数；两个入口函数都只带一个指针

**返回值**（`EntrySymbol`）:
- 成功: 第一个存在的名字所对应的函数指针
- 失败: `cpl::Error::UnavailableAPI`。原因文本里写的是 ABI 规定的名字，不是带修饰的名字

**使用场景**: `LoadPlugin` 用它解析两个入口符号。带模块定义文件的插件工程导出第一种名字；
没有这个文件的 MSVC 工程在 32 位 x86 上导出第二种名字。Windows 客户端的示例插件属于后一种。

### 6. impl::QueryPlugin - 校验插件的应答（内部）

**功能**: 在已经解析好的 `IfwPluginQuery` 上调用它并校验应答。
单独拆出来是为了能不用真实插件就测试这部分契约。

**函数签名**:
```cpp
inline Result<IfwPluginInfo> QueryPlugin(const ifw_plugin_query_fn query)
```

**参数**:
- `query`: 已解析的 `IfwPluginQuery`，不能为空

**返回值**:
- 成功: 插件填好的 `IfwPluginInfo`
- 失败: 见 4. 节表格的最后两行

### 7. impl::Win32ErrorText - Win32 错误文本（内部，仅 Windows）

**功能**: 用 `FormatMessageA` 取一个 Win32 错误码（`GetLastError()` 的值）的系统文本，
去掉末尾的换行。Windows 描述不了这个错误码时返回空串。

**函数签名**:
```cpp
inline std::string Win32ErrorText(const DWORD code)
```

## 错误原因的格式

所有错误原因都以 `[X]` 开头，以 `CPL_FILE_AND_LINE`（`<文件:行>`）结尾，与 `plugins.hpp` 的写法一致。
系统文本（`dlerror()` / `GetLastError()`）位于两者之间。示例：

```
[X] dlopen [/no/such/plugin.so] failed: Error loading shared library /no/such/plugin.so: No such file or directory<../plugin_loader.hpp:239>
[X] LoadLibraryA [C:\no\such\plugin.dll] failed [0x7e]: The specified module could not be found.<../plugin_loader.hpp:221>
[X] dlsym [IfwPluginQuery] failed: Symbol not found: IfwPluginQuery<../plugin_loader.hpp:154>
[X] GetProcAddress [IfwPluginQuery] failed [0x7f]: The specified procedure could not be found.<../plugin_loader.hpp:136>
[X] IfwPluginQuery failed: returned [3], expected [0]<../plugin_loader.hpp:70>
[X] plugin api version mismatch: reported [0x00010001], expected [0x00010002]<../plugin_loader.hpp:83>
```

（行号是源文件当前的行号，源文件改动后会跟着变化。`dlsym` 一行是 musl 的文本，glibc 给出的是 `undefined symbol: ...`。
路径是 `__FILE__` 的值，取决于包含它的方式。）

## 依赖关系
- `base.hpp`: `Result<T>` / `Int32Result` / `MakeErr` / `base::MakeDefer`
- `plugins.hpp`: 插件的 C ABI（`ifw_plugin_query_fn`、`ifw_plugin_run_fn`、`IfwPluginInfo`、`IFW_PLUGIN_*`）
- `strings.hpp`: `strings::Format`（拼接错误原因）
- 平台头文件: `<dlfcn.h>`（POSIX，位于 `#if defined(_WIN32)` 的 `#else` 分支）/
  `<windows.h>`（Windows，位于 `#if defined(_WIN32)` 之内）
- 链接: musl 与 glibc 2.34 及以后的版本不需要额外的库；更早的 glibc 需要链接 `-ldl`

## 使用场景

### 1. 加载一个插件并运行
```cpp
cpl::plugin::Loader loader{};
const auto plugin = cpl::plugin::LoadPlugin(loader, pluginPath);
if (plugin) {
    const int rc = plugin.value().run(&ctx);
}
// loader 离开作用域时自动关闭，不需要显式的 Close()
```

### 2. 解析系统库里的符号
```cpp
cpl::plugin::Loader loader{};
if (loader.Open("libc.so")) {
    const auto strlenFn = loader.Symbol<size_t (*)(const char *)>("strlen");
}
```

### 3. 检查一个库是不是插件
```cpp
cpl::plugin::Loader loader{};
const auto plugin = cpl::plugin::LoadPlugin(loader, path);
if (!plugin) {
    // 不是插件：缺少入口符号，或 API 版本不对；loader 已关闭
}
```

## 注意事项

1. **线程安全**: `Loader` 自身不加锁。多个线程共用一个 loader 时需要外部加锁；
      `dlopen` 的句柄本身可以在多个线程里并发使用
2. **路径**: 建议传绝对路径。Windows 的 `LoadLibraryA` 传不带路径的文件名时会按搜索顺序查找，
      存在 DLL 预加载的风险；调用方应先用 `plugins.hpp` 验证包的签名，再加载解出来的库
3. **生命周期**: `Symbol` 返回的函数指针、`PluginEntry` 里的 `query` / `run`、以及 `info` 里的字符串，
      都只在加载它们的 `Loader` 保持打开期间有效。`Close()` 或析构之后不要再使用
4. **Open 的语义**: 已有库打开时再次 `Open` 会失败，需要先 `Close()`；
      传入 `LoadPlugin` 的 loader 如果已经打开着，会在失败的同时被关闭
5. **异常**: 本文件不主动抛出异常。字符串分配可能抛出 `std::bad_alloc`，
      此时 RAII 保证不泄漏共享库句柄
6. **插件边界**: 主程序与插件各自带一份 C++ 运行库，两边只传 C 类型，不跨边界抛异常
7. **兼容性**: 仅使用 C++11 的特性（没有 inline 变量、`std::optional`、变长数组）。
      Windows 分支按 MSVC v141（XP 目标）编写，并且用 v141_xp 工具集在 32 位 x86 上执行过测试。
      在真实的 Windows XP 上还没有执行过

## 测试
- `test/test_plugin_loader.cpp`（`TEST_SUITE("cpl::plugin::loader")`）：
  在系统库上打开、解析符号、关闭、移动；各种失败路径；用伪造的 `IfwPluginQuery` 测试 `impl::QueryPlugin`
  传入的结构体内容与版本核对；`EntrySymbolNames` 在各个平台上给出的名字；`EntrySymbol` 解析成功的情形，
  以及在名字不存在时原因文本里写的是 ABI 规定的名字
- 插件包格式（`cpl::plugins::LoadPackageConfigFromBytes`）的测试在 `test/test_plugins_package.cpp`
- 一个真实的插件库在宿主里的加载与运行，由 Windows 客户端的测试 `client/ifw/client/windows/test/test_plugin.cpp`
  覆盖：它加载示例插件 `ifw_plugin_demo.dll`，这个工程没有模块定义文件
