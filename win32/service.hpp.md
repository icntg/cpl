# cpl/win32/service.hpp - Windows 服务管理

## 文件概述
此文件定义了 Windows 服务管理功能，包括服务安装、卸载、启动、停止和服务运行框架。

## 设计原则
- 简化 Windows 服务开发
- RAII 模式管理资源
- 统一的错误处理
- 支持服务恢复配置

## 主要功能

### 1. 异常类型枚举

**功能**: 定义服务操作的异常类型

```cpp
enum class ExceptionType : int32_t {
    OpenSCManagerException = 0x01000010,      // 打开服务管理器失败
    CreateServiceException = 0x01000011,      // 创建服务失败
    ChangeServiceConfigException = 0x01000012, // 修改服务配置失败
    StartServiceException = 0x01000013,        // 启动服务失败
    OpenServiceException = 0x01000014,         // 打开服务失败
    QueryServiceStatusException = 0x01000015, // 查询服务状态失败
    ControlServiceException = 0x01000016,     // 控制服务失败
    DeleteServiceException = 0x01000017,       // 删除服务失败
};
```

### 2. Install - 安装服务

**功能**: 安装 Windows 服务并自动启动

**函数签名**:
```cpp
inline int32_t Install(
    const std::wstring &ServiceName,
    const std::wstring &DisplayName,
    const std::wstring &ExecutePath
)
```

**参数**:
- `ServiceName`: 服务名称（内部名称）
- `DisplayName`: 服务显示名称
- `ExecutePath`: 可执行文件路径

**返回值**:
- 0: 成功
- 异常: 失败

**实现逻辑**:
```cpp
1. 打开服务管理器 (OpenSCManagerW)
2. 创建服务 (CreateServiceW)
3. 配置服务恢复设置:
   - 失败后 10 秒重启
   - 永不重置失败计数
4. 启动服务 (StartServiceW)
5. 关闭所有句柄
```

**服务配置**:
```cpp
服务类型: SERVICE_WIN32_OWN_PROCESS
启动类型: SERVICE_AUTO_START
错误处理: SERVICE_ERROR_NORMAL
恢复操作: 10 秒后重启
重置周期: 永不重置
```

**使用示例**:
```cpp
int32_t ret = Install(
    L"IFW",
    L"Internal Firewall Service",
    L"C:\\Program Files\\IFW\\ifw.exe"
);

if (ret == 0) {
    // 安装成功
}
```

### 3. Uninstall - 卸载服务

**功能**: 停止并删除 Windows 服务

**函数签名**:
```cpp
inline int32_t Uninstall(const std::wstring &ServiceName)
```

**参数**:
- `ServiceName`: 服务名称

**返回值**:
- 0: 成功
- 异常: 失败

**实现逻辑**:
```cpp
1. 打开服务管理器 (OpenSCManagerW)
2. 打开服务 (OpenServiceW)
3. 查询服务状态
4. 如果服务正在运行:
   - 发送停止命令 (ControlService)
   - 等待服务停止（最多 1 分钟）
5. 删除服务 (DeleteService)
6. 关闭所有句柄
```

**等待逻辑**:
- 最多等待 60 秒
- 每秒检查一次状态
- 等待直到服务停止

**使用示例**:
```cpp
int32_t ret = Uninstall(L"IFW");

if (ret == 0) {
    // 卸载成功
}
```

### 4. IServiceEventLoop - 服务事件循环接口

**功能**: 定义服务事件循环接口

**成员变量**:
```cpp
mutable WindowsService *mService{};  // 服务实例
mutable HANDLE stopEvent{};          // 停止事件
```

**方法**:

**EventLoop()**:
```cpp
virtual void EventLoop() = 0;
```

**功能**: 事件循环函数（纯虚函数）

**使用示例**:
```cpp
class MyServiceEventLoop : public IServiceEventLoop {
public:
    void EventLoop() override {
        // 等待停止事件
        while (WaitForSingleObject(stopEvent, 1000) != WAIT_OBJECT_0) {
            // 执行服务逻辑
            DoWork();
        }
    }
};
```

### 5. WindowsService - Windows 服务基类

**功能**: Windows 服务基类，提供服务运行框架

**成员变量**:
```cpp
static IServiceEventLoop *wrapper;           // 事件循环包装器
std::wstring serviceName{};                   // 服务名称
SERVICE_STATUS serviceStatus{};              // 服务状态
SERVICE_STATUS_HANDLE serviceStatusHandle{};  // 服务状态句柄
```

**方法**:

**构造函数**:
```cpp
explicit WindowsService(const std::wstring &serviceName, IServiceEventLoop *_wrapper)
```

**参数**:
- `serviceName`: 服务名称
- `_wrapper`: 事件循环实现

**Run()**:
```cpp
virtual void Run()
```

**功能**: 启动服务

**实现逻辑**:
```cpp
1. 构造服务表 (SERVICE_TABLE_ENTRYW)
2. 调用 StartServiceCtrlDispatcherW
3. 将控制权交给 SCM (Service Control Manager)
```

**使用示例**:
```cpp
MyServiceEventLoop eventLoop;
WindowsService service(L"IFW", &eventLoop);

// 启动服务（通常在 ServiceMain 中调用）
service.Run();
```

**ServiceMain()**:
```cpp
virtual void ServiceMain(DWORD argc, LPWSTR *argv)
```

**功能**: 服务主函数

**实现逻辑**:
```cpp
1. 注册服务控制处理器 (RegisterServiceCtrlHandlerW)
2. 初始化服务状态 (SERVICE_START_PENDING)
3. 创建停止事件
4. 更新服务状态为运行 (SERVICE_RUNNING)
5. 调用事件循环 (EventLoop)
6. 更新服务状态为停止 (SERVICE_STOPPED)
```

**服务状态转换**:
```
START_PENDING → RUNNING → STOPPED
             ↓
          STOP_PENDING
```

**ControlHandler()**:
```cpp
virtual void ControlHandler(const DWORD controlCode)
```

**功能**: 处理服务控制命令

**支持的控制码**:
- `SERVICE_CONTROL_STOP`: 停止服务
- `SERVICE_CONTROL_SHUTDOWN`: 关闭服务

**实现逻辑**:
```cpp
1. 接收控制码
2. 更新服务状态为停止中 (SERVICE_STOP_PENDING)
3. 设置停止事件
4. 更新服务状态为停止 (SERVICE_STOPPED)
```

**使用示例**:
```cpp
// ControlHandler 会被 SCM 自动调用
// 开发者不需要手动调用
```

## 依赖关系
- `api.hpp`: API 动态加载

## 使用场景

### 1. 安装服务

```cpp
// 安装服务
int32_t ret = Install(
    L"IFW",
    L"Internal Firewall Service",
    L"C:\\Program Files\\IFW\\ifw.exe"
);

if (ret == 0) {
    std::cout << "Service installed successfully" << std::endl;
}
```

### 2. 卸载服务

```cpp
// 卸载服务
int32_t ret = Uninstall(L"IFW");

if (ret == 0) {
    std::cout << "Service uninstalled successfully" << std::endl;
}
```

### 3. 创建服务类

```cpp
class IFWServiceEventLoop : public IServiceEventLoop {
public:
    void EventLoop() override {
        LOG_I("Service started");
        
        // 等待停止事件
        while (WaitForSingleObject(stopEvent, 1000) != WAIT_OBJECT_0) {
            // 执行服务逻辑
            DoWork();
            
            // 每秒执行一次
            Sleep(1000);
        }
        
        LOG_I("Service stopped");
    }

private:
    void DoWork() {
        // 执行实际工作
        LOG_D("Working...");
    }
};
```

### 4. 运行服务

```cpp
// 在 main 函数中
int main() {
    // 创建事件循环
    IFWServiceEventLoop eventLoop;
    
    // 创建服务
    WindowsService service(L"IFW", &eventLoop);
    
    // 运行服务（服务方式启动时调用）
    service.Run();
    
    return 0;
}
```

### 5. 服务入口点

```cpp
// Windows 服务入口点
void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    static IFWServiceEventLoop eventLoop;
    static WindowsService service(L"IFW", &eventLoop);
    
    service.ServiceMain(argc, argv);
}
```

## 错误处理

### 1. 安装失败

```cpp
try {
    Install(L"IFW", L"IFW Service", L"ifw.exe");
} catch (const cpl::base::exc::Exception &e) {
    if (e.Code() == (int32_t)ExceptionType::CreateServiceException) {
        std::cerr << "Failed to create service" << std::endl;
    } else if (e.Code() == (int32_t)ExceptionType::StartServiceException) {
        std::cerr << "Failed to start service" << std::endl;
    }
}
```

### 2. 卸载失败

```cpp
try {
    Uninstall(L"IFW");
} catch (const cpl::base::exc::Exception &e) {
    if (e.Code() == (int32_t)ExceptionType::DeleteServiceException) {
        std::cerr << "Failed to delete service" << std::endl;
    }
}
```

### 3. 服务运行失败

```cpp
virtual void ServiceMain(DWORD argc, LPWSTR *argv) {
    // 注册控制处理器失败
    const auto r0 = RegisterServiceCtrlHandlerW(serviceName.data(), ControlHandlerWrapper);
    if (!r0) {
        // 返回错误
        return;
    }
    
    // 继续初始化...
}
```

## 关键设计决策

### 1. 服务恢复配置

**优点**:
- 自动重启失败的服务
- 提高服务可用性
- 减少人工干预

**配置**:
```cpp
失败后 10 秒重启
永不重置失败计数
```

### 2. RAII 模式

**优点**:
- 自动关闭句柄
- 避免资源泄漏
- 异常安全

**示例**:
```cpp
const auto $release$ = [&]() {
    if (serviceHandle) {
        CloseServiceHandle(serviceHandle);
    }
    if (scmHandle) {
        CloseServiceHandle(scmHandle);
    }
};

try {
    // 执行操作
} catch (...) {
    $release$();
    throw;
}
$release$();
```

### 3. 事件循环模式

**优点**:
- 分离服务逻辑和服务框架
- 灵活的事件处理
- 易于测试

**示例**:
```cpp
class MyEventLoop : public IServiceEventLoop {
public:
    void EventLoop() override {
        while (!stopRequested) {
            // 执行工作
        }
    }
};
```

## 注意事项

### 1. 服务权限

- 服务以 SYSTEM 账户运行
- 需要管理员权限安装/卸载
- 访问网络和文件需要特殊权限

### 2. 服务状态

- 必须正确更新服务状态
- 状态更新使用 `SetServiceStatus`
- 状态转换必须符合 Windows 规范

### 3. 停止处理

- 必须响应停止命令
- 清理所有资源
- 设置停止事件

### 4. 日志记录

- 服务运行在后台
- 使用日志文件记录
- 不要使用标准输出

### 5. 错误处理

- 捕获所有异常
- 记录错误信息
- 优雅降级

## 最佳实践

### 1. 错误处理

```cpp
try {
    Install(serviceName, displayName, executePath);
} catch (const cpl::base::exc::Exception &e) {
    LOG_E("Failed to install service: %s", e.what());
    return false;
}
```

### 2. 资源管理

```cpp
// 使用 RAII
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        throw std::runtime_error("Failed to open SCM");
    }
    
    // 使用 scm
} // 自动关闭
```

### 3. 状态更新

```cpp
// 更新服务状态
serviceStatus.dwCurrentState = SERVICE_RUNNING;
SetServiceStatus(serviceStatusHandle, &serviceStatus);
```

### 4. 停止处理

```cpp
// 处理停止命令
void ControlHandler(DWORD controlCode) {
    if (controlCode == SERVICE_CONTROL_STOP) {
        // 设置停止事件
        SetEvent(stopEvent);
        
        // 更新状态
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}
```

### 5. 日志记录

```cpp
// 记录服务事件
LOG_I("Service started");
LOG_E("Error occurred: %s", error);
LOG_I("Service stopped");
```

## 性能优化

### 1. 减少状态更新

```cpp
// 批量更新状态
void UpdateStatus(DWORD state) {
    serviceStatus.dwCurrentState = state;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

// 只在必要时更新
UpdateStatus(SERVICE_RUNNING);
```

### 2. 异步处理

```cpp
// 使用线程处理工作
void EventLoop() override {
    HANDLE hThread = CreateThread(nullptr, 0, WorkerThread, this, 0, nullptr);
    
    // 等待停止事件
    WaitForSingleObject(stopEvent, INFINITE);
    
    // 等待工作线程
    WaitForSingleObject(hThread, INFINITE);
}
```

### 3. 定时任务

```cpp
// 使用定时器
void EventLoop() override {
    HANDLE hTimer = CreateWaitableTimer(nullptr, FALSE, nullptr);
    
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000000LL; // 1 秒
    
    SetWaitableTimer(hTimer, &dueTime, 1000, nullptr, nullptr, FALSE);
    
    while (WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0) {
        WaitForSingleObject(hTimer, INFINITE);
        DoWork();
    }
}
```

## 扩展性

### 1. 添加暂停/恢复支持

```cpp
class IServiceEventLoop {
public:
    virtual void Pause() = 0;
    virtual void Resume() = 0;
};

void ControlHandler(DWORD controlCode) {
    switch (controlCode) {
        case SERVICE_CONTROL_PAUSE:
            wrapper->Pause();
            break;
        case SERVICE_CONTROL_CONTINUE:
            wrapper->Resume();
            break;
    }
}
```

### 2. 添加参数支持

```cpp
void ServiceMain(DWORD argc, LPWSTR *argv) {
    // 解析参数
    for (DWORD i = 0; i < argc; i++) {
        LOG_I("Argument %d: %ls", i, argv[i]);
    }
    
    // 继续初始化...
}
```

### 3. 添加自定义控制码

```cpp
#define SERVICE_CONTROL_CUSTOM 128

void ControlHandler(DWORD controlCode) {
    if (controlCode == SERVICE_CONTROL_CUSTOM) {
        // 处理自定义命令
        HandleCustomCommand();
    }
}
```

### 4. 添加配置支持

```cpp
class WindowsService {
protected:
    std::wstring configPath{};
    
public:
    void LoadConfig(const std::wstring &path) {
        configPath = path;
        // 加载配置
    }
};
```

## 实际应用（IFW 项目）

### 1. 服务安装

```cpp
// 在 installService() 中
Install(
    constants::ServiceNameW,
    constants::ServiceDisplayNameW,
    wInternal
);
```

### 2. 服务卸载

```cpp
// 在 uninstallService() 中
Uninstall(constants::ServiceNameW);
```

### 3. 服务运行

```cpp
// 在 Service 模式下运行
if (global::globals->dwRunningMode == 1) {
    WindowsService::Service.Run();
}
```

### 4. 事件循环

```cpp
// 在 loop::svc::srv::Service 中
class ServiceEventLoop : public IServiceEventLoop {
public:
    void EventLoop() override {
        // 初始化网络
        InitNetwork();
        
        // 初始化规则
        InitRules();
        
        // 事件循环
        while (WaitForSingleObject(stopEvent, 1000) != WAIT_OBJECT_0) {
            // 处理网络包
            ProcessPackets();
            
            // 更新统计
            UpdateStats();
        }
        
        // 清理资源
        Cleanup();
    }
};
```

## 调试技巧

### 1. 查看服务状态

```cpp
// 使用 sc 命令
sc query IFW

// 或使用服务管理器
services.msc
```

### 2. 查看服务日志

```cpp
// 服务日志通常在事件查看器中
eventvwr.msc

// 或使用应用程序日志文件
type C:\path\to\ifw.log
```

### 3. 调试服务

```cpp
// 在控制台模式下调试
int main() {
    if (IsDebugMode()) {
        // 直接运行事件循环
        IFWServiceEventLoop eventLoop;
        WindowsService service(L"IFW", &eventLoop);
        eventLoop.EventLoop();
    } else {
        // 作为服务运行
        WindowsService::Service.Run();
    }
}
```

### 4. 模拟停止命令

```cpp
// 使用 sc 命令停止服务
sc stop IFW

// 或在事件循环中手动设置停止事件
SetEvent(stopEvent);
```

## 总结

### 推荐使用顺序

1. **安装服务**: `Install()`
2. **卸载服务**: `Uninstall()`
3. **创建服务**: 继承 `IServiceEventLoop`
4. **运行服务**: `WindowsService::Run()`

### 关键要点

- 使用 RAII 管理资源
- 正确更新服务状态
- 响应停止命令
- 清理所有资源
- 使用日志记录
- 处理所有异常
- 管理服务恢复
- 测试服务安装/卸载