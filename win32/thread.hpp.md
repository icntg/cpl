# cpl/win32/thread.hpp - 线程管理

## 文件概述
此文件定义了 Windows 平台的线程管理类，提供简化线程创建和管理的功能。

## 设计原则
- 简化线程创建
- RAII 模式管理资源
- 支持两种线程创建方式
- 统一的错误处理

## 主要功能

### 1. 回调函数类型

**功能**: 定义线程回调函数类型

```cpp
typedef DWORD (CALLBACK *CallbackFunction)(LPVOID args);
```

**参数**:
- `args`: 线程参数（可以为 nullptr）

**返回值**: 线程退出码

**使用示例**:
```cpp
DWORD CALLBACK MyThreadFunction(LPVOID args) {
    // 线程逻辑
    return 0;
}
```

### 2. Thread 类 - 线程管理类

**功能**: 封装 Windows 线程创建和管理

**成员变量**:
```cpp
DWORD threadId{};              // 线程 ID
HANDLE threadHandle{};         // 线程句柄
CallbackFunction callback{};    // 回调函数
```

#### 2.1 构造函数

**函数签名**:
```cpp
explicit Thread(CallbackFunction callback)
```

**参数**:
- `callback`: 线程回调函数

**使用示例**:
```cpp
Thread thread(MyThreadFunction);
```

#### 2.2 析构函数

**功能**: 自动关闭线程句柄

```cpp
~Thread()
```

**行为**:
- 如果线程句柄有效，关闭句柄
- 清理线程 ID

**使用示例**:
```cpp
{
    Thread thread(MyThreadFunction);
    thread.Start();
} // 自动关闭线程句柄
```

#### 2.3 Start - 创建线程（CreateThread）

**功能**: 使用 `CreateThread` 创建线程

**函数签名**:
```cpp
INT32 Start()
```

**返回值**:
- 0: 成功
- 异常: 失败

**实现逻辑**:
```cpp
1. 调用 CreateThread() 创建线程
2. 保存线程句柄和 ID
3. 失败时抛出异常
```

**参数**:
```cpp
安全属性: nullptr（默认）
堆栈大小: 0（默认）
线程函数: callback
参数: nullptr
创建标志: 0（立即运行）
线程 ID: &this->threadId
```

**注意事项**:
- 可能导致内存泄漏
- 适用于一次性启动、无限循环的任务
- 是否引入 `InitializeCriticalSectionEx` 未知

**使用示例**:
```cpp
Thread thread(MyThreadFunction);
thread.Start();

// 等待线程结束
WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
```

#### 2.4 StartEx - 创建线程（_beginthreadex）

**功能**: 使用 `_beginthreadex` 创建线程

**函数签名**:
```cpp
INT32 StartEx()
```

**返回值**:
- 0: 成功
- 异常: 失败

**实现逻辑**:
```cpp
1. 调用 _beginthreadex() 创建线程
2. 保存线程句柄和 ID
3. 检查错误码并处理
4. 失败时抛出异常
```

**错误处理**:

| 错误码 | 含义 | 处理 |
|--------|------|------|
| EAGAIN | 线程太多 | 抛出异常 |
| EINVAL | 参数错误 | 抛出异常 |
| EACCES | 资源不足 | 抛出异常 |

**注意事项**:
- 不会导致内存泄漏
- 但会引入 `InitializeCriticalSectionEx` 不兼容 XP
- 适用于需要频繁启动、关闭线程的场景

**使用示例**:
```cpp
Thread thread(MyThreadFunction);
thread.StartEx();

// 等待线程结束
WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
```

#### 2.5 GetThreadId - 获取线程 ID

**功能**: 获取线程 ID

**函数签名**:
```cpp
DWORD GetThreadId() const
```

**返回值**: 线程 ID

**使用示例**:
```cpp
Thread thread(MyThreadFunction);
thread.Start();

DWORD tid = thread.GetThreadId();
printf("Thread ID: %lu\n", tid);
```

#### 2.6 GetThreadHandle - 获取线程句柄

**功能**: 获取线程句柄

**函数签名**:
```cpp
HANDLE &GetThreadHandle()
```

**返回值**: 线程句柄引用

**使用示例**:
```cpp
Thread thread(MyThreadFunction);
thread.Start();

HANDLE hThread = thread.GetThreadHandle();

// 等待线程结束
WaitForSingleObject(hThread, INFINITE);
```

## 依赖关系
- `windows.h`: Windows API
- `process.h`: `_beginthreadex` 函数

## 使用场景

### 1. 创建工作线程

```cpp
DWORD CALLBACK WorkerThread(LPVOID args) {
    // 执行工作
    for (int i = 0; i < 100; i++) {
        printf("Working... %d\n", i);
        Sleep(100);
    }
    return 0;
}

int main() {
    Thread thread(WorkerThread);
    thread.Start();
    
    // 等待线程结束
    WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
    
    return 0;
}
```

### 2. 创建后台服务线程

```cpp
DWORD CALLBACK ServiceThread(LPVOID args) {
    // 后台服务
    while (true) {
        // 处理请求
        ProcessRequests();
        Sleep(1000);
    }
    return 0;
}

int main() {
    Thread thread(ServiceThread);
    thread.Start();
    
    // 主线程继续执行
    DoMainWork();
    
    return 0;
}
```

### 3. 频繁创建销毁线程

```cpp
DWORD CALLBACK TaskThread(LPVOID args) {
    // 执行任务
    DoTask();
    return 0;
}

void ProcessTasks() {
    for (int i = 0; i < 100; i++) {
        Thread thread(TaskThread);
        thread.StartEx(); // 使用 StartEx 避免内存泄漏
        
        // 等待任务完成
        WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
    }
}
```

### 4. 传递参数给线程

```cpp
struct ThreadArgs {
    int id;
    const char* message;
};

DWORD CALLBACK ThreadWithArgs(LPVOID args) {
    ThreadArgs* pArgs = (ThreadArgs*)args;
    printf("Thread %d: %s\n", pArgs->id, pArgs->message);
    delete pArgs;
    return 0;
}

int main() {
    ThreadArgs* args = new ThreadArgs{1, "Hello"};
    Thread thread(ThreadWithArgs);
    thread.Start();
    
    WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
    return 0;
}
```

## 性能对比

| 特性 | Start (CreateThread) | StartEx (_beginthreadex) |
|------|----------------------|--------------------------|
| 内存泄漏 | 可能 | 不会 |
| XP 兼容性 | 完全 | 可能有问题 |
| CRT 初始化 | 可能不完整 | 完整 |
| 适用场景 | 长期线程 | 短期线程 |
| 频繁创建 | 不推荐 | 推荐 |

## 错误处理

### 1. 线程创建失败

```cpp
try {
    Thread thread(MyThreadFunction);
    thread.Start();
} catch (const std::system_error &e) {
    std::cerr << "Failed to create thread: " << e.what() << std::endl;
    std::cerr << "Error code: " << e.code() << std::endl;
}
```

### 2. 线程太多

```cpp
try {
    Thread thread(MyThreadFunction);
    thread.StartEx();
} catch (const std::system_error &e) {
    if (errno == EAGAIN) {
        std::cerr << "Too many threads" << std::endl;
    }
}
```

### 3. 参数错误

```cpp
try {
    Thread thread(MyThreadFunction);
    thread.StartEx();
} catch (const std::system_error &e) {
    if (errno == EINVAL) {
        std::cerr << "Invalid parameters" << std::endl;
    }
}
```

### 4. 资源不足

```cpp
try {
    Thread thread(MyThreadFunction);
    thread.StartEx();
} catch (const std::system_error &e) {
    if (errno == EACCES) {
        std::cerr << "Not enough resources" << std::endl;
    }
}
```

## 注意事项

### 1. 线程句柄管理

- 析构函数自动关闭句柄
- 不要手动关闭句柄
- 使用 RAII 确保资源释放

### 2. 线程同步

- 当前类不提供同步机制
- 需要使用临界区、互斥锁等
- 注意竞态条件

### 3. 内存泄漏

- `Start()` 可能导致内存泄漏
- 长期运行的线程使用 `Start()`
- 短期线程使用 `StartEx()`

### 4. XP 兼容性

- `Start()` 完全兼容 XP
- `StartEx()` 可能不兼容 XP
- 需要支持 XP 时谨慎使用

### 5. 线程参数

- 当前实现不传递参数
- 回调函数接收 nullptr
- 需要使用全局变量或静态变量

## 最佳实践

### 1. 使用 RAII

```cpp
// 自动管理线程句柄
{
    Thread thread(MyThreadFunction);
    thread.Start();
    
    // 使用线程
} // 自动关闭句柄
```

### 2. 等待线程结束

```cpp
Thread thread(MyThreadFunction);
thread.Start();

// 等待线程结束
WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
```

### 3. 选择合适的启动函数

```cpp
// 长期线程
Thread longThread(LongRunningThread);
longThread.Start();

// 短期线程
Thread shortThread(ShortRunningThread);
shortThread.StartEx();
```

### 4. 错误处理

```cpp
try {
    Thread thread(MyThreadFunction);
    thread.Start();
} catch (const std::system_error &e) {
    LOG_E("Thread creation failed: %s", e.what());
    return false;
}
```

### 5. 线程同步

```cpp
CRITICAL_SECTION cs;
InitializeCriticalSection(&cs);

DWORD CALLBACK ThreadFunction(LPVOID args) {
    EnterCriticalSection(&cs);
    // 临界区代码
    LeaveCriticalSection(&cs);
    return 0;
}

// 使用线程
Thread thread(ThreadFunction);
thread.Start();

// 等待并清理
WaitForSingleObject(thread.GetThreadHandle(), INFINITE);
DeleteCriticalSection(&cs);
```

## 性能优化

### 1. 线程池

```cpp
// 使用线程池减少创建开销
class ThreadPool {
private:
    std::vector<Thread*> threads;
    
public:
    void Initialize(int count) {
        for (int i = 0; i < count; i++) {
            Thread* thread = new Thread(WorkerThread);
            thread->Start();
            threads.push_back(thread);
        }
    }
    
    void Shutdown() {
        for (auto* thread : threads) {
            WaitForSingleObject(thread->GetThreadHandle(), INFINITE);
            delete thread;
        }
    }
};
```

### 2. 任务队列

```cpp
// 使用任务队列分配工作
std::queue<Task*> taskQueue;
CRITICAL_SECTION csQueue;
HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

DWORD CALLBACK WorkerThread(LPVOID args) {
    while (true) {
        // 等待任务
        WaitForSingleObject(hEvent, INFINITE);
        
        // 获取任务
        EnterCriticalSection(&csQueue);
        Task* task = taskQueue.front();
        taskQueue.pop();
        LeaveCriticalSection(&csQueue);
        
        // 执行任务
        task->Execute();
        delete task;
    }
    return 0;
}
```

### 3. 批量处理

```cpp
// 批量创建线程
std::vector<Thread*> threads;

for (int i = 0; i < 10; i++) {
    Thread* thread = new Thread(WorkerThread);
    thread->Start();
    threads.push_back(thread);
}

// 等待所有线程
for (auto* thread : threads) {
    WaitForSingleObject(thread->GetThreadHandle(), INFINITE);
    delete thread;
}
```

## 扩展性

### 1. 添加参数传递

```cpp
class ThreadEx : public Thread {
private:
    LPVOID args;
    
public:
    ThreadEx(CallbackFunction callback, LPVOID args)
        : Thread(callback), args(args) {
    }
    
    INT32 StartWithArgs() {
        this->threadHandle = CreateThread(
            nullptr,
            0,
            this->callback,
            this->args,
            0,
            &this->threadId
        );
        // ...
    }
};
```

### 2. 添加线程状态

```cpp
class ThreadWithState : public Thread {
private:
    bool running;
    
public:
    bool IsRunning() const {
        return running;
    }
    
    DWORD CALLBACK Wrapper(LPVOID args) {
        running = true;
        DWORD ret = callback(args);
        running = false;
        return ret;
    }
};
```

### 3. 添加超时支持

```cpp
class ThreadWithTimeout : public Thread {
public:
    bool WaitForCompletion(DWORD timeout) {
        DWORD ret = WaitForSingleObject(threadHandle, timeout);
        return ret == WAIT_OBJECT_0;
    }
};
```

### 4. 添加取消支持

```cpp
class ThreadWithCancel : public Thread {
private:
    bool cancelled;
    
public:
    void Cancel() {
        cancelled = true;
    }
    
    DWORD CALLBACK Wrapper(LPVOID args) {
        while (!cancelled) {
            // 执行工作
            DoWork();
        }
        return 0;
    }
};
```

## 实际应用（IFW 项目）

### 1. 网络监听线程

```cpp
DWORD CALLBACK NetworkListenerThread(LPVOID args) {
    // 初始化网络
    InitNetwork();
    
    // 监听循环
    while (true) {
        // 接收数据包
        Packet packet = ReceivePacket();
        
        // 处理数据包
        ProcessPacket(packet);
    }
    return 0;
}

// 启动网络监听线程
Thread listenerThread(NetworkListenerThread);
listenerThread.Start();
```

### 2. 日志写入线程

```cpp
DWORD CALLBACK LoggerThread(LPVOID args) {
    while (true) {
        // 等待日志事件
        WaitForSingleObject(hLogEvent, INFINITE);
        
        // 获取日志
        EnterCriticalSection(&csLog);
        std::string log = logQueue.front();
        logQueue.pop();
        LeaveCriticalSection(&csLog);
        
        // 写入日志
        WriteLog(log);
    }
    return 0;
}

// 启动日志线程
Thread loggerThread(LoggerThread);
loggerThread.Start();
```

### 3. 统计更新线程

```cpp
DWORD CALLBACK StatsUpdateThread(LPVOID args) {
    while (true) {
        // 更新统计
        UpdateStatistics();
        
        // 每分钟更新一次
        Sleep(60000);
    }
    return 0;
}

// 启动统计线程
Thread statsThread(StatsUpdateThread);
statsThread.Start();
```

### 4. 心跳检测线程

```cpp
DWORD CALLBACK HeartbeatThread(LPVOID args) {
    while (true) {
        // 发送心跳
        SendHeartbeat();
        
        // 每 5 秒发送一次
        Sleep(5000);
    }
    return 0;
}

// 启动心跳线程
Thread heartbeatThread(HeartbeatThread);
heartbeatThread.Start();
```

## 调试技巧

### 1. 调试线程

```cpp
DWORD CALLBACK DebugThread(LPVOID args) {
    printf("Thread started\n");
    
    // 执行工作
    DoWork();
    
    printf("Thread finished\n");
    return 0;
}

Thread thread(DebugThread);
thread.Start();

// 检查线程 ID
printf("Thread ID: %lu\n", thread.GetThreadId());
```

### 2. 监控线程状态

```cpp
DWORD CALLBACK WorkerThread(LPVOID args) {
    printf("Working...\n");
    Sleep(5000);
    printf("Done\n");
    return 0;
}

Thread thread(WorkerThread);
thread.Start();

// 检查线程是否运行
DWORD ret = WaitForSingleObject(thread.GetThreadHandle(), 0);
if (ret == WAIT_TIMEOUT) {
    printf("Thread is still running\n");
}
```

### 3. 捕获线程异常

```cpp
DWORD CALLBACK ThreadWithException(LPVOID args) {
    try {
        // 可能抛出异常的代码
        RiskyOperation();
    } catch (const std::exception& e) {
        printf("Thread exception: %s\n", e.what());
    }
    return 0;
}

Thread thread(ThreadWithException);
thread.Start();
```

### 4. 性能测试

```cpp
DWORD CALLBACK PerformanceThread(LPVOID args) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // 执行工作
    DoWork();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    printf("Thread completed in %lld ms\n", duration.count());
    return 0;
}

Thread thread(PerformanceThread);
thread.Start();
```

## 总结

### 推荐使用顺序

1. **长期线程**: `Start()` (CreateThread)
2. **短期线程**: `StartEx()` (_beginthreadex)
3. **获取 ID**: `GetThreadId()`
4. **获取句柄**: `GetThreadHandle()`

### 关键要点

- 使用 RAII 管理线程句柄
- 选择合适的启动函数
- 正确处理线程同步
- 等待线程结束
- 捕获线程异常
- 注意 XP 兼容性
- 避免内存泄漏
- 监控线程状态