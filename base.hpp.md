# cpl/base.hpp - 基础头文件

## 文件概述
此文件定义了 CPL 库的基础类和接口，包括上下文接口、锁接口、单例模式、回调机制、序列化接口、日志控制和异常处理。

## 设计原则
- 基类和接口
- 不依赖具体系统平台
- 尽量不依赖 STL（但实际使用了部分 STL）

## 主要功能

### 1. 基础定义

#### 1.1 Stream 类型
```cpp
typedef std::vector<uint8_t> Stream;
```

**功能**: 字节流类型，用于数据序列化/反序列化

**用途**:
- 网络数据传输
- 文件读写
- 密文/明文转换

#### 1.2 宏定义

**PASS**
```cpp
#define PASS do{}while(false)
```

**功能**: 空语句，用于占位

**使用场景**:
- `goto __FREE__;` 之后的代码块

**bzero**
```cpp
#define bzero ZeroMemory
```

**功能**: 内存清零（Windows 平台）

### 2. 命名空间结构
```
cpl::base
├── IContext (上下文接口）
├── ILock (锁接口）
├── ISingleton (单例模板）
├── callback (回调机制）
│   └── ICallback
├── serialize (序列化接口）
│   ├── ISerialize
│   └── ISerializeJSON
├── log (日志控制）
│   ├── once()
│   └── limit()
└── exc (异常处理）
    ├── Category
    └── Exception
```

### 3. 接口定义

#### 3.1 IContext (上下文接口)

**功能**: 定义可加载/卸载的上下文接口

**纯虚函数**:
```cpp
virtual int32_t Load() = 0;     // 加载
virtual int32_t Unload() = 0;   // 卸载
virtual bool IsLoaded();        // 检查是否已加载（默认返回 false）
```

**使用示例**:
```cpp
class MyClass : public IContext {
    int32_t Load() override {
        // 初始化资源
        return ERROR_SUCCESS;
    }
    
    int32_t Unload() override {
        // 清理资源
        return ERROR_SUCCESS;
    }
    
    bool IsLoaded() override {
        return bLoaded;
    }
};
```

#### 3.2 ILock (锁接口)

**功能**: 定义锁接口，用于线程同步

**纯虚函数**:
```cpp
virtual int32_t Lock() = 0;     // 加锁
virtual int32_t Unlock() = 0;   // 解锁
```

**使用示例**:
```cpp
class Win32ThreadLock : public ILock {
    CRITICAL_SECTION cs{};
    
public:
    Win32ThreadLock() {
        InitializeCriticalSection(&cs);
    }
    
    int32_t Lock() override {
        EnterCriticalSection(&cs);
        return ERROR_SUCCESS;
    }
    
    int32_t Unlock() override {
        LeaveCriticalSection(&cs);
        return ERROR_SUCCESS;
    }
    
    ~Win32ThreadLock() {
        DeleteCriticalSection(&cs);
    }
};
```

### 4. 单例模式 (ISingleton)

#### 4.1 功能说明
**用途**: 解决 C++ 全局变量初始化顺序不确定问题

**特点**:
- 懒加载（首次使用时初始化）
- 线程安全（可传入锁）
- 自动管理生命周期

**注意事项**:
- 会与智能指针冲突
- 谨慎使用
- 如果全局变量够用，尽量避免使用
- 优先使用工厂方法

#### 4.2 使用方法

```cpp
class MyClass : public cpl::base::ISingleton<MyClass> {
private:
    MyClass() = default;  // 私有构造
    
    friend class ISingleton<MyClass>;  // 友元类
    
public:
    void DoSomething() {}
};

// 使用
MyClass::Instance().DoSomething();

// 带锁的单例
auto lock = std::make_unique<Win32ThreadLock>();
MyClass::Instance(lock.get());
```

#### 4.3 实现原理

**Instance() 静态方法**:
```cpp
static T &Instance(ILock *lock = nullptr) {
    static T *instance = nullptr;
    if (nullptr == instance) {
        if (nullptr != lock) {
            lock->Lock();  // 加锁
        }
        if (nullptr == instance) {
            instance = new T();  // 双重检查
            instance->_instance = instance;  // 记录实例
            instance->_lock = lock;  // 记录锁
        }
        if (nullptr != lock) {
            lock->Unlock();  // 解锁
        }
    }
    return *instance;
}
```

**Destroy() 静态方法**:
```cpp
static void Destroy() {
    auto &t = Instance();
    auto lock = t._lock;
    if (nullptr != lock) {
        lock->Lock();
    }
    if (nullptr != t._instance) {
        delete t._instance;
    }
    if (nullptr != lock) {
        lock->Unlock();
    }
    lock = nullptr;
}
```

**注意**: 一般不需要手动调用 `Destroy()`，由系统回收资源即可。

### 5. 回调机制 (callback)

#### 5.1 ICallback 模板

**功能**: 定义回调接口，用于遍历操作

**成员变量**:
```cpp
Identity identity{};  // 回调标识符（std::string）
```

**方法**:
```cpp
virtual std::string GetIdentity() const;  // 获取标识符
virtual int32_t Callback(_In_ T &obj) = 0;  // 回调函数
virtual bool ToBeContinued();  // 是否继续遍历（默认 true）
```

**返回值**:
- `Callback()`: ERROR_SUCCESS（成功）/ 其他（失败）
- `ToBeContinued()`: true（继续遍历）/ false（停止遍历）

**使用示例**:
```cpp
// 遍历所有网卡
class AdapterCallback : public cpl::base::callback::ICallback<_IP_ADAPTER_INFO> {
public:
    explicit AdapterCallback(const std::string &id) 
        : ICallback(id) {}
    
    int32_t Callback(_In_ _IP_ADAPTER_INFO &adapter) override {
        printf("Adapter: %s\n", adapter.Description);
        return ERROR_SUCCESS;
    }
    
    bool ToBeContinued() override {
        // 如果找到目标网卡，停止遍历
        return false;
    }
};

// 使用
AdapterCallback callback("MyCallback");
EnumerateAdapters(callback);
```

### 6. 序列化接口 (serialize)

#### 6.1 ISerialize

**功能**: 二进制序列化接口

**纯虚函数**:
```cpp
virtual Stream Serialize() = 0;  // 序列化
virtual void Unserialize(_In_ const Stream &in) = 0;  // 反序列化
```

**使用示例**:
```cpp
class MyData : public ISerialize {
    int32_t value;
    
public:
    Stream Serialize() override {
        Stream result;
        const auto *p = reinterpret_cast<const uint8_t*>(&value);
        result.insert(result.end(), p, p + sizeof(value));
        return result;
    }
    
    void Unserialize(_In_ const Stream &in) override {
        if (in.size() >= sizeof(value)) {
            memmove(&value, in.data(), sizeof(value));
        }
    }
};
```

#### 6.2 ISerializeJSON

**功能**: JSON 序列化接口

**纯虚函数**:
```cpp
virtual std::string ToJSON() = 0;  // 转换为 JSON
virtual void FromJSON(_In_ const std::string &in) = 0;  // 从 JSON 加载
```

**使用示例**:
```cpp
class AddressRange : public ISerializeJSON {
    std::string start;
    std::string end;
    
public:
    std::string ToJSON() override {
        return strings::Format(R"({"start":"%s","end":"%s"})", 
                              start.data(), end.data());
    }
    
    void FromJSON(_In_ const std::string &in) override {
        // 解析 JSON 字符串
    }
};
```

### 7. 日志控制 (log)

#### 7.1 once() - 单次日志

**功能**: 确保日志只输出一次

**使用场景**: 初始化日志、警告信息

```cpp
cpl::base::log::once([&]() {
    LOG_F(INFO, "This will be logged only once");
});
```

**实现原理**:
```cpp
template<typename Callable>
void once(Callable &&logFunc) {
    static BOOL onlyonce = TRUE;
    if (onlyonce) {
        onlyonce = FALSE;
        std::forward<Callable>(logFunc);
    }
}
```

#### 7.2 limit() - 限频日志

**功能**: 限制日志输出频率

**参数**:
- `logFunc`: 日志函数
- `limit`: 最大输出次数（默认 1800 次）
- `timeout`: 超时时间（默认 3600 秒 = 1 小时）

**使用场景**: 错误日志、调试信息

```cpp
cpl::base::log::limit([](bool isTimeUp, bool isCounterOut) {
    LOG_F(WARNING, "This will be logged at most 1800 times per hour");
}, 1800, 3600);
```

**实现原理**:
```cpp
template<typename Callable>
void limit(Callable &&logFunc, const uint32_t limit = 1800, 
          const uint32_t timeout = 3600) {
    static uint32_t counter = 0;
    static time_t timestamp = time(nullptr);
    static bool first = true;  // 第一次必然输出
    
    bool isTimeUp = false;
    bool isCounterOut = false;
    const auto currentTime = time(nullptr);
    
    if (currentTime - timestamp >= timeout) {
        isTimeUp = true;
    }
    if (counter + 1 > limit) {
        isCounterOut = true;
    }
    
    if (isTimeUp || isCounterOut || first) {
        first = false;
        std::forward<Callable>(logFunc)(isTimeUp, isCounterOut);
        timestamp = currentTime;
        counter = 0;
    }
}
```

**输出条件**:
1. 第一次调用
2. 超过时间限制（timeout）
3. 超过次数限制（limit）

**日志函数签名**:
```cpp
void(bool isTimeUp, bool isCounterOut)
```

### 8. 异常处理 (exc)

#### 8.1 Category 类

**功能**: 自定义错误类别

**继承**: `std::error_category`

**方法**:
```cpp
const char *name() const noexcept override;  // 返回 "cpl"
std::string message(const int ev) const override;  // 返回错误消息
```

#### 8.2 Exception 类

**功能**: 自定义异常类

**继承**: `std::system_error`

**构造函数**:
```cpp
explicit Exception(const int ErrVal, const std::string &Message);
explicit Exception(const int ErrVal, const char *Message);
explicit Exception(const std::error_code &ErrCode);
explicit Exception(const std::error_code &ErrCode, const std::string &Message);
explicit Exception(const std::error_code &ErrCode, const char *Message);
explicit Exception(int ErrVal, const std::error_category &ErrCat);
explicit Exception(int ErrVal, const std::error_category &ErrCat, const std::string &Message);
explicit Exception(int ErrVal, const std::error_category &ErrCat, const char *Message);
```

**使用示例**:
```cpp
// 使用错误码和消息
throw Exception(ERROR_FILE_NOT_FOUND, "File not found");

// 使用 error_code
throw cpl::base::exc::Exception(
    std::error_code(ERROR_INVALID_PARAMETER, cpl::base::exc::Category()),
    "Invalid parameter"
);
```

## 依赖关系
- `vector`: STL 向量
- `string`: STL 字符串
- `cstdint`: 整型类型
- `system_error`: 系统异常

## 关键设计决策

1. **单例模式**:
   - 懒加载
   - 线程安全
   - 自动管理生命周期
   - 避免全局变量初始化顺序问题

2. **接口隔离**:
   - 纯虚函数定义接口
   - 具体类实现接口
   - 便于扩展和测试

3. **回调机制**:
   - 模板化回调
   - 支持标识符
   - 支持提前终止

4. **序列化**:
   - 二进制序列化（高效）
   - JSON 序列化（可读）
   - 统一接口

5. **日志控制**:
   - 单次日志（避免重复）
   - 限频日志（避免刷屏）
   - 时间窗口 + 次数限制

6. **异常处理**:
   - 基于标准库
   - 自定义错误类别
   - 统一异常类型

## 注意事项
- `ISingleton` 会与智能指针冲突
- 尽量避免使用单例模式
- 优先使用工厂方法
- `PASS` 宏用于占位
- `bzero` 宏在 Windows 上映射到 `ZeroMemory`

## 使用示例

### 实现上下文接口
```cpp
class ResourceManager : public cpl::base::IContext {
    bool loaded = false;
    
public:
    int32_t Load() override {
        // 加载资源
        loaded = true;
        return ERROR_SUCCESS;
    }
    
    int32_t Unload() override {
        // 释放资源
        loaded = false;
        return ERROR_SUCCESS;
    }
    
    bool IsLoaded() override {
        return loaded;
    }
};

// 使用
auto manager = std::make_unique<ResourceManager>();
manager->Load();
if (manager->IsLoaded()) {
    // 使用资源
}
manager->Unload();
```

### 实现锁接口
```cpp
class MutexLock : public cpl::base::ILock {
    std::mutex mtx;
    
public:
    int32_t Lock() override {
        mtx.lock();
        return ERROR_SUCCESS;
    }
    
    int32_t Unlock() override {
        mtx.unlock();
        return ERROR_SUCCESS;
    }
};
```

### 使用回调遍历
```cpp
class PrintCallback : public cpl::base::callback::ICallback<std::string> {
public:
    explicit PrintCallback(const std::string &id) 
        : ICallback(id) {}
    
    int32_t Callback(_In_ std::string &obj) override {
        std::cout << obj << std::endl;
        return ERROR_SUCCESS;
    }
};

std::vector<std::string> items = {"a", "b", "c"};
PrintCallback callback("Print");
for (auto &item : items) {
    callback.Callback(item);
}
```

### 使用序列化
```cpp
class User : public cpl::base::serialize::ISerializeJSON {
    std::string name;
    int32_t age;
    
public:
    User(const std::string &n, int32_t a) : name(n), age(a) {}
    
    std::string ToJSON() override {
        return cpl::strings::Format(R"({"name":"%s","age":%d})", 
                                   name.data(), age);
    }
    
    void FromJSON(_In_ const std::string &in) override {
        // 解析 JSON
    }
};

User user("Alice", 30);
std::string json = user.ToJSON();
// {"name":"Alice","age":30}
```

### 使用日志控制
```cpp
// 单次日志
cpl::base::log::once([]() {
    LOG_F(INFO, "Program started");
});

// 限频日志（最多 100 次 / 10 分钟）
cpl::base::log::limit([](bool isTimeUp, bool isCounterOut) {
    if (isTimeUp) {
        LOG_F(WARNING, "Time limit reached, counter reset");
    } else if (isCounterOut) {
        LOG_F(WARNING, "Count limit reached");
    } else {
        LOG_F(INFO, "Processing...");
    }
}, 100, 600);
```

### 使用异常
```cpp
try {
    if (!file_exists(path)) {
        throw cpl::base::exc::Exception(
            ERROR_FILE_NOT_FOUND, 
            "File not found"
        );
    }
} catch (const cpl::base::exc::Exception &e) {
    LOG_F(ERROR, "[%d] %s", e.code().value(), e.what());
}