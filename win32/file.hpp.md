# cpl/win32/file.hpp - 文件操作工具

## 文件概述
此文件定义了 Windows 平台的文件操作工具，包括文件大小获取、文件读取和内存映射文件等功能。

## 设计原则
- 简化文件操作
- 支持多种文件访问方式
- RAII 模式管理资源
- 统一的错误处理

## 主要功能

### 1. GetFileSize - 获取文件大小

**功能**: 获取文件大小（字节）

**函数签名**:
```cpp
inline int64_t GetFileSize(const std::string &filename)
```

**参数**:
- `filename`: 文件路径

**返回值**: 文件大小（字节）

**实现逻辑**:
```cpp
1. 尝试使用 stat() 获取文件大小
   - 成功 → 返回 st.st_size
   - 失败 → 继续

2. 使用 fopen_s() 打开文件
   - 失败 → 抛出异常

3. 使用 _fseeki64() 移动到文件末尾
   - 失败 → 抛出异常

4. 使用 _ftelli64() 获取当前位置
   - 成功 → 返回文件大小
   - 失败 → 抛出异常
```

**注意**:
- `stat()` 只支持绝对路径
- `stat()` 只支持纯英文路径
- 使用 64 位函数支持大文件

**使用示例**:
```cpp
int64_t size = GetFileSize("C:\\path\\to\\file.txt");
if (size > 0) {
    // 文件存在
}
```

### 2. ReadFile - 读取文件内容

**功能**: 读取整个文件内容

**函数签名**:
```cpp
inline Stream ReadFile(_In_ const std::string &filename)
```

**参数**:
- `filename`: 文件路径

**返回值**: 文件内容（Stream 类型）

**实现逻辑**:
```cpp
1. 使用 fopen_s() 打开文件（二进制读取模式）
   - 失败 → 抛出异常

2. 使用 fseek() 移动到文件末尾
3. 使用 ftell() 获取文件大小
   - 失败 → 抛出异常

4. 使用 fseek() 移动到文件开头

5. 分配缓冲区（fileSize + 1 字节）

6. 使用 fread_s() 读取文件内容
   - 失败 → 抛出异常

7. 调整缓冲区大小为实际读取字节数

8. 关闭文件

9. 返回文件内容
```

**返回类型**: `Stream`（通常是 `std::vector<uint8_t>`）

**使用示例**:
```cpp
// 读取文件
Stream content = ReadFile("config.json");

// 转换为字符串
std::string str(content.begin(), content.end());

// 访问数据
const uint8_t *data = content.data();
size_t size = content.size();
```

### 3. FileMappingContext - 文件映射上下文类

**功能**: 内存映射文件管理

**继承**: `base::IContext`

**成员变量**:
```cpp
std::string filename{};              // 文件名
HANDLE FileHandle = INVALID_HANDLE_VALUE;  // 文件句柄
HANDLE MappingHandle = nullptr;             // 映射句柄
void *MappedFileAddress = nullptr;         // 映射地址
size_t MappedFileSize = 0;                // 映射文件大小
```

**方法**:

**构造函数**:
```cpp
explicit FileMappingContext(const std::string &filename)
```

**参数**:
- `filename`: 文件路径

**行为**: 自动调用 `Load()` 加载文件

**析构函数**:
```cpp
~FileMappingContext() override
```

**行为**: 自动调用 `Unload()` 释放资源

**IsLoaded()**:
```cpp
bool IsLoaded() override
```

**返回值**: 始终返回 true

**Load()**:
```cpp
int32_t Load() override
```

**功能**: 加载文件并创建内存映射

**实现逻辑**:
```cpp
1. 获取文件大小
2. 调用 CreateFileA() 打开文件
   - 失败 → 抛出异常

3. 调用 CreateFileMappingA() 创建文件映射对象
   - 失败 → 抛出异常

4. 调用 MapViewOfFile() 映射文件到内存
   - 失败 → 抛出异常

5. 保存映射地址和大小
```

**参数**:
- 文件访问模式: `GENERIC_READ`
- 共享模式: `FILE_SHARE_READ`
- 映射保护: `PAGE_READONLY`
- 视图访问: `FILE_MAP_READ`

**返回值**:
- 0: 成功
- 异常: 失败

**Unload()**:
```cpp
int32_t Unload() override
```

**功能**: 释放内存映射资源

**实现逻辑**:
```cpp
1. 调用 UnmapViewOfFile() 解除文件映射
   - 失败 → 收集异常

2. 关闭映射句柄

3. 关闭文件句柄

4. 如果有异常，重新抛出第一个异常
```

**返回值**:
- 0: 成功
- 异常: 失败

**使用示例**:
```cpp
// 读取大文件
FileMappingContext mapping("large_file.dat");

// 访问映射内存
const void *data = mapping.MappedFileAddress;
size_t size = mapping.MappedFileSize;

// 使用数据
const uint8_t *bytes = static_cast<const uint8_t*>(data);
for (size_t i = 0; i < size; i++) {
    // 处理字节
}

// 自动释放（析构时）
```

## 依赖关系
- `sys.hpp`: 系统函数
- `base.hpp`: 基础定义

## 使用场景

### 1. 检查文件大小

```cpp
// 检查文件大小
int64_t size = GetFileSize("data.bin");

if (size > 1024 * 1024) {
    // 文件大于 1MB
    std::cout << "File size: " << size << " bytes" << std::endl;
}
```

### 2. 读取配置文件

```cpp
// 读取配置文件
Stream content = ReadFile("config.json");

// 转换为字符串
std::string json(content.begin(), content.end());

// 解析 JSON
// ParseJSON(json);
```

### 3. 读取二进制文件

```cpp
// 读取二进制文件
Stream data = ReadFile("image.png");

// 访问二进制数据
const uint8_t *ptr = data.data();
size_t len = data.size();

// 处理数据
ProcessImage(ptr, len);
```

### 4. 内存映射大文件

```cpp
// 内存映射大文件
FileMappingContext mapping("large_dataset.dat");

// 获取映射地址
const uint8_t *data = static_cast<const uint8_t*>(mapping.MappedFileAddress);
size_t size = mapping.MappedFileSize;

// 直接访问数据（无需加载到内存）
for (size_t i = 0; i < size; i++) {
    // 处理数据
    ProcessByte(data[i]);
}

// 自动释放
```

### 5. 随机访问文件

```cpp
// 内存映射后随机访问
FileMappingContext mapping("database.db");

// 访问特定位置
size_t offset = 1024;
const uint8_t *ptr = static_cast<const uint8_t*>(mapping.MappedFileAddress);
const uint8_t *data = ptr + offset;

// 读取数据
ReadRecord(data);
```

## 性能对比

| 操作 | ReadFile | FileMappingContext |
|------|----------|-------------------|
| 小文件 (< 1MB) | 快 | 慢 |
| 大文件 (> 100MB) | 慢 | 快 |
| 随机访问 | 慢 | 快 |
| 顺序读取 | 快 | 快 |
| 内存占用 | 高 | 低 |

**结论**:
- 小文件: 使用 `ReadFile()`
- 大文件: 使用 `FileMappingContext`
- 随机访问: 使用 `FileMappingContext`

## 关键设计决策

### 1. 多种文件访问方式

**ReadFile()**:
- 简单易用
- 适合小文件
- 自动管理内存

**FileMappingContext**:
- 高性能
- 适合大文件
- 支持随机访问

### 2. RAII 模式

**优点**:
- 自动释放资源
- 避免内存泄漏
- 异常安全

**示例**:
```cpp
{
    FileMappingContext mapping("file.dat");
    // 使用映射
} // 自动释放
```

### 3. 64 位文件支持

**函数**:
- `_fseeki64()` / `_ftelli64()`: 64 位文件定位
- `CreateFileMappingA()`: 支持大文件
- `MapViewOfFile()`: 支持大文件映射

**最大文件大小**: 2^64 - 1 字节

## 错误处理

### 1. 文件不存在

```cpp
try {
    Stream content = ReadFile("nonexistent.txt");
} catch (const std::system_error &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    std::cerr << "Code: " << e.code() << std::endl;
}
```

### 2. 权限不足

```cpp
try {
    FileMappingContext mapping("protected.dat");
} catch (const std::system_error &e) {
    if (e.code().value() == ERROR_ACCESS_DENIED) {
        std::cerr << "Access denied" << std::endl;
    }
}
```

### 3. 路径问题

```cpp
try {
    int64_t size = GetFileSize("C:\\中文路径\\文件.txt");
} catch (const std::system_error &e) {
    // stat() 不支持中文路径
    // 会使用 fopen_s() 作为备选
    std::cerr << "Error: " << e.what() << std::endl;
}
```

## 注意事项

1. **文件路径**:
   - `stat()` 只支持绝对路径
   - `stat()` 只支持纯英文路径
   - 中文路径会自动使用备选方案

2. **文件大小**:
   - 使用 64 位函数支持大文件
   - 最大文件大小: 2^64 - 1 字节

3. **内存映射**:
   - 映射地址在进程生命周期内有效
   - 不要手动释放映射地址
   - 使用 RAII 自动管理

4. **文件访问**:
   - 默认只读模式
   - 需要写操作需要修改代码
   - 确保文件未被其他进程锁定

5. **线程安全**:
   - `ReadFile()` 和 `GetFileSize()` 是线程安全
   - `FileMappingContext` 需要外部同步
   - 多个线程访问同一映射需要加锁

## 最佳实践

1. **选择合适的函数**:
   ```cpp
   // 小文件
   Stream content = ReadFile("config.json");

   // 大文件
   FileMappingContext mapping("large_file.dat");
   ```

2. **错误处理**:
   ```cpp
   try {
       Stream content = ReadFile("file.txt");
   } catch (const std::system_error &e) {
       LOG_E("Failed to read file: %s", e.what());
       return false;
   }
   ```

3. **资源管理**:
   ```cpp
   // 使用 RAII
   {
       FileMappingContext mapping("file.dat");
       // 使用映射
   } // 自动释放
   ```

4. **性能优化**:
   ```cpp
   // 缓存文件内容
   static Stream cachedConfig;
   if (cachedConfig.empty()) {
       cachedConfig = ReadFile("config.json");
   }
   ```

5. **路径处理**:
   ```cpp
   // 使用绝对路径
   std::string absPath = GetAbsolutePath("file.txt");
   Stream content = ReadFile(absPath);
   ```

## 扩展性

### 1. 添加写操作

```cpp
inline void WriteFile(const std::string &filename, const Stream &content) {
    FILE *fp{};
    const auto r0 = fopen_s(&fp, filename.data(), "wb");
    if (r0 != 0 || fp == nullptr) {
        throw std::system_error(r0, std::generic_category(), 
                              "Failed to open file");
    }
    fwrite(content.data(), 1, content.size(), fp);
    fclose(fp);
}
```

### 2. 添加追加模式

```cpp
inline void AppendToFile(const std::string &filename, const Stream &content) {
    FILE *fp{};
    const auto r0 = fopen_s(&fp, filename.data(), "ab");
    if (r0 != 0 || fp == nullptr) {
        throw std::system_error(r0, std::generic_category(), 
                              "Failed to open file");
    }
    fwrite(content.data(), 1, content.size(), fp);
    fclose(fp);
}
```

### 3. 添加写映射

```cpp
class WritableFileMappingContext : public FileMappingContext {
public:
    int32_t Load() override {
        // 创建可写映射
        FileHandle = CreateFileA(
            filename.data(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        // ... 其他步骤
    }
};
```

## 实际应用（IFW 项目）

### 1. 读取配置文件

```cpp
// 读取配置
Stream content = ReadFile("ifw.cfg");

// 解析配置
config::config->Load(content);
```

### 2. 加载规则库

```cpp
// 加载规则库
FileMappingContext mapping("rules.dat");

// 快速访问规则
const Rule *rules = static_cast<const Rule*>(mapping.MappedFileAddress);
size_t count = mapping.MappedFileSize / sizeof(Rule);

// 查找规则
for (size_t i = 0; i < count; i++) {
    if (rules[i].Matches(packet)) {
        return &rules[i];
    }
}
```

### 3. 日志文件管理

```cpp
// 检查日志大小
int64_t size = GetFileSize("ifw.log");

// 如果太大，轮转日志
if (size > 10 * 1024 * 1024) { // 10MB
    RotateLog();
}
```

### 4. 更新检测

```cpp
// 获取当前文件大小
int64_t currentSize = GetFileSize("version.dat");

// 下载新版本
Stream newVersion = DownloadLatestVersion();

// 比较大小
if (newVersion.size() > currentSize) {
    // 更新可用
    ShowUpdateNotification();
}
```

## 调试技巧

### 1. 验证文件读取

```cpp
// 读取文件
Stream content = ReadFile("file.txt");

// 验证内容
if (content.empty()) {
    LOG_E("File is empty");
} else {
    LOG_I("Read %zu bytes", content.size());
}
```

### 2. 检查映射地址

```cpp
// 创建映射
FileMappingContext mapping("file.dat");

// 检查映射地址
if (mapping.MappedFileAddress == nullptr) {
    LOG_E("Mapping failed");
} else {
    LOG_I("Mapped at 0x%p, size: %zu", 
          mapping.MappedFileAddress, 
          mapping.MappedFileSize);
}
```

### 3. 调试文件大小

```cpp
// 获取文件大小
int64_t size = GetFileSize("file.txt");

// 输出信息
LOG_I("File size: %lld bytes", size);
LOG_I("File size: %.2f MB", size / 1024.0 / 1024.0);
```

## 总结

### 推荐使用顺序

1. **小文件 (< 1MB)**: `ReadFile()`
2. **大文件 (> 1MB)**: `FileMappingContext`
3. **随机访问**: `FileMappingContext`
4. **顺序读取**: `ReadFile()` 或 `FileMappingContext`

### 关键要点

- 根据文件大小选择合适的方法
- 使用 RAII 自动管理资源
- 处理所有可能的错误
- 注意路径限制（中文路径）
- 64 位文件支持大文件
- 内存映射支持高性能访问