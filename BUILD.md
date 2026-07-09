# cpl 构建与测试

cpl 是 header-only C++17 公共库 + 自研 naion 密码子库（STB 单头 C）。本仓库的
`cpl_test` 可执行文件用 [doctest](https://github.com/doctest/doctest) 跑全部单元测试。

## 依赖

- 平台无关核心：无外部依赖（naion 自带系统 RNG：Windows CryptGenRandom / Linux
  getrandom / 其它 POSIX /dev/urandom）。
- libsodium（`sodium.hpp` 与 3 个 libsodium 测试）默认**关闭**。需接入时：
  ```bash
  cmake ... -DCPL_HAS_LIBSODIUM=ON
  ```
  并自行保证 `vendor/jedisct1/libsodium/` 头文件与静态库可被找到。
- win32/utility 遗留层已迁移到 Result API（`cpl::sys::utility`）。架构：
  - 单一 `base.hpp`：`utility/base.hpp`、`utility/strings.hpp` 改为顶层 re-export，
    消除历史上两者 include guard 完全相同、`cpl::Error` 重复定义的冲突。
  - `api.hpp`/`sys.hpp` 保持 Win32 原生格式（`INT32`/`string`/`_Out_`、动态加载）；
    其 `IContext::Load/Unload` 返回 `Int32Result`，并在 `cpl::win32` 内提供原生
    `Format/Hex/Unhex/Base64Encode/UINT32ToIPString` shim + `RC()` 解包 Int32Result。
  - `utility/net.hpp` 仅保留 Win32 原生 iphlpapi 辅助（`MakeIpForwardRow`、原生
    `UINT32ToIPString`）；平台无关 IPv4 解析用顶层 `net.hpp`（Result API）。
  - `win32/utility.hpp` 在 `cpl::sys::utility` 下做 Result 封装（process/path/session
    + IsAdministrator/IsLikelyRunningAsService/GetSystemGUID/GetHardwareUUID/
    GetUserSID/RunOnlyOnce 等）。
  - 跨编译器：`__kernel_entry` 在非 MSVC 上 no-op；`Reserved3`/`InheritedFromUniqueProcessId`
    按工具集择一；函数指针存 `void*` 用 `reinterpret_cast`。
  通过 `-DCPL_BUILD_WIN32_TESTS=ON`（仅 Windows）纳入 `test_win32_utility.cpp`，
  默认关闭（Linux/musl 无 win32 代码）。

## 三平台构建

> 约定：每台机器只验证当前平台的结果。Windows 跑 cl/gcc，Linux 跑 musl-gcc。

### 1. MSVC `cl` (v141_xp, x86)

`build_cl.bat` 自动调用 `vcvarsall x86` + VS 自带的 CMake/Ninja，编译器指向
`14.51.36231\bin\Hostx86\x86\cl.exe`（v141_xp 工具集）：

```bat
build_cl.bat
```

等价的手工步骤：

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
set "CMAKE=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
set "CL=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231\bin\Hostx86\x86\cl.exe"
cmake -S . -B build_cl -G Ninja ^
      -DCMAKE_MAKE_PROGRAM="%NINJA%" ^
      -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_C_COMPILER="%CL%" -DCMAKE_CXX_COMPILER="%CL%"
cmake --build build_cl
build_cl\cpl_test.exe
```

### 2. MinGW-w64 `gcc` (Windows)

```bash
CMAKE=/c/home/dev/mingw64/bin/cmake.exe
"$CMAKE" -S . -B build_gcc -G Ninja \
    -DCMAKE_C_COMPILER=C:/home/dev/mingw64/bin/gcc.exe \
    -DCMAKE_CXX_COMPILER=C:/home/dev/mingw64/bin/g++.exe \
    -DCMAKE_MAKE_PROGRAM=C:/home/dev/mingw64/bin/ninja.exe
"$CMAKE" --build build_gcc
PATH="/c/home/dev/mingw64/bin:$PATH" ./build_gcc/cpl_test.exe
```

### 3. musl-gcc (WSL2, 静态链接)

WSL2 的 Debian `musl-tools` 只提供 C 工具链，不含 C++ stdlib。用 Alpine 容器
（自带 musl + libstdc++）做静态构建最干净。镜像 `test/musl.Dockerfile` 已预装
g++/cmake/ninja 并配置国内源，避免每次构建都跑 apk：

```bash
# 1. 构建镜像 (一次即可)
docker build -t cpl-musl -f test/musl.Dockerfile .

# 2. 挂载源码，增量构建+测试
docker run --rm -v /mnt/c/home/src/icntg/cpl:/work -w /work cpl-musl sh -c '
  cmake -S . -B build_musl -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_EXE_LINKER_FLAGS=-static
  cmake --build build_musl
  build_musl/cpl_test
'
```

构建产物 `cpl_test` 是**完全静态**的 musl 二进制（`nm | grep " U "` 为 0，
`ldd` 仅报告 `ld-musl-x86_64.so.1`）。

## 用 CTest 跑

```bash
cmake --build build_xxx
ctest --test-dir build_xxx
```

## Windows 专有测试（test_win32_utility）

仅 Windows 平台，需显式开启，默认关闭：

```bat
:: MSVC cl (v141_xp)
build_cl.bat            :: 默认不含 win32 测试
:: 开启 win32 测试：
cmake -S . -B build_cl -G Ninja ^
    -DCMAKE_MAKE_PROGRAM="...\ninja.exe" ^
    -DCMAKE_CXX_COMPILER="...\14.51.36231\bin\Hostx86\x86\cl.exe" ^
    -DCMAKE_BUILD_TYPE=Release -DCPL_BUILD_WIN32_TESTS=ON
cmake --build build_cl && build_cl\cpl_test.exe
```

```bash
# MinGW gcc
cmake -S . -B build_gcc_w32 -G Ninja \
    -DCMAKE_C_COMPILER=C:/home/dev/mingw64/bin/gcc.exe \
    -DCMAKE_CXX_COMPILER=C:/home/dev/mingw64/bin/g++.exe \
    -DCMAKE_MAKE_PROGRAM=C:/home/dev/mingw64/bin/ninja.exe \
    -DCPL_BUILD_WIN32_TESTS=ON
cmake --build build_gcc_w32
PATH="/c/home/dev/mingw64/bin:$PATH" ./build_gcc_w32/cpl_test.exe
```

## 测试清单

| 文件 | 覆盖 | 平台 |
|---|---|---|
| `test/test_strings.cpp` | Hex/Base64/Length 编解码、Format、Trim、Split/Join、StrInStr、UTF16LE | 全平台 |
| `test/test_crypto.cpp` | SHA256/HMAC-SHA256 已知向量、RC4(RFC 6229)、Crypto_RC4_HMAC256 往返+篡改、UnsafeRandom | 全平台 |
| `test/test_net.cpp` | IPv4 解析、掩码、网关、AddressRange | 全平台 |
| `test/test_naion.cpp` | Seal/Open、Sign/Verify、CSM Client/Server 双向往返、UDP 预算、篡改检测 | 全平台 |
| `test/test_win32_utility.cpp` | 进程/路径/会话、管理员/服务探测、机器标识、SID、RunOnlyOnce、递归建目录 | 仅 Windows |
