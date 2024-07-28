cmake_minimum_required(VERSION 3.24)
project(cpl)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 90)

# 设置源文件使用utf8，输出文件使用gbk。使用vs2013后，不支持这两个参数。故所有源文件编码均改为gbk。
# 新版本的vs可使用utf-8源码。
#add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
#add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/execution-charset:gbk>")

# 遍历所有源码文件
#file(GLOB_RECURSE CCL "test/*.c" "test/*.h" "utility/*.c" "utility/*.h" "vendor/*.c" "vendor/*.h")
file(GLOB_RECURSE CPL "*.cpp" "*.hpp")
file(GLOB_RECURSE CPL_EXCLUDE "cmake*/*.cpp" "cmake*/*.hpp")
list(REMOVE_ITEM CPL ${CPL_EXCLUDE})

set(CMAKE_VERBOSE_MAKEFILE on)

add_executable(cpl_test ${CPL})
