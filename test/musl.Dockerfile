# musl-gcc 静态编译环境 (Alpine)。
#
# WSL2 的 Debian musl-tools 只提供 C 工具链，不含 C++ stdlib；Alpine 自带的
# g++ 默认链接 musl + libstdc++，是做 C++ 静态构建最干净的方式。
#
# 构建镜像 (一次即可，后续复用)：
#   docker build -t cpl-musl -f test/musl.Dockerfile .
#
# 用法 (挂载源码，增量构建+测试)：
#   docker run --rm -v /mnt/c/home/src/icntg/cpl:/work -w /work cpl-musl \
#       sh -c 'cmake -S . -B build_musl -G Ninja -DCMAKE_BUILD_TYPE=Release \
#               -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
#               -DCMAKE_EXE_LINKER_FLAGS=-static && \
#               cmake --build build_musl && build_musl/cpl_test'

FROM alpine:latest

# 国内源加速 apk
RUN sed -i 's#dl-cdn.alpinelinux.org#mirrors.aliyun.com#g' /etc/apk/repositories

# 静态 C++ 构建工具链：g++ (链接 musl + libstdc++) + cmake + ninja
RUN apk add --no-cache g++ musl-dev cmake ninja

WORKDIR /work
