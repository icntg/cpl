# Static musl-gcc build environment (Alpine).
#
# The musl-tools package of Debian (WSL2) ships a C toolchain only, without a C++ standard
# library. The g++ of Alpine links against musl and libstdc++ by default, which makes it the
# cleanest way to build C++ statically against musl.
#
# Build the image (once; reuse afterwards):
#   docker build -t cpl-musl -f test/musl.Dockerfile .
#
# Usage (mount the sources, build and test incrementally):
#   docker run --rm -v /mnt/c/home/src/icntg/cpl:/work -w /work cpl-musl \
#       sh -c 'cmake -S . -B build_musl -G Ninja -DCMAKE_BUILD_TYPE=Release \
#               -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
#               -DCMAKE_EXE_LINKER_FLAGS=-static && \
#               cmake --build build_musl && build_musl/cpl_test'

FROM alpine:latest

# Alpine package mirror that is fast from this network
RUN sed -i 's#dl-cdn.alpinelinux.org#mirrors.aliyun.com#g' /etc/apk/repositories

# Static C++ toolchain: g++ (links musl + libstdc++) + cmake + ninja
RUN apk add --no-cache g++ musl-dev cmake ninja

WORKDIR /work
