#!/bin/sh
# run-musl-tests.sh - sync cpl to the Linux test VM, then build and run cpl_test in an Alpine container.
#
# Usage:
#   IFW_VM_PASS=... sh test/run-musl-tests.sh                  run the whole suite (through CMake)
#   IFW_VM_PASS=... sh test/run-musl-tests.sh -ts=cpl::cert     run only the matching test cases (args go to doctest)
#   IFW_VM_PASS=... sh test/run-musl-tests.sh --standalone test/test_cert.cpp [-- doctest args]
#       compile and run the listed test files directly, without CMake. Use this for new tests that are
#       not registered in CMakeLists.txt yet.
#
# Environment variables (all optional except IFW_VM_PASS):
#   PLINK           path of plink.exe                 default /c/home/app/putty/plink.exe
#   IFW_VM          user@host of the test VM          default admin@10.0.0.35
#   IFW_VM_PASS     password of the test VM           no default
#   IFW_VM_HOSTKEY  host key fingerprint of the VM    default is the fingerprint of this test VM
#
# Behaviour:
#   - The cpl directory (without build*, .git and .claude) is synced to /home/dev/igocat/client/cpl on the VM.
#   - The build and the tests run in a throwaway container, so no build output is left on the VM.
#   - The container image is pulled only when it is missing, and it is kept for the next run.
set -eu

PLINK="${PLINK:-/c/home/app/putty/plink.exe}"
IFW_VM="${IFW_VM:-admin@10.0.0.35}"
IFW_VM_HOSTKEY="${IFW_VM_HOSTKEY:-SHA256:2YgQhixbck9WmeUan4o5hvO2zXVo7pVGYItb6f3IQIo}"
: "${IFW_VM_PASS:?please provide IFW_VM_PASS (the password of the test VM)}"
IMAGE="docker.m.daocloud.io/library/alpine:3.24"
REMOTE_DIR="/home/dev/igocat/client/cpl"

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
[ -x "$PLINK" ] || { echo "[X] plink not found: $PLINK" >&2; exit 2; }
SSH="$PLINK -batch -hostkey $IFW_VM_HOSTKEY -pw $IFW_VM_PASS $IFW_VM"

STANDALONE=""
if [ "${1:-}" = "--standalone" ]; then
    shift
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        STANDALONE="$STANDALONE $1"
        shift
    done
    [ "${1:-}" = "--" ] && shift
    [ -n "$STANDALONE" ] || { echo "[X] --standalone needs at least one test file" >&2; exit 2; }
    for f in $STANDALONE; do
        [ -f "$f" ] || { echo "[X] test file not found: $f" >&2; exit 2; }
    done
fi

echo "==> sync cpl to $IFW_VM:$REMOTE_DIR"
tar -cf - --exclude='build*' --exclude='.git' --exclude='__pycache__' --exclude='.claude' . \
    | $SSH "mkdir -p $REMOTE_DIR && tar -C $REMOTE_DIR -xf -"

echo "==> build and run the tests in an Alpine container"
$SSH "IMAGE='$IMAGE' REMOTE_DIR='$REMOTE_DIR' TEST_ARGS='$*' STANDALONE='$STANDALONE' bash -s" <<'REMOTE'
set -eu
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker pull -q "$IMAGE" >/dev/null
fi
docker run --rm -i -e TEST_ARGS="$TEST_ARGS" -e STANDALONE="$STANDALONE" -v "$REMOTE_DIR:/src:ro" "$IMAGE" sh -s <<'INNER'
set -eu
sed -i 's#dl-cdn.alpinelinux.org#mirrors.aliyun.com#g' /etc/apk/repositories
apk add --no-cache g++ musl-dev cmake ninja >/dev/null 2>&1
if [ -n "$STANDALONE" ]; then
    SOURCES=""
    for f in $STANDALONE; do SOURCES="$SOURCES /src/$f"; done
    echo "==> compile directly: $STANDALONE"
    # The first pass shows the diagnostics; the second pass fails the script when the compile fails.
    # shellcheck disable=SC2086
    g++ -std=c++11 -Wall -Wextra -Wno-unused-parameter -I/src -o /tmp/standalone_test \
        /src/test/entry.cpp $SOURCES /src/naion/naion_impl.cpp 2>&1 | grep -E 'error' | head -40 || true
    # shellcheck disable=SC2086
    g++ -std=c++11 -Wall -Wextra -Wno-unused-parameter -I/src -o /tmp/standalone_test \
        /src/test/entry.cpp $SOURCES /src/naion/naion_impl.cpp 2>/dev/null
    echo "==> run"
    # shellcheck disable=SC2086
    /tmp/standalone_test $TEST_ARGS
    exit 0
fi
mkdir -p /work && cp -r /src/. /work/ && cd /work
cmake -S . -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build /tmp/build 2>&1 | tail -25
echo "==> run"
# shellcheck disable=SC2086
/tmp/build/cpl_test $TEST_ARGS
INNER
REMOTE
