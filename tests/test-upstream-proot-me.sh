#!/bin/sh
set -eu

# Host-only: compile actual source helpers, never invoke neoproot or UML.
# Run with: env -i PATH=/usr/bin:/bin sh tests/test-upstream-proot-me.sh
# Set SANITIZE=1 to instrument the tested implementations with UBSan.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=$(dirname -- "$SCRIPT_DIR")
CC=${CC:-cc}
TEST_TMP=$(mktemp -d /tmp/neoproot-proot-me-tests.XXXXXX)
cleanup() {
    case "$TEST_TMP" in
        /tmp/neoproot-proot-me-tests.*) rm -rf -- "$TEST_TMP" ;;
        *) exit 1 ;;
    esac
}
trap cleanup EXIT INT TERM

if [ "$(uname -m)" != aarch64 ]; then
    echo 'SKIP: production path helpers require the supported aarch64 host'
    exit 125
fi

# Deliberately leave these as shell words for the compiler's flag list.
TEST_CFLAGS="-std=gnu11 -D_GNU_SOURCE -O1 -g -Wall -Wextra -ffunction-sections -fdata-sections"
# Only compare_paths is used from path.c. Compile this supporting object
# once; the auxv, exec-exit, and proc tests are instrumented below.
"$CC" $TEST_CFLAGS -I"$SOURCE_DIR/src" -c "$SOURCE_DIR/src/path/path.c" \
    -o "$TEST_TMP/path.o"
if [ "${SANITIZE:-0}" = 1 ]; then
    TEST_CFLAGS="$TEST_CFLAGS -fsanitize=undefined -fno-omit-frame-pointer"
    UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1}
    export UBSAN_OPTIONS
fi

"$CC" $TEST_CFLAGS -I"$SOURCE_DIR/src" \
    "$SCRIPT_DIR/test-upstream-proot-me-auxv.c" \
    "$SOURCE_DIR/src/execve/auxv.c" "$SOURCE_DIR/src/path/temp.c" \
    "$TEST_TMP/path.o" -Wl,--gc-sections -ltalloc -lm \
    -o "$TEST_TMP/auxv"
"$TEST_TMP/auxv"

"$CC" $TEST_CFLAGS -I"$SOURCE_DIR/src" \
    "$SCRIPT_DIR/test-upstream-proot-me-proc.c" \
    "$SOURCE_DIR/src/path/proc.c" "$TEST_TMP/path.o" \
    -Wl,--gc-sections -ltalloc -lm -o "$TEST_TMP/proc"
"$TEST_TMP/proc"

"$CC" $TEST_CFLAGS -I"$SOURCE_DIR/src" \
    "$SCRIPT_DIR/test-upstream-proot-me-host.c" \
    "$SOURCE_DIR/src/execve/auxv.c" \
    -Wl,--gc-sections -ltalloc -lm -o "$TEST_TMP/host"
"$TEST_TMP/host"
