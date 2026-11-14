#!/bin/sh
# Direct handler tests; safe to run under an existing tracer.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d /tmp/neoproot-fake-id.XXXXXX)
case "$work" in /tmp/neoproot-fake-id.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
# Keep compiler scratch files isolated from other concurrently running suites.
export TMPDIR="$work"
set --
for source in "$root"/src/extension/fake_id0/*.c; do
    case "$source" in */fake_id0.c) ;; *) set -- "$@" "$source" ;; esac
done
# TEST_CFLAGS may supply compiler instrumentation flags.
${CC:-clang} ${TEST_CFLAGS:-} -std=c2x -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DUSERLAND \
    -ffunction-sections -fdata-sections -I"$root/src" \
    "$root/tests/test-upstream-fake-id.c" "$@" -ltalloc -Wl,--gc-sections -o "$work/handlers"
mkdir "$work/root"
"$work/handlers" "$work/root"
mkdir -p "$work/include/linux"
printf '%s\n' '#define ASHMEM_NAME_LEN 256' '#define ASHMEM_SET_NAME 1' '#define ASHMEM_SET_SIZE 2' > "$work/include/linux/ashmem.h"
${CC:-clang} ${TEST_CFLAGS:-} -std=c2x -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
    -ffunction-sections -fdata-sections -I"$work/include" -I"$root/src" \
    "$root/tests/test-upstream-fake-id-shm.c" -ltalloc -Wl,--gc-sections -o "$work/shm"
"$work/shm"
