#!/bin/sh
# Compile production metadata and rename hooks with local tracee stubs.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d /tmp/neoproot-meta-tree.XXXXXX)
case "$work" in /tmp/neoproot-meta-tree.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
# TEST_CFLAGS may supply compiler instrumentation flags.
${CC:-clang} ${TEST_CFLAGS:-} -std=c2x -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DUSERLAND \
    -ffunction-sections -fdata-sections -I"$root/src" \
    "$root/tests/test-upstream-meta-tree.c" -ltalloc -Wl,--gc-sections -o "$work/meta-tree"
mkdir "$work/root"
"$work/meta-tree" "$work/root"
