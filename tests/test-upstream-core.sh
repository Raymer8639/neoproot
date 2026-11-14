#!/bin/sh
# Pure logic: actual socket source with local memory/path mocks, never ptrace.
set -eu
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-upstream-core.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
"${CC:-clang}" -D_GNU_SOURCE -std=c2x -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
    -I"$script_directory/../src" "$script_directory/test-upstream-core.c" \
    "$script_directory/../src/syscall/socket.c" -Wl,--gc-sections -ltalloc -o "$test_directory/unit"
"$test_directory/unit"
