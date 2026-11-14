#!/bin/sh
# Actual socket source, real local sockets and process_vm_*; no neoproot/UML.
set -eu
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-upstream-sendmmsg.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
"${CC:-clang}" -D_GNU_SOURCE -std=c2x -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -I"$script_directory/../src" \
    "$script_directory/test-upstream-sendmmsg.c" "$script_directory/../src/syscall/socket.c" \
    -Wl,--gc-sections -Wl,--wrap=syscall -ltalloc -o "$test_directory/unit"
"$test_directory/unit"
