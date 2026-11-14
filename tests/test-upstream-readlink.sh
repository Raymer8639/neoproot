#!/bin/sh
# Actual staging/copy helpers with local memory and register boundaries.
set -eu
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-readlink.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
"${CC:-clang}" -D_GNU_SOURCE -std=c2x -O2 -Wall -Wextra -I"$script_directory/../src" "$script_directory/test-upstream-readlink.c" -ltalloc -o "$test_directory/unit"
"$test_directory/unit"
