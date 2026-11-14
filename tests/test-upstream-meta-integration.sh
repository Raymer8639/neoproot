#!/bin/sh
# True tracee integration for a separately built -DUSERLAND candidate.
set -eu
[ "${NEOPROOT_TEST_USERLAND:-0}" = 1 ] || { echo 'SKIP: set NEOPROOT_TEST_USERLAND=1 for a USERLAND build'; exit 125; }
[ "$(awk '$1 == "TracerPid:" { print $2 }' /proc/self/status)" = 0 ] || { echo 'SKIP: untraced host required'; exit 125; }
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-$script_directory/../src/neoproot}
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-meta-integration.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
"${CC:-cc}" -O2 -Wall -Wextra "$script_directory/test-upstream-meta-integration.c" -o "$test_directory/probe"
native_cap=$("$test_directory/probe" native "$test_directory/native-cap")
mkdir "$test_directory/work"
"$PROOT" -0 -r / -b "$test_directory/work:/case" -w /case "$test_directory/probe" tracee "$native_cap"
"$test_directory/probe" check "$test_directory/work"
