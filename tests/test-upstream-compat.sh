#!/bin/sh
# Integration: run ONLY on an untraced host. No installed binary is modified.
set -eu
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-$script_directory/../src/neoproot}
if [ "$(awk '$1 == "TracerPid:" { print $2 }' /proc/self/status)" != 0 ]; then
    echo "SKIP: run this integration script on an untraced host" >&2
    exit 125
fi
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-upstream-integration.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
fixture="$test_directory/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
mkdir -p "$fixture"
"${CC:-cc}" -D_GNU_SOURCE -O2 -Wall -Wextra "$script_directory/test-upstream-compat.c" -o "$test_directory/probe"
inherited=$("$test_directory/probe" native-privilege)
mapping=$("$test_directory/probe" native-mapping)
ln -s file "$fixture/relative-link"
"$test_directory/probe" permissions "$fixture/relative-link"
for traced_mode in filter all; do
    if [ "$traced_mode" = all ]; then export PROOT_NO_SECCOMP=1; else unset PROOT_NO_SECCOMP; fi
    "$PROOT" -r / -b "$fixture:/case" -w /case "$test_directory/probe" privilege "$inherited"
    "$PROOT" -r / -b "$fixture:/case" -w /case "$test_directory/probe" paths
    "$PROOT" -r / -b "$fixture:/case" -w /case "$test_directory/probe" sockets
    "$PROOT" -r / "$test_directory/probe" mapping "$mapping"
done
