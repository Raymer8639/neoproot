#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor="$script_directory/../src/neoproot-um"

if [ ! -e "$um_supervisor" ]; then
    echo "skip: $um_supervisor is not available" >&2
    exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-bind.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
rootfs="$temporary_directory/rootfs"
mkdir "$rootfs"

expect_failure() {
    name=$1
    shift
    if "$um_supervisor" "$@" >/dev/null 2>&1; then
        echo "FAIL: $name unexpectedly succeeded" >&2
        exit 1
    fi
}

expect_failure "missing bind separator" "$um_supervisor" --rootfs="$rootfs" --hostfs --bind=/tmp -- /bin/true
expect_failure "relative guest target" "$um_supervisor" --rootfs="$rootfs" --hostfs --bind=/tmp:relative -- /bin/true
expect_failure "controlled proc target" "$um_supervisor" --rootfs="$rootfs" --hostfs --bind=/tmp:/proc/x -- /bin/true
expect_failure "unknown bind option" "$um_supervisor" --rootfs="$rootfs" --hostfs --bind=/tmp:/mnt:x -- /bin/true
expect_failure "duplicate bind target" "$um_supervisor" --rootfs="$rootfs" --hostfs \
    --bind=/tmp:/mnt --bind=/tmp:/mnt -- /bin/true
expect_failure "rootfs escape source" "$um_supervisor" --rootfs="$rootfs" --hostfs --bind=/etc:/mnt -- /bin/true

echo "UM supervisor bind CLI validation tests passed"
