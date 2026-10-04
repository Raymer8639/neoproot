#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor="$script_directory/../src/neoproot-um"

if [ ! -e "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-cli.XXXXXX")
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

expect_failure "no arguments"
expect_failure "missing --" \
	--rootfs="$rootfs" --hostfs /bin/true
expect_failure "relative rootfs" \
	--rootfs=relative-rootfs --hostfs -- /bin/true
expect_failure "relative cwd" \
	--rootfs="$rootfs" --hostfs --cwd=relative-cwd -- /bin/true
expect_failure "timeout=nan" \
	--rootfs="$rootfs" --hostfs --timeout=nan -- /bin/true
expect_failure "unknown argument" \
	--rootfs="$rootfs" --hostfs --unknown-option -- /bin/true

echo "UM supervisor CLI validation tests passed"
