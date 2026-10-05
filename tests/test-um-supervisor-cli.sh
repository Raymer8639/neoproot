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
image="$temporary_directory/rootfs.ext4"
dd if=/dev/zero of="$image" bs=1 count=2048 2>/dev/null
printf '\123\357' | dd of="$image" bs=1 seek=1080 conv=notrunc 2>/dev/null

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
expect_failure "readonly hostfs directory" \
	--rootfs="$rootfs" --hostfs --readonly -- /bin/true
expect_failure "hostfs flag with ext4 image" \
	--rootfs="$image" --hostfs -- /bin/true
expect_failure "bind with ext4 image" \
	--rootfs="$image" --bind="$rootfs:/mnt" -- /bin/true
expect_failure "invalid ext4 image" \
	--rootfs="$temporary_directory/invalid-image" -- /bin/true

echo "UM supervisor CLI validation tests passed"
