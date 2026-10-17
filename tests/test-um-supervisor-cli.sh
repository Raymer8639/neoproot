#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor="$script_directory/../src/neoproot-um"

if [ ! -e "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
# The option-validation messages are only produced by a run that gets past the
# tracer check, and a traced process is refused before any option is parsed.
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: UML supervisor CLI test must run untraced" >&2
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
expect_failure "--net with an unbindable umnet path" \
	env NEOPROOT_UM_NET="$temporary_directory/missing-umnet" \
	"$um_supervisor" --rootfs="$rootfs" --hostfs --net -- /bin/true
expect_failure "duplicate --net" \
	--rootfs="$rootfs" --hostfs --net --net -- /bin/true
expect_failure "unknown argument after --net" \
	--rootfs="$rootfs" --hostfs --net --unknown-option -- /bin/true

# --net-ipv6 is a mode of --net: the supervisor must refuse it on its own
# rather than start a guest that was promised a stack it will not get.
expect_failure "--net-ipv6 without --net" \
	--rootfs="$rootfs" --hostfs --net-ipv6 -- /bin/true
expect_failure "--net-ipv6-addr without --net" \
	--rootfs="$rootfs" --hostfs --net-ipv6-addr=fd00::2/64 -- /bin/true
expect_failure "--net-ipv6-gw without --net" \
	--rootfs="$rootfs" --hostfs --net-ipv6-gw=fe80::1 -- /bin/true
expect_failure "--net-ipv6-dns without --net" \
	--rootfs="$rootfs" --hostfs --net-ipv6-dns=none -- /bin/true
expect_failure "duplicate --net-ipv6" \
	--rootfs="$rootfs" --hostfs --net --net-ipv6 --net-ipv6 -- /bin/true
expect_failure "empty --net-ipv6-addr" \
	--rootfs="$rootfs" --hostfs --net --net-ipv6-addr= -- /bin/true
expect_failure "--net-ipv6-addr with a space" \
	--rootfs="$rootfs" --hostfs --net "--net-ipv6-addr=fd00::2/64 " \
	-- /bin/true
expect_failure "unknown argument after --net-ipv6" \
	--rootfs="$rootfs" --hostfs --net --net-ipv6 --unknown-option -- /bin/true

# The message has to name the option, not the parser that happened to see it.
if ! output=$("$um_supervisor" --rootfs="$rootfs" --hostfs --net-ipv6 -- \
	/bin/true 2>&1); then
	case "$output" in
	*"--net-ipv6 options require --net"*) ;;
	*)
		echo "FAIL: --net-ipv6 without --net said: $output" >&2
		exit 1
		;;
	esac
else
	echo "FAIL: --net-ipv6 without --net succeeded" >&2
	exit 1
fi

echo "UM supervisor CLI validation tests passed"
