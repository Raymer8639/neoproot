#!/bin/sh
# --stat-shim must still translate raw, non-libc stat syscalls.
#
# Regression for the gh failure: the shim removes the stat family from the
# seccomp filter, and before PR #58 an untagged raw newfstatat/statx (Go's
# runtime, any program issuing svc directly) was allowed straight to the host
# kernel.  Guest paths were then resolved in the host namespace and silently
# returned wrong results, which made `gh` report "unable to find git
# executable in PATH".  The fix routes untagged raw stat syscalls through the
# tracer's USER_NOTIF channel.
#
# The probe is freestanding (-static -nostdlib) so no libc wrapper or
# LD_PRELOAD can turn the calls into the tagged fast path: every check is the
# untagged raw syscall.  The shim library itself is not needed here; the BPF
# routing is what this test pins down.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
PROOT=$(CDPATH= cd -- "$(dirname -- "$PROOT")" && pwd)/$(basename -- "$PROOT")
CC=${CC:-cc}

case "$(uname -m)" in
aarch64 | arm64) ;;
*)
	printf '%s\n' 'skip: raw stat probe requires ARM64'
	exit 125
	;;
esac

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status 2>/dev/null; then
	printf '%s\n' 'skip: already traced'
	exit 125
fi

if ! command -v "$CC" >/dev/null 2>&1; then
	printf '%s\n' 'skip: C compiler unavailable'
	exit 125
fi

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-shim-raw.XXXXXX")
BOUND=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-shim-raw-bind.XXXXXX")
cleanup() {
	rm -rf "$ROOT" "$BOUND"
}
trap cleanup EXIT INT TERM

printf 'thirteenbytes' > "$BOUND/inside" # 13 bytes
printf 'relx' > "$ROOT/rel-marker"                    # 4 bytes

if ! "$CC" -nostdlib -static -fno-stack-protector \
	-Wl,-e,_start -Wl,--build-id=none \
	-o "$ROOT/probe" "$SCRIPT_DIR/test-stat-shim-raw-stat.c"; then
	printf '%s\n' 'skip: freestanding probe build failed'
	exit 125
fi

# Guest rootfs $ROOT, guest cwd "/", and a bind whose guest path does not exist
# on the host.  Without the fix the raw syscalls are resolved by the host kernel
# and both checks fail.
set +e
(
	cd /
	PROOT_UNSET_DONE=1 "$PROOT" --seccomp-notify \
		--stat-shim=/nonexistent/libstatfast.so \
		-r "$ROOT" -w / -b "$BOUND/inside:/bound/inside" /probe
)
status=$?
set -e

if [ "$status" -ne 0 ]; then
	printf '%s\n' "raw stat syscall regression failed (probe exit $status)"
	exit "$status"
fi

printf '%s\n' 'stat-shim raw stat syscall regression passed'
