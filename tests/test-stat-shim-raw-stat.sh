#!/bin/sh
# --stat-shim must still translate raw, non-wrapper stat syscalls.
#
# Regression for the gh failure: the shim removes the stat family from the
# seccomp filter, and before PR #58 an untagged raw newfstatat/statx (Go's
# runtime, or syscall(2) with no interposer loaded) was allowed straight to
# the host kernel.  Guest paths were then resolved in the host namespace and
# silently returned wrong results, which made `gh` report "unable to find git
# executable in PATH".  The fix routes untagged raw stat syscalls through the
# tracer's USER_NOTIF channel.
#
# The probe issues syscall(SYS_newfstatat) directly.  --stat-shim is pointed
# at a stub library that interposes nothing, so the seccomp fast path is
# removed exactly as in a real deployment while every stat call in the probe
# stays the untagged raw path under test.  Both probe paths exist only inside
# the guest namespace, so an untranslated call returns ENOENT.
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

mkdir -p "$ROOT/rawstat-dir"
printf 'relx' > "$ROOT/rawstat-dir/inside"
printf 'bound-data' > "$BOUND/inside"

# A preloadable library with no interposers: satisfies LD_PRELOAD injection
# without turning the probe's raw syscalls into the tagged fast path.
printf '%s\n' 'void neoproot_raw_stat_stub(void) {}' > "$ROOT/stub.c"
"$CC" -O2 -fPIC -shared -o "$ROOT/empty.so" "$ROOT/stub.c"

if "$CC" -static -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-stat-shim-raw-stat.c" 2>/dev/null; then
	BINDS=""
else
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-stat-shim-raw-stat.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

set +e
PROOT_UNSET_DONE=1 "$PROOT" --seccomp-notify \
	--stat-shim=/empty.so \
	-r "$ROOT" -w / $BINDS -b "$BOUND/inside:/rawstat-bound" /probe
status=$?
set -e

if [ "$status" -ne 0 ]; then
	printf '%s\n' "raw stat syscall regression failed (probe exit $status)"
	exit "$status"
fi

printf '%s\n' 'stat-shim raw stat syscall regression passed'
