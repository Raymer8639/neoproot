#!/bin/sh
# PR_SET_NO_NEW_PRIVS commit timing regression
#
# neoproot answers PR_GET_NO_NEW_PRIVS from the guest's own intent, because the
# real flag is always 1 (neoproot's seccomp filter needs it).  That intent may
# only be recorded once the kernel accepted the SET: a filter the guest
# installed itself can fail PR_SET_NO_NEW_PRIVS with EPERM, and the answer must
# stay whatever it was before (0 for a fresh guest).
#
# Part 1 is pure source: the commit condition is a header inline, so this half
# runs in a container where a nested neoproot is forbidden.
# Part 2 needs an untraced ARM64 host with a working neoproot; it is skipped
# (exit 125) otherwise, like the other integration scripts.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
CC=${CC:-cc}
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-nnp-commit.XXXXXX")

cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

# ---- 1. the commit condition itself ---------------------------------------
TALLOC_CFLAGS=$(pkg-config --cflags talloc 2>/dev/null || true)
# shellcheck disable=SC2086
"$CC" -std=c11 -O2 -Wall -Wextra $TALLOC_CFLAGS -I"$SCRIPT_DIR/../src" \
	-o "$ROOT/commit-policy" \
	"$SCRIPT_DIR/test-no-new-privs-commit-policy.c"
"$ROOT/commit-policy"

# ---- 2. the guest-visible contract ----------------------------------------
case "$(uname -m)" in
aarch64|arm64) ;;
*)
	echo "SKIP: the guest-side probe needs an ARM64 host"
	exit 125
	;;
esac
if [ ! -x "$PROOT" ]; then
	echo "SKIP: neoproot binary not found ($PROOT)"
	exit 125
fi
if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status 2>/dev/null; then
	echo "SKIP: neoproot cannot be run from inside another tracer"
	exit 125
fi
if ! command -v "$CC" >/dev/null 2>&1; then
	echo "SKIP: C compiler unavailable for the guest-side probe"
	exit 125
fi

mkdir -p "$ROOT/rootfs/bin"
if "$CC" -static -std=c11 -O2 -o "$ROOT/rootfs/bin/probe" \
	"$SCRIPT_DIR/test-no-new-privs-commit.c" 2>/dev/null; then
	BINDS=""
else
	"$CC" -std=c11 -O2 -o "$ROOT/rootfs/bin/probe" \
		"$SCRIPT_DIR/test-no-new-privs-commit.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

# seccomp mode: neoproot's filter is what sets the real no_new_privs flag, so
# the guest may install its own filter.  --require-filter makes a host that
# cannot do that a skip instead of a silent pass.  PROOT_UNSET_DONE is left
# alone on purpose: the tracer's own clean re-exec is what prepares the host
# side of the launch on Android.
"$PROOT" -r "$ROOT/rootfs" $BINDS /bin/probe --require-filter

# All-stop mode (PROOT_NO_SECCOMP): neoproot stops every syscall with ptrace,
# so the refused SET reaches the enter and exit handlers directly.  The real
# flag starts at 0 here, so the probe can only skip its filter cases.
PROOT_NO_SECCOMP=1 "$PROOT" -r "$ROOT/rootfs" $BINDS /bin/probe

echo "no_new_privs commit regression passed"
