#!/bin/sh
# fchmodat2(2) flag-semantics regression for neoproot.
#
# neoproot registers fchmodat2 (ARM64 452, Linux 6.6+) and must read the flags
# argument from the fourth register.  The upstream patch reads SYSARG_3, the
# *mode*, so a mode with the 0x100 bit (0640, 0600, ...) is mistaken for
# AT_SYMLINK_NOFOLLOW and the final symlink component is not resolved.  This
# test needs a kernel that actually implements 452, so it skips elsewhere
# (e.g. Android, whose outer seccomp rejects the syscall).
#
# Exit 125 = kernel lacks fchmodat2.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
PROOT=$(CDPATH= cd -- "$(dirname -- "$PROOT")" && pwd)/$(basename -- "$PROOT")
CC=${CC:-cc}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-fchmodat2.XXXXXX")
cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/fc2-dir"
printf 'target' > "$ROOT/fc2-target"
printf 'inside' > "$ROOT/fc2-dir/inside"
chmod 0644 "$ROOT/fc2-target"
chmod 0644 "$ROOT/fc2-dir/inside"
ln -s /fc2-target "$ROOT/fc2-link"

if "$CC" -static -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-fchmodat2.c" 2>/dev/null; then
	BINDS=""
else
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-fchmodat2.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

set +e
PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe
status=$?
set -e

if [ "$status" -eq 125 ]; then
	printf '%s\n' 'skip: fchmodat2 unsupported on this kernel'
	exit 125
fi
if [ "$status" -ne 0 ]; then
	printf '%s\n' "fchmodat2 semantics regression failed (probe exit $status)"
	exit "$status"
fi

printf '%s\n' 'fchmodat2 flag semantics regression passed'
