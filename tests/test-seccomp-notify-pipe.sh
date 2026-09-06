#!/bin/sh
# Step 2: --seccomp-notify USER_NOTIF plumbing for newfstatat.
# Uses default rootfs "/" so guest paths are host paths (dynamic linker lives).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
PROOT=$(CDPATH= cd -- "$(dirname -- "$PROOT")" && pwd)/$(basename -- "$PROOT")
CC=${CC:-cc}

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status; then
	printf '%s\n' 'skip: already traced'
	exit 125
fi

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-seccomp-notify-pipe.XXXXXX")
cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

printf 'hello' > "$ROOT/marker"
"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-seccomp-notify-pipe.c"
chmod 0755 "$ROOT/probe"

set +e
(cd "$ROOT" && PROOT_UNSET_DONE=1 "$PROOT" ./probe expect-real)
status=$?
set -e
if [ "$status" -ne 0 ]; then
	printf '%s\n' 'without --seccomp-notify: expected real fstatat'
	exit "$status"
fi

set +e
(cd "$ROOT" && PROOT_UNSET_DONE=1 "$PROOT" --seccomp-notify ./probe expect-magic >"$ROOT/out" 2>&1)
status=$?
set -e
cat "$ROOT/out"
if [ "$status" -ne 0 ]; then
	printf '%s\n' 'with --seccomp-notify: expected sentinel plumbing fstatat'
	exit "$status"
fi
grep -F 'USER_NOTIF listener ready' "$ROOT/out" >/dev/null
grep -F 'pipe expect-magic ok' "$ROOT/out" >/dev/null

printf '%s\n' 'seccomp-notify pipe regression passed'
