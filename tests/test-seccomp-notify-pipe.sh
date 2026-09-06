#!/bin/sh
# Step 3: --seccomp-notify emulates newfstatat (translate + fake_id0 + L2S nlink).
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
mkdir -p "$ROOT/subdir" "$ROOT/subdir2"
printf 'abcd' > "$ROOT/subdir/inside"
printf 'plain' > "$ROOT/subdir/plain"
printf 'ninebytes' > "$ROOT/subdir2/inside"
ln -s marker "$ROOT/link-to-marker"
printf 'xx' > "$ROOT/l2s-a"

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
(cd "$ROOT" && PROOT_UNSET_DONE=1 NEOPROOT_TEST_HOST_DIRFD=1 \
	"$PROOT" --seccomp-notify ./probe expect-translated >"$ROOT/out" 2>&1)
status=$?
set -e
cat "$ROOT/out"
if [ "$status" -ne 0 ]; then
	printf '%s\n' 'with --seccomp-notify: expected translated fstatat'
	exit "$status"
fi
grep -F 'USER_NOTIF listener ready' "$ROOT/out" >/dev/null
grep -F 'pipe expect-translated ok' "$ROOT/out" >/dev/null
grep -F 'neoproot host-dirfd: hit' "$ROOT/out" >/dev/null

PRIVATE=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-seccomp-notify-bind.XXXXXX")
printf 'bound-content' > "$PRIVATE/inside"
set +e
(cd "$ROOT" && PROOT_UNSET_DONE=1 NEOPROOT_TEST_HOST_DIRFD=1 \
	"$PROOT" --seccomp-notify -b "$PRIVATE/inside:$ROOT/subdir/inside" \
	./probe expect-bind >"$ROOT/out-bind" 2>&1)
status=$?
set -e
cat "$ROOT/out-bind"
rm -rf "$PRIVATE"
if [ "$status" -ne 0 ]; then
	printf '%s\n' 'with --seccomp-notify bind overlay: expected bound size'
	exit "$status"
fi
grep -F 'pipe expect-bind ok' "$ROOT/out-bind" >/dev/null
grep -F 'neoproot host-dirfd: miss' "$ROOT/out-bind" >/dev/null
grep -F 'neoproot host-dirfd: hit' "$ROOT/out-bind" >/dev/null

set +e
(cd "$ROOT" && PROOT_UNSET_DONE=1 "$PROOT" --seccomp-notify --link2symlink ./probe expect-l2s >"$ROOT/out-l2s" 2>&1)
status=$?
set -e
cat "$ROOT/out-l2s"
if [ "$status" -ne 0 ]; then
	printf '%s\n' 'with --seccomp-notify --link2symlink: expected nlink=2'
	exit "$status"
fi
grep -F 'pipe expect-l2s ok' "$ROOT/out-l2s" >/dev/null

printf '%s\n' 'seccomp-notify pipe regression passed'
