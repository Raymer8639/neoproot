#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT=$(mktemp -d)
PRIVATE=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
	rm -rf "$ROOT" "$PRIVATE"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/data/nested" "$PRIVATE"
printf 'orig\n' > "$ROOT/data/nested/marker"
printf 'bind\n' > "$PRIVATE/marker"

PROBE_BIND=""
if ! "$CC" -static -O2 -o "$ROOT/probe" \
	"$SCRIPT_DIR/test-dirfd-fast-path.c" 2>/dev/null; then
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-dirfd-fast-path.c"
	if [ -n "${PREFIX:-}" ]; then
		PROBE_BIND="-b $PREFIX:$PREFIX -b /system -b /apex"
	fi
fi

if ! output=$(PROOT_UNSET_DONE=1 NEOPROOT_TEST_DIRFD_FAST_PATH=1 \
	"$PROOT" -r "$ROOT" $PROBE_BIND --link2symlink \
	-b "$PRIVATE:/data/nested" /probe 2>&1); then
	printf '%s\n' "$output"
	exit 1
fi
printf '%s\n' "$output"
printf '%s\n' "$output" | grep -qx 'dirfd fast-path probe passed'
printf '%s\n' "$output" | grep -q 'neoproot dirfd-fast: hit'

printf '%s\n' 'dirfd fast-path regression passed'
