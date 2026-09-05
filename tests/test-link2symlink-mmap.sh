#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT=$(mktemp -d)
EXTERNAL_ROOT=$(mktemp -d)
BACKING=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
	rm -rf "$ROOT" "$EXTERNAL_ROOT" "$BACKING"
}
trap cleanup EXIT INT TERM

PROBE_BIND=""
if ! "$CC" -static -O2 -o "$ROOT/probe" \
	"$SCRIPT_DIR/test-link2symlink-mmap.c" 2>/dev/null; then
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-link2symlink-mmap.c"
	if [ -n "${PREFIX:-}" ]; then
		PROBE_BIND="-b $PREFIX:$PREFIX -b /system -b /apex"
	fi
fi

cp "$ROOT/probe" "$EXTERNAL_ROOT/probe"

run_probe() {
	probe_root=$1
	l2s_dir=$2

	if ! output=$(PROOT_L2S_DIR="$l2s_dir" PROOT_UNSET_DONE=1 \
		"$PROOT" -r "$probe_root" $PROBE_BIND --link2symlink /probe 2>&1); then
		printf '%s\n' "$output"
		exit 1
	fi
	printf '%s\n' "$output"
	printf '%s\n' "$output" | grep -qx 'link2symlink mmap follow-at-open probe passed'

	# Follow-at-open must not copy-materialize the visible names: Git
	# objects stay as L2S chains while mmap sees the backing file.
	test -L "$probe_root/objects/d9/source"
	test -L "$probe_root/objects/d9/8dbb9d39fd0ad9c95597fd043cb76f2958e313"
}

run_probe "$ROOT" ''
run_probe "$EXTERNAL_ROOT" "$BACKING"

test -n "$(find "$BACKING" -mindepth 1 -print -quit)"
printf '%s\n' 'link2symlink mmap follow-at-open regression passed'
