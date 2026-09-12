#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT=$(mktemp -d)
EXTERNAL_ROOT=$(mktemp -d)
BACKING=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

SHA1_OBJ='.git/objects/01/23456789abcdef0123456789abcdef01234567'
SHA256_OBJ='.git/objects/ab/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd'
PACK_OBJ='.git/objects/pack/pack-0123456789abcdef0123456789abcdef01234567.pack'
PNPM_OBJ='files/ab/0123456789abcdef0123456789abcdef01234567'

cleanup() {
	rm -rf "$ROOT" "$EXTERNAL_ROOT" "$BACKING"
}
trap cleanup EXIT INT TERM

PROBE_BIND=""
if ! "$CC" -static -O2 -o "$ROOT/probe" \
	"$SCRIPT_DIR/test-link2symlink-git-objects.c" 2>/dev/null; then
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-link2symlink-git-objects.c"
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
	printf '%s\n' "$output" | grep -qx 'link2symlink git-object skip probe passed'

	# Git dests must be real files on the host, not L2S chains.
	test -f "$probe_root/$SHA1_OBJ"
	test ! -L "$probe_root/$SHA1_OBJ"
	test -f "$probe_root/$SHA256_OBJ"
	test ! -L "$probe_root/$SHA256_OBJ"
	test -f "$probe_root/$PACK_OBJ"
	test ! -L "$probe_root/$PACK_OBJ"

	# pnpm-like and ordinary dests still go through L2S.
	test -L "$probe_root/$PNPM_OBJ"
	test -L "$probe_root/work/source"
	test -L "$probe_root/work/fake"
}

run_probe "$ROOT" ''
run_probe "$EXTERNAL_ROOT" "$BACKING"

test -n "$(find "$BACKING" -mindepth 1 -print -quit)"
printf '%s\n' 'link2symlink git-object skip regression passed'
