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
	"$SCRIPT_DIR/test-link2symlink-stat-guard.c" 2>/dev/null; then
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-link2symlink-stat-guard.c"
	if [ -n "${PREFIX:-}" ]; then
		PROBE_BIND="-b $PREFIX:$PREFIX -b /system -b /apex"
	fi
fi

cp "$ROOT/probe" "$EXTERNAL_ROOT/probe"

run_probe() {
	probe_root=$1
	l2s_dir=$2

	if ! output=$(NEOPROOT_TEST_L2S_STAT_EXIT_COUNTER=1 PROOT_L2S_DIR="$l2s_dir" PROOT_UNSET_DONE=1 \
		"$PROOT" -r "$probe_root" $PROBE_BIND --link2symlink /probe 2>&1); then
		printf '%s\n' "$output"
		exit 1
	fi
	printf '%s\n' "$output"

	# A real host hard link could satisfy the probe's nlink checks by itself.
	# Require link2symlink to have converted both visible members to symlinks.
	test -L "$probe_root/work/source"
	test -L "$probe_root/work/fake"
	printf '%s\n' "$output" | grep -Eq \
		'^neoproot l2s-stat-exit guard: checked=[1-9][0-9]* skipped=[1-9][0-9]*$'
}

run_probe "$ROOT" ''
run_probe "$EXTERNAL_ROOT" "$BACKING"

# The second run proves that an explicit host backing directory retains the
# same visible semantics and is actually used for the L2S representation.
test -n "$(find "$BACKING" -mindepth 1 -print -quit)"
printf '%s\n' 'link2symlink stat exit guard regression passed'
