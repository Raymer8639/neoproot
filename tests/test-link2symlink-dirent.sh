#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT_BASELINE=$(mktemp -d)
ROOT_OPT_IN=$(mktemp -d)
ROOT_HIDDEN=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
	rm -rf "$ROOT_BASELINE" "$ROOT_OPT_IN" "$ROOT_HIDDEN"
}
trap cleanup EXIT INT TERM

PROBE_BIND=""
compile_probe() {
	probe_root=$1
	if ! "$CC" -static -O2 -o "$probe_root/probe" \
	    "$SCRIPT_DIR/test-link2symlink-dirent.c" 2>/dev/null; then
		"$CC" -O2 -o "$probe_root/probe" \
		    "$SCRIPT_DIR/test-link2symlink-dirent.c"
		if [ -n "${PREFIX:-}" ]; then
			PROBE_BIND="-b $PREFIX:$PREFIX -b /system -b /apex"
		fi
	fi
}

compile_probe "$ROOT_BASELINE"
compile_probe "$ROOT_OPT_IN"
compile_probe "$ROOT_HIDDEN"

baseline=$(PROOT_L2S_DIR= PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT_BASELINE" $PROBE_BIND \
	--link2symlink /probe)
opt_in=$(PROOT_L2S_DIR= PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT_OPT_IN" $PROBE_BIND \
	--link2symlink-dirent /probe)
with_hidden_files=$(PROOT_L2S_DIR= PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT_HIDDEN" $PROBE_BIND \
	--link2symlink -H --link2symlink-dirent /probe)

test "$baseline" = "fake=10 real=10"
test "$opt_in" = "fake=8 real=10"
test "$with_hidden_files" = "fake=8 real=10"
printf '%s\n' "link2symlink dirent regression passed"
