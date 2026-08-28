#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-bwrap-resolve-in-root.XXXXXX")

cleanup() {
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

case "$ROOT" in
    /data/*)
        ;;
    *)
        printf '%s\n' 'SKIP: bwrap RESOLVE_IN_ROOT test requires ROOT under /data/'
        exit 0
        ;;
esac

mkdir -p "$ROOT/tmp" "$ROOT/.l2s" "$ROOT/cwd-probe"
: > "$ROOT/cwd-probe/relative-probe"
"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-bwrap-resolve-in-root.c"

PROOT_UNSET_DONE=1 PROOT_L2S_DIR="$ROOT/.l2s" "$PROOT" --link2symlink \
    -r "$ROOT" -b /dev -b /proc -b "$PREFIX:$PREFIX" \
    -b /system -b /apex /probe
printf '%s\n' 'bwrap RESOLVE_IN_ROOT root-bind regression passed'
