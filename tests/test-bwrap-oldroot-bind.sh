#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-bwrap-oldroot.XXXXXX")
TMP_BIND=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-bwrap-tmp.XXXXXX")
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
    rm -rf "$ROOT" "$TMP_BIND"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/tmp"
printf 'original-tmp\n' > "$TMP_BIND/source"

if "$CC" -static -O2 -o "$ROOT/probe" \
    "$SCRIPT_DIR/test-bwrap-oldroot-bind.c" 2>/dev/null; then
    BINDS=""
else
    "$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-bwrap-oldroot-bind.c"
    if [ -n "${PREFIX:-}" ]; then
        BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
    else
        BINDS="-b /usr -b /lib -b /lib64"
    fi
fi

PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" -b "$TMP_BIND:/tmp" $BINDS /probe
printf '%s\n' 'bwrap oldroot binding regression passed'
