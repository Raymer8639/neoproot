#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-bwrap-proc.XXXXXX")

cleanup() {
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

case "$ROOT" in
    /data/*)
        ;;
    *)
        printf "%s\n" "SKIP: bwrap proc dirfd test requires ROOT under /data/ for mountinfo virtualization"
        exit 0
        ;;
esac

if ! "$CC" -static -O2 -o "$ROOT/probe" \
    "$SCRIPT_DIR/test-bwrap-proc-dirfd.c" 2>/dev/null; then
    "$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-bwrap-proc-dirfd.c"
    if [ -n "${PREFIX:-}" ]; then
        BINDS="-b /proc -b $PREFIX:$PREFIX -b /system -b /apex"
    else
        BINDS="-b /proc -b /usr -b /lib -b /lib64"
    fi
else
    BINDS="-b /proc"
fi

PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe
printf "%s\n" "bwrap proc dirfd pivot regression passed"
