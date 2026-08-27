#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-bwrap-procfd-target.XXXXXX")

cleanup() {
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

case "$ROOT" in
    /data/*)
        ;;
    *)
        printf '%s\n' 'SKIP: bwrap procfd mount-target test requires ROOT under /data/'
        exit 0
        ;;
esac

"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-bwrap-procfd-mount-target.c"
if [ -n "${PREFIX:-}" ]; then
    BINDS="-b /dev -b /proc -b $PREFIX:$PREFIX -b /system -b /apex"
else
    BINDS="-b /dev -b /proc -b /usr -b /lib -b /lib64"
fi

PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe
printf '%s\n' 'bwrap procfd mount target regression passed'
