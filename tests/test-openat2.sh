#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
CC=${CC:-cc}
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-openat2.XXXXXX")

cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/tmp"

if "$CC" -static -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-openat2.c" 2>/dev/null; then
	BINDS=""
else
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-openat2.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

set +e
PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe
status=$?
set -e

if [ "$status" -eq 125 ]; then
	printf '%s\n' '跳过 openat2 测试（内核不支持）'
	exit 125
fi
if [ "$status" -ne 0 ]; then
	exit "$status"
fi

printf '%s\n' 'openat2 regression passed'
