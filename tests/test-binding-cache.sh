#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

if "$CC" -static -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-binding-cache.c" 2>/dev/null; then
	BINDS=""
else
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-binding-cache.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

if ! output=$(NEOPROOT_TEST_BINDING_CACHE_COUNTER=1 PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe 2>&1); then
	printf '%s\n' "$output"
	exit 1
fi
printf '%s\n' "$output"

count=$(printf '%s\n' "$output" | grep -c '^neoproot binding cache: allocate$' || true)
test "$count" -eq 1
printf '%s\n' 'binding cache reuse regression passed'
