#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-tracer-guard.XXXXXX")

cleanup() {
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

"$CC" -std=c23 -Wall -Wextra -O2 -o "$ROOT/probe" \
    "$SCRIPT_DIR/test-tracer-guard.c"
"$ROOT/probe" "$PROOT"
printf "%s\n" "nested tracer guard regression passed"
