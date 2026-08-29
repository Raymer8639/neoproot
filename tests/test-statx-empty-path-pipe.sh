#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
CC=${CC:-cc}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT INT TERM

if ! "$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-statx-empty-path-pipe.c"; then
    exit 125
fi

mkfifo "$ROOT/outpipe"
wc -c <"$ROOT/outpipe" >"$ROOT/count" &
reader=$!
set +e
"$PROOT" "$ROOT/probe" >"$ROOT/outpipe" 2>"$ROOT/err"
status=$?
set -e
wait "$reader"
case "$status" in
    0)
        bytes=$(cat "$ROOT/count")
        test "$bytes" -eq 8
        test ! -s "$ROOT/err"
        ;;
    125)
        printf '%s\n' 'SKIP: nested PRoot/statx probe unavailable'
        exit 0
        ;;
    1)
        if grep -q 'refusing to start while already traced' "$ROOT/err"; then
            printf '%s\n' 'SKIP: nested PRoot/statx probe unavailable'
            exit 0
        fi
        cat "$ROOT/err" >&2
        exit 1
        ;;
    *)
        cat "$ROOT/err" >&2
        exit "$status"
        ;;
esac
printf '%s\n' 'statx empty-path pipe regression passed'
