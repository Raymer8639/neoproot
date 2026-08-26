#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-statx-empty-path.XXXXXX")

cleanup() {
    rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

mkdir "$ROOT/test-dir"
if "$CC" -static -std=c11 -Wall -Wextra -O2 -o "$ROOT/probe" \
    "$SCRIPT_DIR/test-statx-empty-path-mount-id.c" 2>/dev/null; then
    BIND_ARGS=
elif [ -n "${PREFIX:-}" ] && "$CC" -std=c11 -Wall -Wextra -O2 -o "$ROOT/probe" \
    "$SCRIPT_DIR/test-statx-empty-path-mount-id.c" 2>/dev/null; then
    BIND_ARGS="-b /proc -b /system -b /apex -b $PREFIX:$PREFIX"
else
    printf "%s\n" "SKIP: compiler cannot build a runnable statx/seccomp probe"
    exit 0
fi

set +e
"$PROOT" -r "$ROOT" $BIND_ARGS /probe
status=$?
set -e
case "$status" in
    0)
        printf "%s\n" "statx AT_EMPTY_PATH mount ID regression passed"
        ;;
    125)
        printf "%s\n" "SKIP: statx AT_EMPTY_PATH seccomp probe unavailable"
        ;;
    *)
        exit "$status"
        ;;
esac
