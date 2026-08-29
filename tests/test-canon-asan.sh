#!/bin/sh
set -eu

# This regression catches unchecked vector reads while canonicalize() and
# execve path translation resolve the short "." and ".." components.
PROOT_ASAN=${PROOT_ASAN:-}
if [ -z "$PROOT_ASAN" ] || [ ! -x "$PROOT_ASAN" ]; then
    echo "SKIP: set PROOT_ASAN to an AddressSanitizer-instrumented neoproot"
    exit 125
fi

ROOT=$(mktemp -d)
LOG="$ROOT/asan.log"
trap 'rm -rf "$ROOT"' EXIT INT TERM
mkdir "$ROOT/work"

if [ -n "${PREFIX:-}" ]; then
    RUNTIME_BINDS="-b $PREFIX:$PREFIX -b /system:/system -b /apex:/apex"
    TARGET="$PREFIX/bin/true"
else
    RUNTIME_BINDS="-b /usr:/usr -b /lib:/lib -b /lib64:/lib64"
    TARGET=/bin/true
fi

if ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}" \
    "$PROOT_ASAN" -r "$ROOT" -w /work/../. $RUNTIME_BINDS "$TARGET" \
        > /dev/null 2>"$LOG"; then
    status=0
else
    status=$?
fi

if grep -q 'ERROR: AddressSanitizer' "$LOG"; then
    cat "$LOG" >&2
    exit 1
fi

if [ "$status" -ne 0 ]; then
    cat "$LOG" >&2
    exit "$status"
fi

echo "canonicalization ASAN regression passed"
