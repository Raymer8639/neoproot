#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT INT TERM

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -m)" in
    aarch64|arm64) ;;
    *)
        echo "SKIP: brk diagnostic helper requires ARM64"
        exit 125
        ;;
esac

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status 2>/dev/null; then
    echo "SKIP: brk diagnostic integration cannot run under another tracer"
    exit 125
fi

HELPER="$ROOT/brk-first"
CC=${CC:-cc}
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "SKIP: C compiler unavailable for brk diagnostic helper"
    exit 125
fi
"$CC" -nostdlib -static -fno-stack-protector \
    -Wl,-e,_start -Wl,--build-id=none \
    -o "$HELPER" "$SCRIPT_DIR/test-brk-diagnostic.S"

default_log=$(mktemp)
verbose_log=$(mktemp)
trap 'rm -rf "$ROOT" "$default_log" "$verbose_log"' EXIT INT TERM

"$PROOT" -r "$ROOT" /brk-first > /dev/null 2>"$default_log"
if grep -q 'suspicious brk' "$default_log"; then
    echo "default PRoot mode emitted an internal brk diagnostic" >&2
    cat "$default_log" >&2
    exit 1
fi

"$PROOT" --verbose=1 -r "$ROOT" /brk-first > /dev/null 2>"$verbose_log"
if ! grep -q 'suspicious brk' "$verbose_log"; then
    echo "verbose PRoot mode did not emit the brk diagnostic" >&2
    cat "$verbose_log" >&2
    exit 1
fi

echo "brk diagnostic verbosity regression passed"
