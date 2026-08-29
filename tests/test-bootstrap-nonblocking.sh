#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$(uname -m)" in
    aarch64|arm64) ;;
    *)
        echo "SKIP: bootstrap test requires ARM64"
        exit 125
        ;;
esac

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status 2>/dev/null; then
    echo "SKIP: bootstrap test cannot run under another tracer"
    exit 125
fi

if [ ! -x /system/bin/sh ]; then
    echo "SKIP: bootstrap test requires the Android system shell"
    exit 125
fi

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT INT TERM
mkdir "$ROOT/bin"
cp "$SCRIPT_DIR/mock-termux-wake-lock.sh" "$ROOT/bin/termux-wake-lock"
chmod 755 "$ROOT/bin/termux-wake-lock"

MARKER="$ROOT/wake-lock-ran"
LOG="$ROOT/neoproot.log"
if timeout -k 1 1 env -u PROOT_UNSET_DONE -u PROOT_MEMFD_LOADER \
    PATH="$ROOT/bin:$PATH" NEOPROOT_WAKE_LOCK_MARKER="$MARKER" \
    "$PROOT" --version >"$LOG" 2>&1; then
    status=0
else
    status=$?
fi

if [ "$status" -ne 0 ]; then
    echo "neoproot blocked on the wake-lock bootstrap hook" >&2
    cat "$LOG" >&2
    exit 1
fi

for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$MARKER" ] && break
    sleep 0.1
done
if [ ! -s "$MARKER" ]; then
    echo "mock termux-wake-lock was not invoked" >&2
    cat "$LOG" >&2
    exit 1
fi

echo "nonblocking wake-lock bootstrap regression passed"
