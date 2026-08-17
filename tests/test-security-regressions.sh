#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
CC=${CC:-cc}
ROOT=$(mktemp -d)
OUTSIDE=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() {
    rm -rf "$ROOT" "$OUTSIDE"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/safe" "$ROOT/l2s"
printf 'inside\n' > "$ROOT/safe/probe"
printf 'host-only\n' > "$OUTSIDE/secret"

"$CC" -static -O2 -o "$ROOT/security-regressions" \
    "$SCRIPT_DIR/test-security-regressions.c"

PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" -b /proc --link2symlink -0 /security-regressions "$OUTSIDE"

if find "$ROOT" -name '.proot-meta-file.*' -print | grep -q .; then
    echo "guest-visible fake-id0 metadata found" >&2
    exit 1
fi

echo "security regression tests passed"
