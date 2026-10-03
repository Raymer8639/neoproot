#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=$(realpath "${PROOT:-$SCRIPT_DIR/../src/neoproot}")
CC=${CC:-cc}

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status; then
    printf '%s\n' 'skip: already traced'
    exit 125
fi
if ! awk '$5 == "/data" { found = 1 } END { exit !found }' /proc/self/mountinfo; then
    printf '%s\n' 'skip: mountinfo virtualization requires a /data mount'
    exit 125
fi

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-mountinfo-aliases-long-root.XXXXXX")
trap 'rm -rf "$ROOT"' EXIT INT TERM
case "$ROOT" in
    /data/*) ;;
    *)
        printf '%s\n' 'skip: mountinfo virtualization requires rootfs under /data'
        exit 125
        ;;
esac

mkdir -p "$ROOT/proc" "$ROOT/tmp/codex-daemon-mountinfo" \
    "$ROOT/tmp/codex-daemon-surviving" \
    "$ROOT/tmp/codex-daemon-reverse" \
    "$ROOT/tmp/codex-daemon-exec" \
    "$ROOT/bind-replay" "$ROOT/tmpfs" "$ROOT/newroot/proc" \
    "$ROOT/newroot/oldroot" "$ROOT/bound-directory"
printf '%s\n' marker > "$ROOT/marker"
: > "$ROOT/tmp/socket-bind-visible"
"$CC" -O2 -Wall -Wextra "$SCRIPT_DIR/test-mountinfo-internal-bindings.c" -o "$ROOT/probe"
if [ -n "${PREFIX:-}" ]; then
    BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
else
    BINDS="-b /usr -b /lib -b /lib64"
fi

PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" -w / $BINDS -b /proc \
    -b "$ROOT/marker:/file-bind" -b "$ROOT/bound-directory:/dir-bind" /probe
