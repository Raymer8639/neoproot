#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=$(realpath "${PROOT:-$SCRIPT_DIR/../src/neoproot}")
CC=${CC:-cc}
if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status; then
    printf '%s\n' 'skip: already traced'
    exit 125
fi
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-mount-setattr.XXXXXX")
trap 'rm -rf "$ROOT"' EXIT INT TERM
mkdir -p "$ROOT/source/child" "$ROOT/child-source" "$ROOT/mnt" "$ROOT/copy" "$ROOT/proc"
mkdir -p "$ROOT/parent-write"
: > "$ROOT/parent-write/marker"
mkdir -p "$ROOT/workspace-source/protected" "$ROOT/rw-workspace"
: > "$ROOT/workspace-source/marker"
: > "$ROOT/workspace-source/protected/marker"
: > "$ROOT/source/file"
: > "$ROOT/child-source/file"
: > "$ROOT/source/device"
: > "$ROOT/fd-device"
"$CC" -O2 -Wall -Wextra "$SCRIPT_DIR/test-mount-setattr.c" -o "$ROOT/probe"
cp "$ROOT/probe" "$ROOT/source/suid-probe"
chmod 6755 "$ROOT/source/suid-probe"
BINDS=""
add_runtime_bind() {
    runtime_source=$(readlink -f "$1" 2>/dev/null || true)
    [ -d "$runtime_source" ] || return 0
    BINDS="${BINDS}${BINDS:+ }-b $runtime_source:$1"
}
if [ -n "${PREFIX:-}" ]; then
    add_runtime_bind "$PREFIX"
    add_runtime_bind /system
    add_runtime_bind /apex
else
    add_runtime_bind /usr
    add_runtime_bind /lib
    add_runtime_bind /lib64
fi
PROOT_UNSET_DONE=1 PROOT_MEMFD_LOADER=1 "$PROOT" -r "$ROOT" -w / \
    -i 1234:1234 $BINDS -b /proc -b /dev /probe
