#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT INT TERM

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HEAP_SOURCE="$SCRIPT_DIR/../src/syscall/heap.c"
if ! awk '
    /if \(new_brk != 0\)/ { in_guard = 1 }
    in_guard && /tracee->verbose > 0/ { found = 1 }
    in_guard && /^[[:space:]]*return;/ { saw_return = 1; exit }
    END { exit(found && saw_return ? 0 : 1) }
' "$HEAP_SOURCE"; then
    echo "default brk handling is not guarded by tracee verbosity" >&2
    exit 1
fi

# The nested-tracer guard intentionally prevents an integration run from
# inside an existing PRoot instance; the source invariant above still runs.
if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status 2>/dev/null; then
    echo "brk diagnostic verbosity source regression passed (integration skipped under PRoot)"
    exit 0
fi

RUNTIME_BINDS=""
add_runtime_bind() {
    source=$(readlink -f "$1")
    [ -d "$source" ] || return 0
    RUNTIME_BINDS="$RUNTIME_BINDS -b $source:$1"
}

if [ -n "${PREFIX:-}" ]; then
    add_runtime_bind "$PREFIX"
    add_runtime_bind /system
    add_runtime_bind /apex
    TARGET="$PREFIX/bin/true"
else
    add_runtime_bind /usr
    add_runtime_bind /lib
    add_runtime_bind /lib64
    TARGET=/bin/true
fi

default_log=$(mktemp)
verbose_log=$(mktemp)
trap 'rm -rf "$ROOT" "$default_log" "$verbose_log"' EXIT INT TERM

"$PROOT" -r "$ROOT" $RUNTIME_BINDS "$TARGET" > /dev/null 2>"$default_log"
if grep -q 'suspicious brk' "$default_log"; then
    echo "default PRoot mode emitted an internal brk diagnostic" >&2
    cat "$default_log" >&2
    exit 1
fi

"$PROOT" --verbose=1 -r "$ROOT" $RUNTIME_BINDS "$TARGET" > /dev/null 2>"$verbose_log"
if ! grep -q 'suspicious brk' "$verbose_log"; then
    echo "verbose PRoot mode did not emit the brk diagnostic" >&2
    cat "$verbose_log" >&2
    exit 1
fi

echo "brk diagnostic verbosity regression passed"
