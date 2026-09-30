#!/bin/sh
# A CLONE_VM|CLONE_VFORK exec must not recopy untouched environment strings.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=$(realpath "${PROOT:-$SCRIPT_DIR/../src/neoproot}")
if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status; then
    echo 'skip: already traced'; exit 125
fi
CC=${CC:-cc}
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-exec-env.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT INT TERM
"$CC" -O2 "$SCRIPT_DIR/test-exec-env-stack.c" -o "$TEMP/probe"
printf '%s\n' 'void empty_shim(void) {}' > "$TEMP/shim.c"
"$CC" -shared -fPIC "$TEMP/shim.c" -o "$TEMP/empty.so"
"$PROOT" --seccomp-notify --stat-shim="$TEMP/empty.so" -r / -w / "$TEMP/probe" /bin/true
