#!/bin/sh
# Step 1: --seccomp-notify is visible; a successful probe still uses TRACE.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
PROOT=$(CDPATH= cd -- "$(dirname -- "$PROOT")" && pwd)/$(basename -- "$PROOT")
CC=${CC:-cc}

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status; then
	printf '%s\n' 'skip: already traced'
	exit 125
fi

help_out=$("$PROOT" --help)
printf '%s\n' "$help_out" | grep -F -- '--seccomp-notify' >/dev/null

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-seccomp-notify.XXXXXX")
cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

cat > "$ROOT/probe.c" <<'EOF'
int main(void) { return 0; }
EOF

STATIC=0
if "$CC" -static -O2 -o "$ROOT/probe" "$ROOT/probe.c" 2>/dev/null; then
	BINDS=""
	STATIC=1
else
	"$CC" -O2 -o "$ROOT/probe" "$ROOT/probe.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi
mkdir -p "$ROOT/tmp"

set +e
PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe
status=$?
set -e
if [ "$status" -ne 0 ]; then
	printf '%s\n' 'neoproot without --seccomp-notify failed'
	exit "$status"
fi

if [ "$STATIC" -eq 0 ]; then
	printf '%s\n' 'seccomp-notify CLI probe passed (with-flag launch needs static)'
	exit 0
fi

set +e
notify_err=$(PROOT_UNSET_DONE=1 "$PROOT" --seccomp-notify -r "$ROOT" $BINDS /probe 2>&1 >/dev/null)
status=$?
set -e
if [ "$status" -ne 0 ]; then
	printf '%s\n' "$notify_err"
	printf '%s\n' 'neoproot --seccomp-notify failed'
	exit "$status"
fi
printf '%s\n' "$notify_err" | grep -F 'USER_NOTIF listener ready' >/dev/null

printf '%s\n' 'seccomp-notify CLI probe passed'
