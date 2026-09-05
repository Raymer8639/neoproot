#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
CC=${CC:-cc}
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-faccessat2.XXXXXX")

cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT/bin" "$ROOT/tmp"
printf '#!/bin/sh\nexit 0\n' > "$ROOT/bin/present"
chmod 0755 "$ROOT/bin/present"

if "$CC" -static -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-faccessat2.c" 2>/dev/null; then
	BINDS=""
else
	"$CC" -O2 -o "$ROOT/probe" "$SCRIPT_DIR/test-faccessat2.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

set +e
PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" $BINDS /probe
status=$?
set -e

if [ "$status" -ne 0 ]; then
	exit "$status"
fi

printf '%s\n' 'faccessat2 AT_EACCESS regression passed'
