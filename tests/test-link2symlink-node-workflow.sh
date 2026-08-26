#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# The fixture runs the Termux Node binary inside an isolated guest root. CI
# retains the portable C coverage and skips this host-runtime integration test.
if [ -z "${PREFIX:-}" ] || [ ! -x "$PREFIX/bin/node" ]; then
	printf '%s\n' 'link2symlink node workflow skipped: Termux Node unavailable'
	exit 0
fi

ROOT=$(mktemp -d)
cleanup() {
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

cp "$SCRIPT_DIR/test-link2symlink-node-workflow.js" "$ROOT/probe.js"

if ! output=$(PROOT_L2S_DIR= PROOT_UNSET_DONE=1 "$PROOT" -r "$ROOT" \
	-b "$PREFIX:$PREFIX" -b /system -b /apex --link2symlink \
	"$PREFIX/bin/node" /probe.js 2>&1); then
	printf '%s\n' "$output"
	exit 1
fi
printf '%s\n' "$output"
printf '%s\n' "$output" | grep -qx 'link2symlink node module workflow passed'
