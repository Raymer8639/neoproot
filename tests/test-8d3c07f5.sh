#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}

if ! command -v mcookie >/dev/null 2>&1 ||
	! command -v busybox >/dev/null 2>&1; then
	exit 125
fi

# PROOT_L2S_DIR is used by the link2symlink extension for backing files of
# emulated hard links. Replacing that directory from inside the rootfs must
# not redirect those files to a host directory.
DIR=/tmp/$(mcookie).l2s
ROOTFS="$DIR/rootfs"
OUTSIDE="$DIR/outside"

cleanup() {
	rm -rf "$DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOTFS/bin" "$ROOTFS/.l2s" "$OUTSIDE"
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"

MARKER=$(PROOT_L2S_DIR="$ROOTFS/.l2s" "$PROOT" -l --rootfs="$ROOTFS" \
	/bin/busybox sh -c '
		echo escaped > /original
		/bin/busybox rm -rf /.l2s
		/bin/busybox ln -s '"$OUTSIDE"' /.l2s
		/bin/busybox test -L /.l2s && echo READY
		/bin/busybox ln /original /link
	' 2>/dev/null)

ESCAPED=$(ls -A "$OUTSIDE" | wc -l)

# The tracee must have replaced the directory, or the test could pass without
# exercising the vulnerable path.
if [ "$MARKER" != "READY" ]; then
	exit 125
fi

if [ "$ESCAPED" != "0" ]; then
	exit 1
fi

printf '%s\n' "link2symlink directory redirection regression passed"
