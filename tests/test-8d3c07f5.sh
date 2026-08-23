#!/bin/sh
set -eu

PROOT=${PROOT:-../src/neoproot}

for tool in mcookie busybox cp file find grep mkdir rm; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		exit 125
	fi
done

BUSYBOX=$(command -v busybox)
if ! BUSYBOX_FILE=$(file -L "$BUSYBOX" 2>&1); then
	exit 125
fi
case "$BUSYBOX_FILE" in
	*"statically linked"*) ;;
	*) exit 125 ;;
esac

# PROOT_L2S_DIR is used by the link2symlink extension for backing files of
# emulated hard links. Replacing that directory from inside the rootfs must
# not redirect those files to a host directory.
DIR=/tmp/$(mcookie).l2s
ROOTFS="$DIR/rootfs"
OUTSIDE="$DIR/outside"
TRACE_LOG="$DIR/trace.log"

cleanup() {
	rm -rf "$DIR"
}
trap cleanup EXIT INT TERM

if ! mkdir -p "$ROOTFS/bin" "$ROOTFS/.l2s" "$OUTSIDE" ||
	! test -d "$OUTSIDE" ||
	! cp "$BUSYBOX" "$ROOTFS/bin/busybox"; then
	exit 1
fi

if [ ! -x "$PROOT" ]; then
	exit 1
fi

if MARKER=$(PROOT_L2S_DIR="$ROOTFS/.l2s" "$PROOT" -v 1 -l --rootfs="$ROOTFS" \
	/bin/busybox sh -c '
		echo escaped > /original
		# A lookup of an internal name opens and caches the protected
		# backing-directory descriptor without creating a guest link that
		# would become deliberately broken below.
		/bin/busybox test ! -e /.l2s/.l2s.prime0001 || exit 1
		echo WARMUP_READY
		/bin/busybox rm -rf /.l2s
		/bin/busybox ln -s '"$OUTSIDE"' /.l2s || exit 1
		echo REPLACED_READY
		echo READY
		/bin/busybox ln /original /link
		/bin/busybox test -L /link || exit 1
		echo LINK_READY
	' 2>"$TRACE_LOG"); then
	TRACE_STATUS=0
	else
	TRACE_STATUS=$?
	printf '%s\n' "link2symlink tracee command failed (status $TRACE_STATUS); marker: $MARKER" >&2
	cat "$TRACE_LOG" >&2
	exit 1
fi

# The tracee must have replaced the directory, or the test could pass without
# exercising the vulnerable path.
if ! printf '%s\n' "$MARKER" | grep -qx 'WARMUP_READY'; then
	exit 1
fi
if ! printf '%s\n' "$MARKER" | grep -qx 'REPLACED_READY'; then
	exit 1
fi
if ! printf '%s\n' "$MARKER" | grep -qx 'LINK_READY'; then
	exit 1
fi

OUTSIDE_ENTRY=$(find "$OUTSIDE" -mindepth 1 -maxdepth 1 -print -quit) || exit 1
if [ -n "$OUTSIDE_ENTRY" ]; then
	exit 1
fi

printf '%s\n' "link2symlink directory redirection regression passed"
