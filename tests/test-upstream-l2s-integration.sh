#!/bin/sh
set -eu
# Host-only: Lead may run this after rebuilding. Do not run inside PRoot/UML.
TASK_SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TASK_PROOT=${PROOT:-$TASK_SRC/src/neoproot}
[ -x "$TASK_PROOT" ] || { echo "SKIP: set PROOT to a rebuilt neoproot"; exit 125; }
TASK_TMP=$(mktemp -d /tmp/neoproot-upstream-l2s-host.XXXXXX)
case "$TASK_TMP" in /tmp/neoproot-upstream-l2s-host.*) ;; *) exit 1;; esac
trap 'rm -rf -- "$TASK_TMP"' EXIT HUP INT TERM
env -i PATH=/usr/bin:/bin cc -std=gnu11 -O2 -Wall -Wextra \
    "$TASK_SRC/tests/test-upstream-l2s-integration.c" -o "$TASK_TMP/helper"
for TASK_MODE in sibling separate; do
    for TASK_SECCOMP in yes no; do
        TASK_WORK="$TASK_TMP/$TASK_MODE-$TASK_SECCOMP"
        mkdir "$TASK_WORK" "$TASK_WORK/backing"
        if [ "$TASK_MODE" = separate ]; then TASK_STORE="PROOT_L2S_DIR=$TASK_WORK/backing"; else TASK_STORE=; fi
        if [ "$TASK_SECCOMP" = no ]; then TASK_FILTER=PROOT_NO_SECCOMP=1; else TASK_FILTER=; fi
        env -i PATH=/usr/bin:/bin $TASK_STORE $TASK_FILTER \
            "$TASK_PROOT" -l -r / -w "$TASK_WORK" "$TASK_TMP/helper" "$TASK_WORK"
    done
done
# A failed guest translation must not move a host-only source. The helper is
# static only for this empty-rootfs scenario; other scenarios work dynamically.
if env -i PATH=/usr/bin:/bin cc -static -O2 \
    "$TASK_SRC/tests/test-upstream-l2s-integration.c" -o "$TASK_TMP/static-helper" 2>/dev/null; then
    mkdir "$TASK_TMP/rootfs" "$TASK_TMP/host-only"
    printf keep > "$TASK_TMP/host-only/file"
    set +e
    env -i PATH=/usr/bin:/bin "$TASK_PROOT" -l -r "$TASK_TMP/rootfs" \
        -b "$TASK_TMP/static-helper:/helper" -w / /helper link-error "$TASK_TMP/host-only/file" /new
    TASK_STATUS=$?
    set -e
    [ "$TASK_STATUS" -eq 2 ]
    [ ! -L "$TASK_TMP/host-only/file" ]
    [ "$(ls -A "$TASK_TMP/host-only")" = file ]
fi
