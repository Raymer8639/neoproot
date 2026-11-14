#!/bin/sh
set -eu
# Run with: env -i PATH=/usr/bin:/bin sh tests/test-upstream-l2s-logic.sh
# Optional host ASAN: append "quick sanitize"; ASAN needs a host address space.
TASK_SRC=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TASK_TMP=$(mktemp -d /tmp/neoproot-upstream-l2s.XXXXXX)
case "$TASK_TMP" in /tmp/neoproot-upstream-l2s.*) ;; *) exit 1;; esac
trap 'rm -rf -- "$TASK_TMP"' EXIT HUP INT TERM
mkdir "$TASK_TMP/sibling" "$TASK_TMP/separate" "$TASK_TMP/backing"
TASK_EXHAUSTIVE=${1:-}
for TASK_VARIANT in ${2:-clang gcc userland ubsan}; do
    TASK_CC=$TASK_VARIANT
    TASK_DEFINES=
    if [ "$TASK_VARIANT" = userland ]; then TASK_CC=clang; TASK_DEFINES=-DUSERLAND; fi
    if [ "$TASK_VARIANT" = sanitize ]; then TASK_CC=clang; TASK_DEFINES="-fsanitize=address,undefined -fno-omit-frame-pointer"; fi
    if [ "$TASK_VARIANT" = ubsan ]; then TASK_CC=clang; TASK_DEFINES="-fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"; fi
    command -v "$TASK_CC" >/dev/null 2>&1 || continue
    env -i PATH=/usr/bin:/bin "$TASK_CC" -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
        -std=gnu2x -O2 -g -Wall -Wextra -Wno-unused-function -Wno-attributes $TASK_DEFINES \
        -ffunction-sections -fdata-sections -I"$TASK_SRC/src" \
        "$TASK_SRC/tests/test-upstream-l2s-logic.c" -Wl,--gc-sections -ltalloc \
        -o "$TASK_TMP/test-$TASK_VARIANT"
    mkdir "$TASK_TMP/sibling/$TASK_VARIANT" "$TASK_TMP/separate/$TASK_VARIANT" "$TASK_TMP/backing/$TASK_VARIANT"
    env -i PATH=/usr/bin:/bin "$TASK_TMP/test-$TASK_VARIANT" "$TASK_TMP/sibling/$TASK_VARIANT" $TASK_EXHAUSTIVE
    TASK_EXHAUSTIVE=quick
    env -i PATH=/usr/bin:/bin PROOT_L2S_DIR="$TASK_TMP/backing/$TASK_VARIANT" \
        "$TASK_TMP/test-$TASK_VARIANT" "$TASK_TMP/separate/$TASK_VARIANT" quick
done
