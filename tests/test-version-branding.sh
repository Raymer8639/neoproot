#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status; then
    echo "skip: already traced"; exit 125
fi
output=$("$PROOT" --version)
printf "%s\n" "$output" | grep -F "N   N  EEEEE   OOO   PPPP   RRRR    OOO    OOO   TTTTT"
printf "%s\n" "$output" | grep -F "built by Raymer8639."
printf "%s\n" "$output" | grep -F "https://github.com/Raymer8639/neoproot"
if printf "%s\n" "$output" | grep -E "built by scicat-team|https://gitee.com|UPROOT"; then exit 1; fi
echo "version branding regression passed"
