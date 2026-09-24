#!/bin/sh
# Build and install the local ARM64 neoproot binary.
set -eu
if [ "$#" -gt 1 ]; then echo "Usage: sh install.sh [PREFIX]" >&2; exit 2; fi
PREFIX_DIR=${1:-${PREFIX:-}}
if [ -z "$PREFIX_DIR" ]; then echo "错误: 需要 PREFIX，或传入安装前缀：sh install.sh /path/to/prefix" >&2; exit 2; fi
BINDIR=$PREFIX_DIR/bin
mkdir -p "$BINDIR"
sh "$(dirname "$0")/build.sh"
TARGET=$BINDIR/neoproot
if [ -e "$TARGET" ]; then BACKUP=$TARGET.prev-$(date +%Y%m%d-%H%M%S); cp -a "$TARGET" "$BACKUP"; echo "==> 旧二进制备份: $BACKUP"; fi
STAGE=$BINDIR/.neoproot.install.$$
trap 'rm -f "$STAGE"' EXIT INT TERM
cp src/neoproot "$STAGE"; chmod 755 "$STAGE"; mv -f "$STAGE" "$TARGET"
trap - EXIT INT TERM
echo "==> 安装完成: $TARGET"
"$TARGET" --version 2>/dev/null || true
