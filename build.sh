#!/bin/sh
# Build neoproot on an ARM64 host. Installation is separate: use ./install.sh.
set -eu
if [ "$#" -ne 0 ]; then echo "Usage: sh build.sh" >&2; exit 2; fi
case "$(uname -m)" in aarch64|arm64) ;; *) echo "错误: 本项目仅支持 aarch64/arm64 设备" >&2; exit 1;; esac
MISSING=""
check_cmd() { pkg=$1; shift; for c in "$@"; do command -v "$c" >/dev/null 2>&1 && return 0; done; MISSING="$MISSING $pkg"; }
check_cmd clang clang
check_cmd make make
check_cmd llvm llvm-config llvm-ar
check_cmd binutils as ld.bfd
check_cmd pkg-config pkg-config
if ! pkg-config --exists talloc 2>/dev/null; then MISSING="$MISSING libtalloc"; fi
if [ -n "$MISSING" ]; then
  echo "==> 缺少依赖:$MISSING" >&2
  echo "    Termux: pkg install clang make llvm binutils pkg-config libtalloc" >&2
  echo "    Debian/Ubuntu: install clang make llvm binutils pkg-config libtalloc-dev" >&2
  exit 1
fi
echo "==> neoproot 构建（不安装）"
echo "    平台: $(uname -m) / $(uname -s)"
make -C src neoproot -j"$(nproc 2>/dev/null || echo 4)" V=1
echo "==> 构建完成: $(pwd)/src/neoproot"
ls -lh src/neoproot
