#!/bin/sh
# Build neoproot on an ARM64 host. Installation is separate: use ./install.sh.
#
# Usage: sh build.sh [--with-um|--without-um] [--help]
#
#   --with-um      build neoproot with the UML backend and neoproot-um (default)
#   --without-um   build the fast backend only: no UML objects, no neoproot-um,
#                  about 14% smaller and a shorter build
set -eu

WITH_UM=1
usage() {
	cat <<'USAGE'
Usage: sh build.sh [--with-um|--without-um]

  --with-um       compile the UML backend into neoproot and build neoproot-um
                  (default: a neoproot that can run --backend=um)
  --without-um    leave the UML backend out: fast backend only, no neoproot-um
  --help          show this text
USAGE
}

for argument do
	case "$argument" in
	--with-um) WITH_UM=1 ;;
	--without-um) WITH_UM=0 ;;
	--help|-h) usage; exit 0 ;;
	*) echo "错误: 未知参数 $argument（sh build.sh --help）" >&2; exit 2 ;;
	esac
done

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
if [ "$WITH_UM" = 1 ]; then
  echo "==> neoproot 构建（不安装，含 UML 后端）"
else
  echo "==> neoproot 构建（不安装，仅 fast 后端）"
fi
echo "    平台: $(uname -m) / $(uname -s)"
make -C src $( [ "$WITH_UM" = 1 ] && echo all || echo neoproot ) WITH_UM="$WITH_UM" -j"$(nproc 2>/dev/null || echo 4)" V=1
echo "==> 构建完成: $(pwd)/src/neoproot"
ls -lh src/neoproot
if [ "$WITH_UM" = 1 ]; then
  ls -lh src/neoproot-um
fi
