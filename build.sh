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
	*)
		echo "错误: 未知参数 $argument" >&2
		usage >&2
		exit 2
		;;
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
# The default -march is armv8.2-a, which is fast on a recent phone and an
# illegal instruction on an older one: the binary is linked fine, then dies with
# SIGILL on the first atomics/crypto instruction it meets.  Ask the CPU what it
# actually has and fall back rather than assume.
#
# /proc/cpuinfo "Features" is the authority; a missing file (some kernels hide
# it from non-root) is treated as "unknown", and unknown keeps the fast default
# only when the caller asked for it explicitly.
cpu_has() { # cpu_has FEATURE_NAME
	grep -qw "$1" /proc/cpuinfo 2>/dev/null
}

if [ -z "${MARCH:-}" ]; then
	case "$(uname -m)" in
	aarch64|arm64) ;;
	*) : ;;
	esac
	# crc32, not crc: that is the name in /proc/cpuinfo, and grep -w does not
	# match a whole word against it.
	if cpu_has asimd && cpu_has crc32 && cpu_has sha1 && cpu_has sha2 \
		&& cpu_has aes && cpu_has atomics && cpu_has fphp && cpu_has asimdhp; then
		MARCH="-march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto -mtune=generic"
		echo "==> CPU supports armv8.2 features, using the fast instruction set"
	elif cpu_has asimd; then
		MARCH="-march=armv8-a -mtune=generic"
		echo "==> CPU is pre-armv8.2, building a baseline binary (slower, but it runs)"
	else
		MARCH="-march=armv8-a -mtune=generic"
		echo "==> CPU features unknown, building a baseline binary"
	fi
	export MARCH
fi

if [ "$WITH_UM" = 1 ]; then

echo "==> neoproot 构建（不安装，含 UML 后端）"
else
  echo "==> neoproot 构建（不安装，仅 fast 后端）"
fi
echo "    平台: $(uname -m) / $(uname -s)"
make -C src $( [ "$WITH_UM" = 1 ] && echo all || echo neoproot ) WITH_UM="$WITH_UM" MARCH="$MARCH" -j"$(nproc 2>/dev/null || echo 4)" V=1
echo "==> 构建完成: $(pwd)/src/neoproot"
ls -lh src/neoproot
if [ "$WITH_UM" = 1 ]; then
  ls -lh src/neoproot-um
fi
