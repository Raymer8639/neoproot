#!/bin/sh
# Build and install neoproot, optionally with the UML backend and the stat shim.
#
# Usage: sh install.sh [options] [PREFIX]
#
#   --prefix=DIR        install prefix (or pass it as the last argument, or set
#                       $PREFIX).  The binaries go to DIR/bin.
#   --with-um           build and install neoproot-um too (default)
#   --without-um        fast backend only: smaller neoproot, no neoproot-um
#   --with-shim         install the stat shim and drop it into every rootfs
#                       given with --shim-rootfs (default)
#   --without-shim      do not install the shim
#   --shim-rootfs=DIR   copy the shim into this container rootfs at
#                       /opt/neoproot/libstatfast.so.  Repeatable.
#   --help              show this text
#
# The shim is a guest-ABI shared library, so it has to exist *inside* the
# container: installing it on the host is not enough.  neoproot picks it up by
# itself when it finds /opt/neoproot/libstatfast.so in the rootfs, which is why
# --shim-rootfs exists -- it saves passing --stat-shim on every run.
set -eu

WITH_UM=1
WITH_SHIM=1
PREFIX_DIR=
SHIM_ROOTFS=
SHIM_GUEST_DIR=/opt/neoproot
SHIM_NAME=libstatfast.so

usage() {
	cat <<'USAGE'
Usage: sh install.sh [options] [PREFIX]

  --prefix=DIR        install prefix (default: $PREFIX)
  --with-um           build and install neoproot-um too (default)
  --without-um        fast backend only: no UML objects, no neoproot-um
  --with-shim         install the stat shim (default)
  --without-shim      do not install the shim
  --shim-rootfs=DIR   also copy the shim into this container rootfs, at
                      /opt/neoproot/libstatfast.so (repeatable)
  --help              show this text

Examples:
  sh install.sh                                  # host install, UM + shim
  sh install.sh --without-um                     # smallest neoproot
  sh install.sh --shim-rootfs=~/alarm-rootfs     # shim into a container too
USAGE
}

for argument do
	case "$argument" in
	--with-um) WITH_UM=1 ;;
	--without-um) WITH_UM=0 ;;
	--with-shim) WITH_SHIM=1 ;;
	--without-shim) WITH_SHIM=0 ;;
	--prefix=*) PREFIX_DIR=${argument#--prefix=} ;;
	--shim-rootfs=*)
		SHIM_ROOTFS="$SHIM_ROOTFS ${argument#--shim-rootfs=}" ;;
	--help|-h) usage; exit 0 ;;
	-*) echo "错误: 未知参数 $argument（sh install.sh --help）" >&2; exit 2 ;;
	*) PREFIX_DIR=$argument ;;
	esac
done

if [ -z "$PREFIX_DIR" ]; then PREFIX_DIR=${PREFIX:-}; fi
if [ -z "$PREFIX_DIR" ]; then
	echo "错误: 需要 PREFIX，或传入安装前缀：sh install.sh --prefix=/path/to/prefix" >&2
	exit 2
fi
BINDIR=$PREFIX_DIR/bin
LIBEXECDIR=$PREFIX_DIR/libexec/neoproot
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

mkdir -p "$BINDIR"

# Build with the same choice, so the flag cannot disagree with what is installed.
if [ "$WITH_UM" = 1 ]; then
	sh "$HERE/build.sh" --with-um
else
	sh "$HERE/build.sh" --without-um
fi

install_atomically() {
	source_file=$1
	target=$2
	if [ -e "$target" ]; then
		backup=$target.prev-$(date +%Y%m%d-%H%M%S)
		cp -a "$target" "$backup"
		echo "==> 旧文件备份: $backup"
	fi
	stage=$target.install.$$
	trap 'rm -f "$stage"' EXIT INT TERM
	cp "$source_file" "$stage"
	chmod 755 "$stage"
	mv -f "$stage" "$target"
	trap - EXIT INT TERM
}

install_atomically "$HERE/src/neoproot" "$BINDIR/neoproot"
echo "==> 安装完成: $BINDIR/neoproot"

if [ "$WITH_UM" = 1 ]; then
	install_atomically "$HERE/src/neoproot-um" "$BINDIR/neoproot-um"
	echo "==> 安装完成: $BINDIR/neoproot-um"
else
	# A stale neoproot-um from an earlier install would claim a backend this
	# build does not have.
	if [ -e "$BINDIR/neoproot-um" ]; then
		mv -f "$BINDIR/neoproot-um" "$BINDIR/neoproot-um.stale-$(date +%Y%m%d-%H%M%S)"
		echo "==> 旧的 neoproot-um 已改名（本次未编译 UML 后端）"
	fi
fi

if [ "$WITH_SHIM" = 1 ]; then
	SHIM_SOURCE=$HERE/stat-shim/$SHIM_NAME
	if [ ! -f "$SHIM_SOURCE" ]; then
		echo "==> stat shim 未构建，先跑 stat-shim/build.sh" >&2
		sh "$HERE/stat-shim/build.sh"
	fi
	mkdir -p "$LIBEXECDIR"
	cp -f "$SHIM_SOURCE" "$LIBEXECDIR/$SHIM_NAME"
	chmod 644 "$LIBEXECDIR/$SHIM_NAME"
	echo "==> shim 已安装: $LIBEXECDIR/$SHIM_NAME"

	for rootfs in $SHIM_ROOTFS; do
		case "$rootfs" in
		/*) ;;
		*) echo "==> 跳过非绝对路径的 rootfs: $rootfs" >&2; continue ;;
		esac
		if [ ! -d "$rootfs" ]; then
			echo "==> 跳过不存在的 rootfs: $rootfs" >&2
			continue
		fi
		mkdir -p "$rootfs$SHIM_GUEST_DIR"
		cp -f "$SHIM_SOURCE" "$rootfs$SHIM_GUEST_DIR/$SHIM_NAME"
		chmod 755 "$rootfs$SHIM_GUEST_DIR/$SHIM_NAME"
		echo "==> shim 已放入容器: $rootfs$SHIM_GUEST_DIR/$SHIM_NAME"
	done
else
	echo "==> 跳过 shim（--without-shim）"
fi

"$BINDIR/neoproot" --version 2>/dev/null || true
