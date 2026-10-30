#!/bin/sh
# Build and install neoproot, asking each question in turn.
#
# Usage: sh install.sh [options] [PREFIX]
#
# Run with no options on a terminal and it walks you through the choices the
# way "pnpm create vite" does: a short list, a default in brackets, and the
# summary before anything is written.  Piped into a shell (curl | sh) there is
# nobody to answer, so it falls back to the defaults and says so.
#
#   --prefix=DIR        install prefix (DIR/bin, DIR/libexec/neoproot)
#   --with-um           build and install the UML backend
#   --without-um        fast backend only
#   --with-shim         install the stat shim
#   --without-shim      do not install the shim
#   --shim-rootfs=DIR   also put the shim in this container rootfs (repeatable)
#   --um-kernel=FILE    kernel to install as libexec/neoproot/um/linux-bionic
#   --um-stub=FILE      stub_exe for it
#   --um-net=FILE       umnet (optional, needed by --net)
#   --um-passt=FILE     passt-bionic (optional, needed by --net)
#   --interactive       ask even when stdin is not a terminal
#   --non-interactive   never ask; use the flags and defaults
#   --help              show this text
#
# Why --um-kernel exists: neoproot does not contain a kernel, it execs one.  An
# install with the um backend but no kernel fails at the first --backend=um with
# "set --kernel/--stub", which reads like a broken install.  Installing the
# kernel here keeps the two together, and neoproot finds it by itself.
set -eu

WITH_UM=
WITH_SHIM=
PREFIX_DIR=
SHIM_ROOTFS=
UM_KERNEL=
UM_STUB=
UM_NET=
UM_PASST=
INTERACTIVE=auto
SHIM_GUEST_DIR=/opt/neoproot
SHIM_NAME=libstatfast.so

usage() {
	cat <<'USAGE'
Usage: sh install.sh [options] [PREFIX]

Run without options on a terminal for the guided install.

  --prefix=DIR        install prefix (default: $PREFIX)
  --with-um           build and install the UML backend (default: yes)
  --without-um        fast backend only: no UML objects, no neoproot-um
  --with-shim         install the stat shim (default: yes)
  --without-shim      do not install the shim
  --shim-rootfs=DIR   also copy the shim into this container rootfs, at
                      /opt/neoproot/libstatfast.so (repeatable)
  --um-kernel=FILE    kernel to install at libexec/neoproot/um/linux-bionic
  --um-stub=FILE      stub_exe that goes with that kernel
  --um-net=FILE       umnet, needed by --net (optional)
  --um-passt=FILE     passt-bionic, needed by --net (optional)
  --interactive       ask even when stdin is not a terminal
  --non-interactive   never ask; use the flags and defaults
  --help              show this text

Examples:
  sh install.sh                                   # guided
  sh install.sh --non-interactive                 # defaults, no questions
  sh install.sh --without-um                      # smallest neoproot
  sh install.sh --um-kernel=kernel/linux-bionic \
                --um-stub=kernel/stub_exe \
                --shim-rootfs=~/alarm-rootfs      # everything, one command
USAGE
}

for argument do
	case "$argument" in
	--with-um) WITH_UM=1 ;;
	--without-um) WITH_UM=0 ;;
	--with-shim) WITH_SHIM=1 ;;
	--without-shim) WITH_SHIM=0 ;;
	--prefix=*) PREFIX_DIR=${argument#--prefix=} ;;
	--shim-rootfs=*) SHIM_ROOTFS="$SHIM_ROOTFS ${argument#--shim-rootfs=}" ;;
	--um-kernel=*) UM_KERNEL=${argument#--um-kernel=} ;;
	--um-stub=*) UM_STUB=${argument#--um-stub=} ;;
	--um-net=*) UM_NET=${argument#--um-net=} ;;
	--um-passt=*) UM_PASST=${argument#--um-passt=} ;;
	--interactive) INTERACTIVE=yes ;;
	--non-interactive|-y|--yes) INTERACTIVE=no ;;
	--help|-h) usage; exit 0 ;;
	-*) echo "错误: 未知参数 $argument（sh install.sh --help）" >&2; exit 2 ;;
	*) PREFIX_DIR=$argument ;;
	esac
done

# ---------------------------------------------------------------------------
# The questions
#
# Every prompt has a default, empty input takes it, and the answer is read from
# stdin so the same code works for a person and for a script feeding answers.
# ---------------------------------------------------------------------------

say() { printf '%s\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

ask_text() {
	# $1 question, $2 default.  Prints the answer.
	_question=$1
	_default=$2
	if [ -n "$_default" ]; then
		printf '? %s (%s): ' "$_question" "$_default" >&2
	else
		printf '? %s: ' "$_question" >&2
	fi
	IFS= read -r _answer || _answer=
	if [ -z "$_answer" ]; then _answer=$_default; fi
	printf '%s\n' "$_answer"
}

ask_choice() {
	# $1 question, $2 default number, $3... options.  Prints the chosen number.
	_question=$1
	_default=$2
	shift 2
	printf '? %s\n' "$_question" >&2
	_number=0
	for _option do
		_number=$((_number + 1))
		if [ "$_number" = "$_default" ]; then
			printf '    %s) %s  (默认)\n' "$_number" "$_option" >&2
		else
			printf '    %s) %s\n' "$_number" "$_option" >&2
		fi
	done
	while :; do
		printf '  选择 [%s]: ' "$_default" >&2
		IFS= read -r _answer || _answer=
		if [ -z "$_answer" ]; then _answer=$_default; fi
		case "$_answer" in
		''|*[!0-9]*) printf '  请输入编号\n' >&2; continue ;;
		esac
		if [ "$_answer" -ge 1 ] && [ "$_answer" -le "$_number" ]; then
			printf '%s\n' "$_answer"
			return 0
		fi
		printf '  请输入 1 到 %s 之间的编号\n' "$_number" >&2
	done
}

if [ "$INTERACTIVE" = auto ]; then
	if [ -t 0 ]; then INTERACTIVE=yes; else INTERACTIVE=no; fi
fi

if [ "$INTERACTIVE" = no ]; then
	[ -n "$WITH_UM" ] || WITH_UM=1
	[ -n "$WITH_SHIM" ] || WITH_SHIM=1
	if [ -z "$PREFIX_DIR" ]; then PREFIX_DIR=${PREFIX:-}; fi
	if [ -z "$PREFIX_DIR" ]; then
		echo "错误: 非交互安装需要 --prefix=DIR 或 \$PREFIX" >&2
		exit 2
	fi
	say "==> 非交互安装（--non-interactive 或 stdin 不是终端），使用默认值"
else
	bold ""
	bold "neoproot 安装"
	bold ""
	say "  每个问题直接回车即用默认值。"
	say ""

	if [ -z "$PREFIX_DIR" ]; then
		_default_prefix=${PREFIX:-/usr/local}
		PREFIX_DIR=$(ask_text "安装到哪里（bin、libexec 会在其下）" "$_default_prefix")
	fi

	if [ -z "$WITH_UM" ]; then
		_choice=$(ask_choice "要不要 UML 后端" 1 \
			"编译进 neoproot（可用 --backend=um，多 28 KB）" \
			"不要，只留 fast 后端（更小）")
		if [ "$_choice" = 1 ]; then WITH_UM=1; else WITH_UM=0; fi
	fi

	if [ "$WITH_UM" = 1 ] && [ -z "$UM_KERNEL" ]; then
		say ""
		say "  neoproot 本身不含内核，--backend=um 需要另外的内核文件。"
		UM_KERNEL=$(ask_text "UML 内核路径（留空稍后自己放）" "")
		if [ -n "$UM_KERNEL" ] && [ -z "$UM_STUB" ]; then
			UM_STUB=$(ask_text "stub_exe 路径（内核旁边那个）" "")
		fi
		if [ -n "$UM_KERNEL" ] && [ ! -f "$UM_KERNEL" ]; then
			say "  注意: $UM_KERNEL 不存在，跳过内核安装"
			UM_KERNEL=
			UM_STUB=
		fi
	fi

	if [ -z "$WITH_SHIM" ]; then
		_choice=$(ask_choice "要不要 stat shim（加速 stat 系列系统调用）" 1 \
			"要" \
			"不要")
		if [ "$_choice" = 1 ]; then WITH_SHIM=1; else WITH_SHIM=0; fi
	fi

	if [ "$WITH_SHIM" = 1 ] && [ -z "$SHIM_ROOTFS" ]; then
		say ""
		say "  shim 是 guest 侧的库，装在宿主机上对容器没用。"
		_rootfs=$(ask_text "把 shim 放进哪个容器 rootfs（留空跳过）" "")
		if [ -n "$_rootfs" ]; then SHIM_ROOTFS=" $_rootfs"; fi
	fi

	say ""
	bold "即将执行"
	say "  安装前缀   : $PREFIX_DIR"
	if [ "$WITH_UM" = 1 ]; then
		say "  UML 后端   : 编译并安装"
		if [ -n "$UM_KERNEL" ]; then
			say "  内核       : $UM_KERNEL"
			say "  stub       : ${UM_STUB:-（无）}"
		else
			say "  内核       : 未提供（--backend=um 暂时不可用）"
		fi
	else
		say "  UML 后端   : 不安装"
	fi
	if [ "$WITH_SHIM" = 1 ]; then
		say "  stat shim  : 安装"
		say "  放进容器   : ${SHIM_ROOTFS:-（不）}"
	else
		say "  stat shim  : 不安装"
	fi
	say ""
	_confirm=$(ask_text "继续？(y/N)" "n")
	case "$_confirm" in
	y|Y|yes|YES) ;;
	*) say "已取消"; exit 1 ;;
	esac
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

BINDIR=$PREFIX_DIR/bin
LIBEXECDIR=$PREFIX_DIR/libexec/neoproot
UM_DIR=$LIBEXECDIR/um
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# build.sh and the src/ paths it produces are relative to the repository, and
# "sh /somewhere/install.sh" may be run from anywhere.
cd "$HERE"

mkdir -p "$BINDIR" "$LIBEXECDIR"

if [ "$WITH_UM" = 1 ]; then
	sh "$HERE/build.sh" --with-um
else
	sh "$HERE/build.sh" --without-um
fi

install_atomically() {
	_source_file=$1
	_target=$2
	if [ -e "$_target" ]; then
		_backup=$_target.prev-$(date +%Y%m%d-%H%M%S)
		cp -a "$_target" "$_backup"
		echo "==> 旧文件备份: $_backup"
	fi
	_stage=$_target.install.$$
	trap 'rm -f "$_stage"' EXIT INT TERM
	cp "$_source_file" "$_stage"
	chmod 755 "$_stage"
	mv -f "$_stage" "$_target"
	trap - EXIT INT TERM
}

install_atomically "$HERE/src/neoproot" "$BINDIR/neoproot"
echo "==> 安装完成: $BINDIR/neoproot"

if [ "$WITH_UM" = 1 ]; then
	# neoproot carries the UML supervisor itself; the second name is a link, so
	# "neoproot-um session start ..." reaches the same code without a second copy.
	ln -sf neoproot "$BINDIR/neoproot-um"
	echo "==> 安装完成: $BINDIR/neoproot-um -> neoproot"
else
	if [ -e "$BINDIR/neoproot-um" ]; then
		mv -f "$BINDIR/neoproot-um" "$BINDIR/neoproot-um.stale-$(date +%Y%m%d-%H%M%S)"
		echo "==> 旧的 neoproot-um 已改名（本次未编译 UML 后端）"
	fi
fi

if [ "$WITH_UM" = 1 ]; then
	if [ -n "$UM_KERNEL" ]; then
		if [ ! -f "$UM_KERNEL" ]; then
			echo "错误: 内核不存在: $UM_KERNEL" >&2
			exit 1
		fi
		mkdir -p "$UM_DIR"
		cp -f "$UM_KERNEL" "$UM_DIR/linux-bionic"
		# The kernel is exec'd, not read: it needs the execute bit.
		chmod 755 "$UM_DIR/linux-bionic"
		echo "==> 内核已安装: $UM_DIR/linux-bionic"
		if [ -n "$UM_STUB" ]; then
			if [ ! -f "$UM_STUB" ]; then
				echo "错误: stub 不存在: $UM_STUB" >&2
				exit 1
			fi
			cp -f "$UM_STUB" "$UM_DIR/stub_exe"
			chmod 755 "$UM_DIR/stub_exe"
			echo "==> stub 已安装: $UM_DIR/stub_exe"
		else
			echo "==> 注意: 没有 stub_exe，--backend=um 会失败。用 --um-stub=FILE 补上" >&2
		fi
		if [ -n "$UM_NET" ] && [ -f "$UM_NET" ]; then
			cp -f "$UM_NET" "$UM_DIR/umnet"
			chmod 755 "$UM_DIR/umnet"
			echo "==> umnet 已安装: $UM_DIR/umnet"
		fi
		if [ -n "$UM_PASST" ] && [ -f "$UM_PASST" ]; then
			cp -f "$UM_PASST" "$UM_DIR/passt-bionic"
			chmod 755 "$UM_DIR/passt-bionic"
			echo "==> passt 已安装: $UM_DIR/passt-bionic"
		fi
	else
		echo "==> 注意: 已安装 um 后端，但没有装内核。" >&2
		echo "    --backend=um 需要内核文件，否则会报 set --kernel/--stub。" >&2
		echo "    补装: sh install.sh --um-kernel=内核 --um-stub=stub_exe" >&2
		echo "    或手动放到: $UM_DIR/linux-bionic 和 $UM_DIR/stub_exe" >&2
	fi
fi

if [ "$WITH_SHIM" = 1 ]; then
	SHIM_SOURCE=$HERE/stat-shim/$SHIM_NAME
	if [ ! -f "$SHIM_SOURCE" ]; then
		echo "==> stat shim 未构建，先跑 stat-shim/build.sh" >&2
		sh "$HERE/stat-shim/build.sh"
	fi
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

echo ""
"$BINDIR/neoproot" --version 2>/dev/null || true
if [ "$WITH_UM" = 1 ] && [ -n "$UM_KERNEL" ]; then
	echo "==> 现在可以直接: neoproot --backend=um -r <镜像> --cow-file=<cow> -- <命令>"
fi
