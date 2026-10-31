#!/bin/sh
# neoproot installer - https://github.com/Raymer8639/neoproot
#
#   Termux (Android, bionic): builds the binary from the tagged source, because
#                             the published release binaries are ARM64 glibc.
#   ARM64 Linux (glibc):      downloads the matching release binary, verifies
#                             it against SHA256SUMS and installs it.
#
# The script only writes into a bin directory. It never touches a container
# rootfs: the stat-shim library belongs to the guest and must be built there
# (see stat-shim/README.md).
#
# Usage:
#   curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
#   sh install.sh --version v5.10.7 --prefix "$HOME/.local" --portable
set -eu

REPO="Raymer8639/neoproot"
VERSION="latest"
PREFIX_DIR=""
PORTABLE=0
MODE="auto"   # auto | termux | linux  (NEOPROOT_INSTALL_MODE overrides auto)
ACTION=install  # install | update
FORCE_UPDATE=0
LOG=""

LANG_CHOICE=""   # en | zh   (asked first, or from --lang / NEOPROOT_LANG)
ASSUME_YES=0
SHIM_ROOTFS=""
UM_KERNEL_OVERRIDE=""
WITH_UM=""
WITH_SHIM=""
INTERACTIVE=auto

# Every message the script prints to a person goes through t(), so the language
# question at the start actually changes what follows.  Two languages are worth
# having: the project's own documentation is written in both, and a Chinese
# user reading English prompts is the case that prompted this.
t() { # t KEY  -- prints the message for $LANG_CHOICE
	_key=$1
	case "$LANG_CHOICE:$_key" in
	zh:lang_q)        printf '%s' "选择语言 / Choose language" ;;
	zh:lang_1)        printf '%s' "中文" ;;
	zh:lang_2)        printf '%s' "English" ;;
	zh:welcome)       printf '%s' "neoproot 安装" ;;
	zh:each_default)  printf '%s' "每个问题直接回车即用默认值。" ;;
	zh:q_prefix)      printf '%s' "安装到哪里" ;;
	zh:q_um)          printf '%s' "要不要 UML 后端" ;;
	zh:um_yes)        printf '%s' "要（可用 --backend=um 启动文件系统镜像）" ;;
	zh:um_no)         printf '%s' "不要（只留 fast 后端，更小）" ;;
	zh:q_kernel)      printf '%s' "UML 内核路径（留空则跳过，之后可补）" ;;
	zh:q_shim)        printf '%s' "要不要 stat shim（加速 stat 系列系统调用）" ;;
	zh:shim_yes)      printf '%s' "要" ;;
	zh:shim_no)       printf '%s' "不要" ;;
	zh:q_rootfs)      printf '%s' "把 shim 放进哪个容器 rootfs（留空跳过）" ;;
	zh:summary)       printf '%s' "即将执行" ;;
	zh:s_prefix)      printf '%s' "安装前缀" ;;
	zh:s_um)          printf '%s' "UML 后端" ;;
	zh:s_shim)        printf '%s' "stat shim" ;;
	zh:s_lang)        printf '%s' "语言" ;;
	zh:q_confirm)     printf '%s' "继续？(y/N)" ;;
	zh:cancelled)     printf '%s' "已取消" ;;
	zh:choose)        printf '%s' "选择" ;;
	zh:default)       printf '%s' "默认" ;;
	zh:um_note)       printf '%s' "将自动下载内核、stub_exe、umnet、passt（约 15MB）。" ;;
	zh:shim_note)     printf '%s' "shim 是 guest 侧的库，装在宿主机上对容器没用。" ;;
	zh:need_number)   printf '%s' "请输入编号" ;;
	zh:not_current)   printf '%s' "没有任何安装记录" ;;
	zh:already)       printf '%s' "已是最新版本" ;;
	zh:updating)      printf '%s' "正在更新" ;;
	zh:runtime_only)  printf '%s' "只更新运行时" ;;
	en:lang_q)        printf '%s' "Choose language" ;;
	en:lang_1)        printf '%s' "中文" ;;
	en:lang_2)        printf '%s' "English" ;;
	en:welcome)       printf '%s' "neoproot install" ;;
	en:each_default)  printf '%s' "Press Enter to accept the default for every question." ;;
	en:q_prefix)      printf '%s' "Install where" ;;
	en:q_um)          printf '%s' "Include the UML backend" ;;
	en:um_yes)        printf '%s' "yes (--backend=um can boot a filesystem image)" ;;
	en:um_no)         printf '%s' "no (fast backend only, smaller)" ;;
	en:q_kernel)      printf '%s' "UML kernel path (blank to skip and add later)" ;;
	en:q_shim)        printf '%s' "Include the stat shim (faster stat syscalls)" ;;
	en:shim_yes)      printf '%s' "yes" ;;
	en:shim_no)       printf '%s' "no" ;;
	en:q_rootfs)      printf '%s' "Copy the shim into which container rootfs (blank to skip)" ;;
	en:summary)       printf '%s' "About to install" ;;
	en:s_prefix)      printf '%s' "prefix" ;;
	en:s_um)          printf '%s' "UML backend" ;;
	en:s_shim)        printf '%s' "stat shim" ;;
	en:s_lang)        printf '%s' "language" ;;
	en:q_confirm)     printf '%s' "Continue? (y/N)" ;;
	en:cancelled)     printf '%s' "cancelled" ;;
	en:choose)        printf '%s' "choose" ;;
	en:default)       printf '%s' "default" ;;
	en:um_note)       printf '%s' "the kernel, stub_exe, umnet and passt will be downloaded (about 15 MB)." ;;
	en:shim_note)     printf '%s' "the shim is a guest-side library; the host copy does nothing for a container." ;;
	en:need_number)   printf '%s' "enter a number" ;;
	en:not_current)   printf '%s' "no record of a previous install" ;;
	en:already)       printf '%s' "already at" ;;
	en:updating)      printf '%s' "updating" ;;
	en:runtime_only)  printf '%s' "runtime only" ;;
	*)                printf '%s' "$_key" ;;
	esac
}

# Where the choices of the last install are kept, so --update can reuse them
# instead of asking again.  Written by a normal install, read by --update.
state_file() {
	printf '%s/libexec/neoproot/install-state' "$1"
}

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'neoproot: %s\n' "$*" >&2; }
die()  { printf 'neoproot: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
neoproot installer

Usage: sh install.sh [options]

Options:
  --version TAG   install a specific release (default: the latest one)
  --prefix DIR    install prefix; the binary goes to DIR/bin
                  (default: Termux $PREFIX, elsewhere $HOME/.local)
  --portable      ARM64 Linux only: use neoproot-portable (armv8-a baseline)
  --force         with --update: reinstall even when the version is current
  --update        bring an existing install up to date: replace the binary and
                  the UML runtime, keep every option you chose before, and do
                  nothing if you are already current
  --mode MODE     force the install mode: auto (default), termux or linux
  --lang LANG     en or zh; asked first when not given
  --with-um / --without-um      include the UML backend (default: ask)
  --with-shim / --without-shim  include the stat shim (default: ask)
  --shim-rootfs DIR             copy the shim into this container rootfs
  -y, --yes       accept every default, ask nothing
  --interactive / --non-interactive  force or suppress the questions
                  (also settable with NEOPROOT_INSTALL_MODE)
  -h, --help      show this help

What it does:
  Termux  installs clang/make/llvm/binutils/pkg-config/libtalloc/git if needed,
          clones the tagged source, builds it and installs $PREFIX/bin/neoproot
          (the previous binary is kept as neoproot.prev-<timestamp>).
  Linux   downloads neoproot (or neoproot-portable) plus SHA256SUMS from the
          release, verifies the checksum and installs DIR/bin/neoproot.

Both paths back up an existing binary before replacing it. Source builds never
come from the release: those assets are glibc builds and will not run as the
Termux Android binary.
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
		--version) [ $# -ge 2 ] || die "--version needs an argument"; VERSION=$2; shift 2 ;;
		--prefix)  [ $# -ge 2 ] || die "--prefix needs an argument";  PREFIX_DIR=$2; shift 2 ;;
		--portable) PORTABLE=1; shift ;;
		--update) ACTION=update; shift ;;
		--force) FORCE_UPDATE=1; shift ;;
		--mode) [ $# -ge 2 ] || die "--mode needs an argument"; MODE=$2; shift 2 ;;
		--lang) [ $# -ge 2 ] || die "--lang needs an argument"; LANG_CHOICE=$2; shift 2 ;;
		--shim-rootfs) [ $# -ge 2 ] || die "--shim-rootfs needs an argument"; SHIM_ROOTFS=$2; shift 2 ;;
		--with-um) WITH_UM=1; shift ;;
		--without-um) WITH_UM=0; shift ;;
		--with-shim) WITH_SHIM=1; shift ;;
		--without-shim) WITH_SHIM=0; shift ;;
		-y|--yes) ASSUME_YES=1; shift ;;
		--interactive) INTERACTIVE=yes; shift ;;
		--non-interactive) INTERACTIVE=no; shift ;;
		-h|--help) usage; exit 0 ;;
		*) die "unknown option: $1 (try --help)" ;;
	esac
done

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # fetch URL OUTFILE
	if have curl; then curl -fsSL --retry 3 -o "$2" "$1"
	elif have wget; then wget -q -O "$2" "$1"
	else die "curl or wget is required"; fi
}

fetch_stdout() { # fetch_stdout URL
	if have curl; then curl -fsSL --retry 3 "$1"
	elif have wget; then wget -q -O - "$1"
	else die "curl or wget is required"; fi
}

resolve_tag() {
	if [ "$VERSION" != "latest" ]; then printf '%s' "$VERSION"; return 0; fi
	json=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest") \
		|| die "cannot reach the GitHub API; pass --version vX.Y.Z instead"
	tag=$(printf '%s\n' "$json" \
		| sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$tag" ] || die "could not determine the latest release; pass --version vX.Y.Z"
	printf '%s' "$tag"
}

check_arch() {
	case "$(uname -m)" in
		aarch64|arm64) ;;
		*) die "neoproot targets 64-bit ARM only (found $(uname -m))" ;;
	esac
}

install_binary() { # install_binary NEW_BINARY PREFIX
	# Every variable here is prefixed: POSIX sh has no locals, and clobbering the
	# caller's workdir would make the EXIT trap clean up the wrong path (leaking
	# the download/build directory).
	bin_src=$1
	bin_prefix=$2
	[ -n "$bin_prefix" ] || die "empty install prefix"
	bin_dir=$bin_prefix/bin
	mkdir -p "$bin_dir" || die "cannot create $bin_dir"
	bin_target=$bin_dir/neoproot
	if [ -e "$bin_target" ]; then
		bin_backup=$bin_target.prev-$(date +%Y%m%d-%H%M%S)
		cp -a "$bin_target" "$bin_backup"
		log "previous binary kept as $bin_backup"
	fi
	bin_stage=$bin_dir/.neoproot.new.$$
	cp "$bin_src" "$bin_stage" && chmod 755 "$bin_stage" && mv -f "$bin_stage" "$bin_target" \
		|| die "cannot install into $bin_dir"
	log "installed $bin_target"
	"$bin_target" --version 2>/dev/null || warn "installed binary did not report a version"
}

# Install the UML runtime beside the binary.
#
# The runtime is not built here and it is not published here: a kernel belongs
# to linux-um-arm64 and passt belongs to passt-android, so each repository
# releases its own artifacts and this function fetches from the source.  That
# keeps neoproot's CI about neoproot -- cross-compiling somebody else's kernel
# on every neoproot commit is slow and puts the version of one project in the
# release of another.
#
# The pins below are what this neoproot release was tested against.  A mismatch
# is a real problem (the kernel has to agree with um-init, umnet and passt), so
# they are constants rather than "latest".
UM_KERNEL_REPO=Raymer8639/linux-um-arm64
UM_KERNEL_TAG=${NEOPROOT_UM_KERNEL_TAG:-um-arm64-v0.3.0}
PASST_REPO=Raymer8639/passt-android
PASST_TAG=${NEOPROOT_UM_PASST_TAG:-v0.3.1}

# Record what this install chose, for --update.
#
# Written after the files are in place: a state file that claims a version the
# disk does not have would make the next --update think it was already current.
write_state() { # write_state PREFIX TAG PORTABLE
	_ws_prefix=$1
	_ws_tag=$2
	_ws_portable=$3
	_ws_dir=$_ws_prefix/libexec/neoproot
	_ws_file=$_ws_dir/install-state
	_ws_with_um=1
	[ "${FORCE_NO_UM:-0}" = 1 ] && _ws_with_um=0
	[ "${WITH_UM:-1}" = 1 ] || _ws_with_um=0
	mkdir -p "$_ws_dir" 2>/dev/null || return 0
	{
		printf 'version=%s\n' "$_ws_tag"
		printf 'prefix=%s\n' "$_ws_prefix"
		printf 'portable=%s\n' "$_ws_portable"
		printf 'with_um=%s\n' "$_ws_with_um"
		printf 'um_kernel_tag=%s\n' "$UM_KERNEL_TAG"
		printf 'um_passt_tag=%s\n' "$PASST_TAG"
		printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$_ws_file.tmp" 2>/dev/null && mv -f "$_ws_file.tmp" "$_ws_file"
	return 0
}

# Put the shim into a container rootfs, which is the only place it can work.
_install_shim_into() { # _install_shim_into ROOTFS
	_si_rootfs=$1
	case "$_si_rootfs" in
	/*) ;;
	*) warn "--shim-rootfs needs an absolute path: $_si_rootfs"; return 0 ;;
	esac
	[ -d "$_si_rootfs" ] || { warn "no such rootfs: $_si_rootfs"; return 0; }
	_si_src=
	for _si_candidate in \
		"$_si_rootfs/opt/neoproot/libstatfast.so" \
		"${PREFIX:-/nonexistent}/libexec/neoproot/libstatfast.so"; do
		[ -r "$_si_candidate" ] && _si_src=$_si_candidate && break
	done
	if [ -z "$_si_src" ]; then
		# The shim ships as a release asset, so fetch it rather than requiring
		# a source tree next to the installer.
		_si_tmp=$(mktemp "${TMPDIR:-/tmp}/libstatfast.XXXXXX") || return 0
		_si_tag=$(resolve_tag)
		if fetch "https://github.com/$REPO/releases/download/$_si_tag/libstatfast.so" "$_si_tmp" 2>/dev/null; then
			_si_src=$_si_tmp
		else
			rm -f "$_si_tmp"
			warn "could not fetch libstatfast.so; the shim was not installed into $_si_rootfs"
			return 0
		fi
	fi
	mkdir -p "$_si_rootfs/opt/neoproot" 2>/dev/null || return 0
	cp -f "$_si_src" "$_si_rootfs/opt/neoproot/libstatfast.so" 2>/dev/null || return 0
	chmod 755 "$_si_rootfs/opt/neoproot/libstatfast.so" 2>/dev/null
	log "shim installed into $_si_rootfs/opt/neoproot/libstatfast.so"
	return 0
}

install_um_runtime() {
	_prefix=$1
	_um_dir=$_prefix/libexec/neoproot/um
	_missing=

	mkdir -p "$_um_dir" 2>/dev/null || true

	# linux-um-arm64 publishes the kernel, its SMP build, the stub, umnet and
	# passt-bionic in one release; they are built together and only make sense
	# together.
	# A kernel the user pointed at wins over the published one: it is the only
	# way to use a build for a device profile no release covers.
	if [ -n "${UM_KERNEL_OVERRIDE:-}" ] && [ -f "${UM_KERNEL_OVERRIDE:-}" ]; then
		cp -f "$UM_KERNEL_OVERRIDE" "$_um_dir/linux-bionic" &&
			chmod 755 "$_um_dir/linux-bionic" &&
			log "kernel from $UM_KERNEL_OVERRIDE"
	fi
	_kernel_base="https://github.com/$UM_KERNEL_REPO/releases/download/$UM_KERNEL_TAG"
	for _name in linux-bionic stub_exe umnet passt-bionic; do
		# Skip what the override already provided.
		[ "$_name" = linux-bionic ] && [ -n "${UM_KERNEL_OVERRIDE:-}" ] &&
			[ -f "${UM_KERNEL_OVERRIDE:-}" ] && continue
		if fetch "$_kernel_base/$_name" "$_um_dir/$_name" 2>/dev/null; then
			chmod 755 "$_um_dir/$_name"
			log "UML runtime: $_name"
		else
			_missing="$_missing $_name"
		fi
	done

	if [ -n "$_missing" ]; then
		warn "could not fetch from $UM_KERNEL_REPO@$UM_KERNEL_TAG:$_missing"
		warn "put them in $_um_dir, or set NEOPROOT_UM_KERNEL_TAG to a release that has them"
	else
		log "UML runtime installed into $_um_dir"
	fi

	# passt also has a release of its own.  passt-bionic above is the copy that
	# linux-um-arm64 shipped with its kernel; this one is the standalone build,
	# and it is only a fallback for a caller who wants the newest passt rather
	# than the matched set.
	if [ ! -e "$_um_dir/passt-bionic" ]; then
		_passt_base="https://github.com/$PASST_REPO/releases/download/$PASST_TAG"
		if fetch "$_passt_base/passt-android-arm64" "$_um_dir/passt-bionic" 2>/dev/null; then
			chmod 755 "$_um_dir/passt-bionic"
			log "passt-bionic from $PASST_REPO@$PASST_TAG"
		else
			warn "--net needs passt-bionic; could not fetch it from $PASST_REPO@$PASST_TAG"
		fi
	fi
	return 0
}

next_steps() {
	cat <<'NEXT'

Next steps:
  * neoproot --version             # confirm the install
  * Launch a container the same way you configure proot today; the CLI follows
    official PRoot conventions.
  * Faster metadata: add --seccomp-notify, and --stat-shim=<guest lib> once the
    shim is built inside the container (see stat-shim/README.md). The tracer and
    the shim must come from the same release; restart running containers after
    updating either one.
NEXT
}

# Real Termux runs on bionic: Android's linker is at its Android path and the
# Termux package manager exists. Never trust an inherited $PREFIX/TERMUX_VERSION
# alone -- a proot container started from Termux inherits both, and its glibc
# userland needs the release binary, not a source build.
is_termux() {
	[ -x /system/bin/linker64 ] || [ -x /system/bin/linker ] || return 1
	have pkg || return 1
	[ -n "${PREFIX-}" ] || return 1
	[ -d "${PREFIX}/bin" ] || return 1
	return 0
}

[ "$MODE" = "auto" ] && MODE=${NEOPROOT_INSTALL_MODE:-auto}
case "$MODE" in auto|termux|linux) ;; *) die "--mode must be auto, termux or linux" ;; esac
if [ "$MODE" = "auto" ]; then
	if is_termux; then MODE=termux; else MODE=linux; fi
fi
[ "$MODE" = "termux" ] && ! is_termux && warn "forced termux mode outside Termux: the build may fail"

# ---------------------------------------------------------------------------
# --update: replace what this script owns, keep what the user chose
#
# The state file a previous install wrote says which prefix and which options
# were used, so an update does not have to ask again -- and must not silently
# switch someone from a portable build to a release one, or move their files.
# ---------------------------------------------------------------------------
read_state() { # read_state PREFIX -> prints saved key=value lines
	_state=$(state_file "$1")
	[ -r "$_state" ] && cat "$_state"
	return 0
}

if [ "$ACTION" = "update" ]; then
	# The prefix has to come from somewhere: the state file of the install we
	# are updating, or an explicit --prefix.
	if [ -z "$PREFIX_DIR" ]; then
		for _candidate in "${PREFIX:-}" "${HOME:-}/.local" /usr/local; do
			[ -n "$_candidate" ] || continue
			[ -r "$(state_file "$_candidate")" ] && PREFIX_DIR=$_candidate && break
		done
	fi
	[ -n "$PREFIX_DIR" ] ||
		die "cannot tell which install to update; pass --prefix DIR"

	_saved=$(read_state "$PREFIX_DIR")
	if [ -z "$_saved" ]; then
		warn "no record of a previous install in $PREFIX_DIR"
		warn "an update replaces the binary and the runtime; run without --update to choose options"
	fi

	# Reuse the *choices* from the record -- portable, whether the um backend
	# was installed.  The runtime tags are not taken from it: an update moves
	# them forward to what this script knows, which is the whole point.  They
	# are read only to decide whether the runtime on disk is behind.
	for _line in $_saved; do
		case "$_line" in
		portable=1) [ "$PORTABLE" = 0 ] && PORTABLE=1 ;;
		with_um=0) FORCE_NO_UM=1 ;;
		esac
	done

	tag=$(resolve_tag)
	# "Already current" is decided from the record, not from the file's mtime:
	# a copy or a backup restores the old one with a fresh timestamp.
	_installed_version=$(sed -n 's/^version=//p' "$(state_file "$PREFIX_DIR")" 2>/dev/null)
	if [ "$_installed_version" = "$tag" ] && [ "$FORCE_UPDATE" != 1 ]; then
		log "already at $tag (use --force to reinstall anyway)"
		# The runtime has its own tags, so it can be behind even when the
		# binary is current.  Only fetch it when the record says it differs.
		_saved_kernel=$(sed -n 's/^um_kernel_tag=//p' "$(state_file "$PREFIX_DIR")" 2>/dev/null)
		_saved_passt=$(sed -n 's/^um_passt_tag=//p' "$(state_file "$PREFIX_DIR")" 2>/dev/null)
		if [ "$MODE" != "termux" ] &&
		   { [ "$_saved_kernel" != "$UM_KERNEL_TAG" ] ||
		     [ "$_saved_passt" != "$PASST_TAG" ] ||
		     [ ! -e "$PREFIX_DIR/libexec/neoproot/um/linux-bionic" ]; }; then
			log "runtime: ${_saved_kernel:-none} -> $UM_KERNEL_TAG"
			install_um_runtime "$PREFIX_DIR"
			write_state "$PREFIX_DIR" "$tag" "$PORTABLE"
		else
			log "runtime: already at $UM_KERNEL_TAG"
		fi
		exit 0
	fi
	log "updating ${_installed_version:-an older build} -> $tag in $PREFIX_DIR"
	VERSION=$tag
	ACTION=install-replace
fi

# ---------------------------------------------------------------------------
# The questions
#
# Asked in the order that makes the answers useful: language first, because it
# changes every later prompt; then what to install; then where.  A terminal is
# required -- with stdin redirected (curl | sh) there is nobody to answer, so
# the defaults are used and the script says so rather than hanging.
# ---------------------------------------------------------------------------
ask_text() { # ask_text PROMPT DEFAULT
	_at_prompt=$1
	_at_default=$2
	if [ -n "$_at_default" ]; then
		printf '? %s (%s): ' "$_at_prompt" "$_at_default" >&2
	else
		printf '? %s: ' "$_at_prompt" >&2
	fi
	IFS= read -r _at_answer || _at_answer=
	[ -n "$_at_answer" ] || _at_answer=$_at_default
	printf '%s\n' "$_at_answer"
}

ask_choice() { # ask_choice PROMPT DEFAULT OPTION...
	_ac_prompt=$1
	_ac_default=$2
	shift 2
	printf '? %s\n' "$_ac_prompt" >&2
	_ac_n=0
	for _ac_opt do
		_ac_n=$((_ac_n + 1))
		if [ "$_ac_n" = "$_ac_default" ]; then
			printf '    %s) %s  [%s]\n' "$_ac_n" "$_ac_opt" "$(t default)" >&2
		else
			printf '    %s) %s\n' "$_ac_n" "$_ac_opt" >&2
		fi
	done
	while :; do
		printf '  %s [%s]: ' "$(t choose)" "$_ac_default" >&2
		IFS= read -r _ac_answer || _ac_answer=
		[ -n "$_ac_answer" ] || _ac_answer=$_ac_default
		case "$_ac_answer" in
		''|*[!0-9]*) printf '  %s\n' "$(t need_number)" >&2; continue ;;
		esac
		if [ "$_ac_answer" -ge 1 ] && [ "$_ac_answer" -le "$_ac_n" ]; then
			printf '%s\n' "$_ac_answer"
			return 0
		fi
		printf '  1-%s\n' "$_ac_n" >&2
	done
}

if [ "$INTERACTIVE" = auto ]; then
	if [ -t 0 ] && [ "$ASSUME_YES" = 0 ]; then INTERACTIVE=yes; else INTERACTIVE=no; fi
fi

if [ -z "$LANG_CHOICE" ]; then LANG_CHOICE=${NEOPROOT_LANG:-}; fi
if [ -z "$LANG_CHOICE" ]; then
	case "${LC_ALL:-}${LC_MESSAGES:-}${LANG:-}" in
	*zh*|*ZH*) LANG_CHOICE=zh ;;
	*) LANG_CHOICE=en ;;
	esac
fi

if [ "$INTERACTIVE" = yes ] && [ "$ACTION" != "update" ]; then
	if [ -z "${NEOPROOT_LANG:-}" ]; then
		_lang_choice=$(ask_choice "$(t lang_q)" "$([ "$LANG_CHOICE" = zh ] && echo 1 || echo 2)" \
			"$(t lang_1)" "$(t lang_2)")
		[ "$_lang_choice" = 1 ] && LANG_CHOICE=zh || LANG_CHOICE=en
	fi
	printf '\n'
	printf '%s\n' "$(t welcome)"
	printf '  %s\n\n' "$(t each_default)"

	if [ -z "$PREFIX_DIR" ]; then
		PREFIX_DIR=$(ask_text "$(t q_prefix)" "${PREFIX:-/usr/local}")
	fi

	if [ -z "$WITH_UM" ]; then
		_um_choice=$(ask_choice "$(t q_um)" 1 "$(t um_yes)" "$(t um_no)")
		[ "$_um_choice" = 1 ] && WITH_UM=1 || WITH_UM=0
	fi

	# No kernel prompt.  Turning the backend on is the whole answer: the kernel,
	# stub, umnet and passt are fetched from the releases that publish them, so
	# asking for a path would be asking the user to do the installer's job.
	if [ "$WITH_UM" = 1 ]; then
		printf '\n  %s\n' "$(t um_note)"
	fi

	if [ -z "$WITH_SHIM" ]; then
		_shim_choice=$(ask_choice "$(t q_shim)" 1 "$(t shim_yes)" "$(t shim_no)")
		[ "$_shim_choice" = 1 ] && WITH_SHIM=1 || WITH_SHIM=0
	fi
	if [ "$WITH_SHIM" = 1 ] && [ -z "$SHIM_ROOTFS" ]; then
		printf '\n  %s\n' "$(t shim_note)"
		SHIM_ROOTFS=$(ask_text "$(t q_rootfs)" "")
	fi

	printf '\n%s\n' "$(t summary)"
	printf '  %-14s %s\n' "$(t s_prefix)" "$PREFIX_DIR"
	printf '  %-14s %s\n' "$(t s_lang)" "$LANG_CHOICE"
	printf '  %-14s %s\n' "$(t s_um)" "$([ "$WITH_UM" = 0 ] && echo no || echo yes)"
	printf '  %-14s %s\n' "$(t s_shim)" "$([ "$WITH_SHIM" = 0 ] && echo no || echo yes)"
	printf '\n'
	_confirm=$(ask_text "$(t q_confirm)" "n")
	case "$_confirm" in
	y|Y|yes|YES) ;;
	*) printf '%s\n' "$(t cancelled)" >&2; exit 1 ;;
	esac
else
	[ -n "$WITH_UM" ] || WITH_UM=1
	[ -n "$WITH_SHIM" ] || WITH_SHIM=1
fi

if [ "$MODE" = "termux" ]; then
	check_arch
	[ -n "${PREFIX-}" ] || die "PREFIX is not set; this does not look like Termux"
	tag=$(resolve_tag)
	log "building neoproot $tag for Termux (bionic)"
	# The Termux package that ships talloc.h and talloc.pc is libtalloc, not
	# talloc; only install when something is actually missing, so an existing
	# toolchain never depends on a fresh package index.
	missing=""
	have clang       || missing="$missing clang"
	have make        || missing="$missing make"
	have llvm-ar     || missing="$missing llvm"
	have as          || missing="$missing binutils"
	have pkg-config  || missing="$missing pkg-config"
	have git         || missing="$missing git"
	pkg-config --exists talloc 2>/dev/null || missing="$missing libtalloc"
	if [ -n "$missing" ]; then
		log "installing build dependencies:$missing"
		# shellcheck disable=SC2086
		pkg install -y $missing >/dev/null 2>&1 \
			|| die "pkg install failed; run 'pkg update' and try again"
	fi
	workdir=$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/neoproot-build.XXXXXX")
	trap 'rm -rf "$workdir"' EXIT INT TERM
	log "cloning $REPO at $tag"
	# An annotated tag is a tag object, not a commit: --branch accepts it but git
	# then warns "refs/tags/... is not a commit" and checks out the peeled commit
	# in detached HEAD, which reads like a failure to anyone watching.  Fetching
	# the tag explicitly and checking out its commit avoids the warning and makes
	# the intent obvious.
	git init --quiet "$workdir/repo" || die "git init failed"
	if ! ( cd "$workdir/repo" &&
	       git remote add origin "https://github.com/$REPO.git" &&
	       git fetch --quiet --depth 1 origin "refs/tags/$tag:refs/tags/$tag" &&
	       git checkout --quiet "refs/tags/$tag" ); then
		die "git fetch failed"
	fi
	LOG=${TMPDIR:-$PREFIX/tmp}/neoproot-build.log
	log "compiling (a few minutes on a phone; log: $LOG)"
	# WITH_UM from the questions decides whether the supervisor is compiled in.
	_build_flag=
	[ "${WITH_UM:-1}" = 1 ] || _build_flag=--without-um
	if ! ( cd "$workdir/repo" && sh build.sh $_build_flag ) >"$LOG" 2>&1; then
		tail -n 20 "$LOG" >&2
		die "build failed, full log in $LOG"
	fi
	[ -n "$PREFIX_DIR" ] || PREFIX_DIR=${PREFIX:-}
	install_binary "$workdir/repo/src/neoproot" "$PREFIX_DIR"
	# The build produces the supervisor; the kernel and the network helpers are
	# separate and come from their own releases, on the same "backend on means
	# fetch it" rule as the Linux path.
	if [ "${WITH_UM:-1}" = 1 ]; then
		install_um_runtime "$PREFIX_DIR"
	fi
	write_state "$PREFIX_DIR" "$tag" 0
else
	check_arch
	tag=$(resolve_tag)
	asset=neoproot
	[ "$PORTABLE" = 1 ] && asset=neoproot-portable
	base="https://github.com/$REPO/releases/download/$tag"
	workdir=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-install.XXXXXX")
	trap 'rm -rf "$workdir"' EXIT INT TERM
	log "downloading $asset $tag"
	fetch "$base/$asset" "$workdir/$asset" || die "download failed"
	fetch "$base/SHA256SUMS" "$workdir/SHA256SUMS" || die "could not download SHA256SUMS"
	grep -q " $asset\$" "$workdir/SHA256SUMS" \
		|| die "$tag does not publish $asset (try --portable or another --version)"
	( cd "$workdir" && grep " $asset\$" SHA256SUMS > selected.sum && sha256sum -c selected.sum ) \
		|| die "checksum verification failed"
	[ -n "$PREFIX_DIR" ] || PREFIX_DIR=${HOME:?}/.local
	install_binary "$workdir/$asset" "$PREFIX_DIR"
	if [ "${WITH_UM:-1}" = 1 ]; then
		install_um_runtime "$PREFIX_DIR"
	fi
	write_state "$PREFIX_DIR" "$tag" "$PORTABLE"
	if [ "${WITH_SHIM:-1}" = 1 ] && [ -n "$SHIM_ROOTFS" ]; then
		_install_shim_into "$SHIM_ROOTFS"
	fi
fi

next_steps
