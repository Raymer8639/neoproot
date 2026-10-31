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

install_um_runtime() {
	_prefix=$1
	_um_dir=$_prefix/libexec/neoproot/um
	_missing=

	mkdir -p "$_um_dir" 2>/dev/null || true

	# linux-um-arm64 publishes the kernel, its SMP build, the stub, umnet and
	# passt-bionic in one release; they are built together and only make sense
	# together.
	_kernel_base="https://github.com/$UM_KERNEL_REPO/releases/download/$UM_KERNEL_TAG"
	for _name in linux-bionic stub_exe umnet passt-bionic; do
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
	git clone --quiet --depth 1 --branch "$tag" "https://github.com/$REPO.git" "$workdir/repo" \
		|| die "git clone failed"
	LOG=${TMPDIR:-$PREFIX/tmp}/neoproot-build.log
	log "compiling (a few minutes on a phone; log: $LOG)"
	if ! ( cd "$workdir/repo" && sh build.sh ) >"$LOG" 2>&1; then
		tail -n 20 "$LOG" >&2
		die "build failed, full log in $LOG"
	fi
	[ -n "$PREFIX_DIR" ] || PREFIX_DIR=${PREFIX:-}
	install_binary "$workdir/repo/src/neoproot" "$PREFIX_DIR"
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
	install_um_runtime "$PREFIX_DIR"
	write_state "$PREFIX_DIR" "$tag" "$PORTABLE"
fi

next_steps
