#!/bin/sh
# neoproot installer - https://github.com/Raymer8639/neoproot
#
#   Termux (Android, bionic): builds the binary from the tagged source, because
#                             the published release binaries are ARM64 glibc.
#   ARM64 Linux (glibc):      downloads the matching release binary, verifies
#                             it against SHA256SUMS and installs it.
#
# The script writes into a bin directory. A container rootfs is touched only
# when --shim-rootfs is given: the stat-shim library belongs to the guest, so
# it is copied (never built) there in the ABI the rootfs loader implies.
#
# An install is a transaction
# ---------------------------
# Nothing is written over a live file before every payload is ready.  The
# binary, the UML runtime and an optional guest shim are downloaded (or built,
# on Termux) into <prefix>/libexec/neoproot/.transaction, and each one is
# checked against the digest its release publishes: SHA256SUMS for the tracer
# and the shims, SHA256SUMS plus MANIFEST (which also states the size) for the
# UML runtime, SHA256SUMS for the standalone passt.  GitHub's release metadata
# is cross-checked when it is reachable.  A file that cannot be verified is not
# installed and is never replaced by a cached copy; the install fails.
#
# Only then does the commit begin, one file at a time: the old file is copied
# to <name>.prev-<timestamp>, a temporary file is written in the target's own
# directory, and a rename puts it in place.  A reader of the old file keeps its
# inode, and a running guest keeps its mapped shim, so no program ever sees a
# half-written file.
#
# The plan (targets and backup names) and the journal (which steps finished)
# live in the same .transaction directory.  install-state is written as the
# last step of the plan, so nothing is called current before every file is in
# place.  If a step fails, the journal is replayed backwards: the backups go
# back, the previous install-state comes back, and the failed transaction is
# kept as .transaction.rolledback-<timestamp> for inspection.  A rollback that
# cannot finish says which targets it could not restore and leaves the
# .transaction directory in place.
#
# SIGINT, SIGTERM and SIGHUP roll back the open transaction in the exit trap.
# SIGKILL cannot be caught, so the *next* run of any action finds the open
# transaction first, rolls it back (or, when every planned step had finished,
# records it as complete instead), and only then does what it was asked to do;
# --recover does only that and exits.  A prefix-level lock -- a directory,
# <prefix>/libexec/neoproot/.install-lock, created with mkdir so that Termux,
# which refuses link(2), can install at all -- keeps two installers from
# committing into the same prefix, and a lock whose process is gone is
# recognised as stale and removed.  The guarantee covers process interruption,
# not sudden power loss: there is no fsync barrier.
#
# Usage:
#   curl -fsSL https://github.com/Raymer8639/neoproot/releases/latest/download/install.sh | sh
#   sh install.sh --version v6.0.4.0 --prefix "$HOME/.local" --portable
set -eu

REPO="Raymer8639/neoproot"
VERSION="latest"
PREFIX_DIR=""
PORTABLE=0
MODE="auto"   # auto | termux | linux  (NEOPROOT_INSTALL_MODE overrides auto)
ACTION=install  # install | update
FORCE_UPDATE=0
RECOVER=0       # --recover: roll an unfinished transaction back and stop
LOG=""

LANG_CHOICE=""   # en | zh   (asked first, or from --lang / NEOPROOT_LANG)
ASSUME_YES=0
SHIM_ROOTFS=""
SHIM_ABI=""
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
  --recover       roll back an install that was interrupted (SIGKILL, power
                  loss) and stop without installing anything; every other
                  action does this rollback first, automatically
  --mode MODE     force the install mode: auto (default), termux or linux
  --lang LANG     en or zh; asked first when not given
  --with-um / --without-um      include the UML backend (default: ask)
  --with-shim / --without-shim  include the stat shim (default: ask)
  --shim-rootfs DIR             copy the shim into this container rootfs
  --shim-abi ABI                force the guest ABI for --shim-rootfs: musl or
                                glibc (default: read the rootfs loader)
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

Both paths stage every file, verify it against the release digests, and only
then replace the live files one at a time with a rename; a failure rolls the
finished steps back in reverse order. Source builds never come from the
release: those assets are glibc builds and will not run as the Termux Android
binary.
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
		--version) [ $# -ge 2 ] || die "--version needs an argument"; VERSION=$2; shift 2 ;;
		--prefix)  [ $# -ge 2 ] || die "--prefix needs an argument";  PREFIX_DIR=$2; shift 2 ;;
		--portable) PORTABLE=1; shift ;;
		--update) ACTION=update; shift ;;
		--force) FORCE_UPDATE=1; shift ;;
		--recover) RECOVER=1; shift ;;
		--mode) [ $# -ge 2 ] || die "--mode needs an argument"; MODE=$2; shift 2 ;;
		--lang) [ $# -ge 2 ] || die "--lang needs an argument"; LANG_CHOICE=$2; shift 2 ;;
		--shim-rootfs) [ $# -ge 2 ] || die "--shim-rootfs needs an argument"; SHIM_ROOTFS=$2; shift 2 ;;
		--shim-abi) [ $# -ge 2 ] || die "--shim-abi needs an argument"; SHIM_ABI=$2; shift 2 ;;
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

case "$SHIM_ABI" in
	''|musl|glibc) ;;
	*) die "--shim-abi must be musl or glibc: $SHIM_ABI" ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }


# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------
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

# The shell runs with set -u, which treats an inherited-but-absent PREFIX,
# HOME or TMPDIR as an error.  Normalise them once here, so the rest of the
# script can simply read them.
if [ -z "$(printenv PREFIX)" ]; then
	PREFIX=
fi
if [ -z "$(printenv HOME)" ]; then
	HOME=/
fi
TMPDIR=$(printenv TMPDIR) || TMPDIR=
TMPDIR_SET=0
if [ -n "$TMPDIR" ]; then
	TMPDIR_SET=1
else
	TMPDIR=/tmp
fi
FORCE_NO_UM=0

# ---------------------------------------------------------------------------
# Integrity
#
# Every payload is checked against the digest its release publishes for it.
# The digest file arrives over TLS from the same release as the bytes, so it is
# the trust anchor; the size comes from a second source (the UML release
# MANIFEST, or the GitHub release metadata) and is cross-checked when that
# second source is reachable.  Two sources that disagree mean the release is
# inconsistent, and the installer refuses to guess which one is right.
#
# There is no "use the cached copy instead" path.  An asset that cannot be
# verified is not installed: the install fails, the live files are untouched,
# and nothing is recorded as current.
# ---------------------------------------------------------------------------
sha256_of() { # sha256_of FILE -> 64 hex characters
	if have sha256sum; then
		_so_out=$(sha256sum "$1" 2>/dev/null) || return 1
		set -- $_so_out
		printf '%s\n' "$1"
	elif have shasum; then
		_so_out=$(shasum -a 256 "$1" 2>/dev/null) || return 1
		set -- $_so_out
		printf '%s\n' "$1"
	elif have openssl; then
		_so_out=$(openssl dgst -sha256 "$1" 2>/dev/null) || return 1
		_so_last=
		for _so_word in $_so_out; do _so_last=$_so_word; done
		[ -n "$_so_last" ] || return 1
		printf '%s\n' "$_so_last"
	else
		return 1
	fi
}

require_sha256() {
	have sha256sum || have shasum || have openssl ||
		die "no sha256 tool (sha256sum, shasum or openssl); refusing to install without verification"
}

file_size() { # file_size FILE -> decimal bytes
	[ -f "$1" ] || return 1
	_fs_bytes=$(wc -c <"$1" 2>/dev/null) || return 1
	# Some wc implementations pad the number; word splitting drops the spaces
	# without another process.
	set -- $_fs_bytes
	[ -n "$1" ] || return 1
	printf '%s\n' "$1"
}

# The expected digest for NAME from a sha256sum-style file.  A missing entry
# means "this release does not publish this asset"; a duplicate means the file
# disagrees with itself.  Both are errors, not something to work around.
sums_lookup() { # sums_lookup SUMFILE NAME -> digest
	_sl_digest=$(awk -F'[[:space:]]+' -v want="$2" '
		{
			name = $2
			sub(/\r$/, "", name)
			sub(/^\*/, "", name)
			if (name == want) { count++; if (count == 1) print $1 }
		}
		END { if (count > 1) exit 3 }
	' "$1" 2>/dev/null)
	_sl_status=$?
	[ "$_sl_status" = 0 ] ||
		die "$1 names $2 more than once; refusing to guess which digest is right"
	[ -n "$_sl_digest" ] || return 1
	printf '%s\n' "$_sl_digest"
}

manifest_lookup() { # manifest_lookup MANIFEST NAME FIELD
	_ml_value=$(awk -F= -v key="asset.$2.$3" '
		{
			k = $1
			sub(/\r$/, "", k)
			if (k == key) {
				line = $0
				sub(/\r$/, "", line)
				print substr(line, length(key) + 2)
				found = 1
				exit
			}
		}
		END { if (!found) exit 1 }
	' "$1" 2>/dev/null) || return 1
	[ -n "$_ml_value" ] || return 1
	printf '%s\n' "$_ml_value"
}

# GitHub publishes size and digest for every asset of a release.  It is not
# needed to trust a download (SHA256SUMS is), but it is an independent second
# statement of the same facts: when it is reachable, a disagreement between the
# two is a broken release and stops the install.  When it is not reachable
# (rate limit, offline, a proxy), the checksums are still enforced.
meta_load() { # meta_load TAG -> sets META_FILE (empty when unavailable)
	_ml_tag=$1
	META_FILE=
	[ -n "$TXN_DIR" ] || return 1
	_ml_cache=$TXN_DIR/staging/release-$_ml_tag.json
	if [ -s "$_ml_cache" ]; then
		META_FILE=$_ml_cache
		return 0
	fi
	if fetch "https://api.github.com/repos/$REPO/releases/tags/$_ml_tag" "$_ml_cache" 2>/dev/null &&
		[ -s "$_ml_cache" ]; then
		META_FILE=$_ml_cache
		return 0
	fi
	rm -f "$_ml_cache"
	warn "GitHub release metadata for $_ml_tag is unavailable; asset sizes are not cross-checked (their sha256 still is)"
	return 1
}

meta_expect() { # meta_expect NAME -> META_SIZE, META_DIGEST; 1 when unknown
	META_SIZE=
	META_DIGEST=
	[ -n "$META_FILE" ] || return 1
	_me_out=$(awk -v want="$1" '
		BEGIN { inside = 0; name = ""; size = ""; digest = "" }
		/^[ \t]*"assets"[ \t]*:[ \t]*\[/ { inside = 1; next }
		inside && /^[ \t]*\][,]?[ \t]*$/ { inside = 0 }
		inside && /^[ \t]*\{/ { name = ""; size = ""; digest = ""; next }
		inside && /"name"[ \t]*:/ {
			line = $0
			sub(/^.*"name"[ \t]*:[ \t]*"/, "", line)
			sub(/".*$/, "", line)
			name = line
		}
		inside && /"size"[ \t]*:/ {
			line = $0
			sub(/^.*"size"[ \t]*:[ \t]*/, "", line)
			sub(/[, \t].*$/, "", line)
			size = line
		}
		inside && /"digest"[ \t]*:/ {
			line = $0
			if (line ~ /sha256:[0-9a-f]+/) {
				sub(/^.*sha256:/, "", line)
				sub(/".*$/, "", line)
				digest = line
			}
		}
		inside && /^[ \t]*\}[,]?[ \t]*$/ {
			if (name == want) { print size " " digest; exit }
		}
	' "$META_FILE" 2>/dev/null) || return 1
	[ -n "$_me_out" ] || return 1
	set -- $_me_out
	META_SIZE=$1
	META_DIGEST=
	if [ $# -ge 2 ]; then META_DIGEST=$2; fi
	[ -n "$META_SIZE" ] || return 1
	return 0
}

verify_asset() { # verify_asset FILE NAME SUMSFILE [MANIFEST] [METAFILE]
	_va_file=$1
	_va_name=$2
	_va_sums=$3
	_va_manifest=
	_va_meta=
	if [ $# -ge 4 ]; then _va_manifest=$4; fi
	if [ $# -ge 5 ]; then _va_meta=$5; fi
	[ -f "$_va_file" ] || die "no downloaded file for $_va_name"
	[ -s "$_va_sums" ] || die "$_va_name: the release checksum file is missing or empty"

	_va_expected=$(sums_lookup "$_va_sums" "$_va_name") ||
		die "$_va_name is not listed in $_va_sums; refusing to install an unverifiable file"
	case "$_va_expected" in
	*[!0-9a-f]*) die "$_va_sums has a malformed sha256 for $_va_name: $_va_expected" ;;
	esac
	[ ${#_va_expected} -eq 64 ] ||
		die "$_va_sums has a malformed sha256 for $_va_name: $_va_expected"

	_va_size=$(file_size "$_va_file") || die "cannot read $_va_file"

	if [ -n "$_va_manifest" ]; then
		_va_msha=$(manifest_lookup "$_va_manifest" "$_va_name" sha256) ||
			die "$_va_manifest does not describe $_va_name; refusing a partial runtime"
		_va_msize=$(manifest_lookup "$_va_manifest" "$_va_name" size) ||
			die "$_va_manifest has no size for $_va_name"
		[ "$_va_msha" = "$_va_expected" ] ||
			die "$_va_manifest and $_va_sums disagree about $_va_name; the release is inconsistent"
		[ "$_va_msize" = "$_va_size" ] ||
			die "$_va_name is $_va_size bytes but $_va_manifest says $_va_msize; refusing to install"
	fi

	_va_actual=$(sha256_of "$_va_file") || die "cannot compute the sha256 of $_va_file"
	[ "$_va_actual" = "$_va_expected" ] ||
		die "checksum mismatch for $_va_name: expected $_va_expected, got $_va_actual; refusing to install"

	if [ -n "$_va_meta" ] && meta_expect "$_va_name"; then
		[ "$META_SIZE" = "$_va_size" ] ||
			die "$_va_name is $_va_size bytes but the release metadata says $META_SIZE; refusing to install"
		if [ -n "$META_DIGEST" ] && [ "$META_DIGEST" != "$_va_actual" ]; then
			die "$_va_name has sha256 $_va_actual but the release metadata says $META_DIGEST; refusing to install"
		fi
	fi
	log "verified $_va_name ($_va_size bytes, sha256 $_va_actual)"
	return 0
}

# ---------------------------------------------------------------------------
# Locks
#
# One installer per prefix, and one per guest rootfs.  The lock is a *directory*
# created with mkdir(2): mkdir either creates it or fails with EEXIST, which is
# atomic on any filesystem whose mkdir is atomic.  link(2) does the same job with
# a file, but Termux/Android refuses a hard link outright -- "ln: failed to
# create hard link ...: Permission denied", link(2) returns EPERM under SELinux
# -- so the old file lock made every install on a phone die before it installed
# anything.  mkdir(2) is allowed there.
#
# The directory holds an "owner" file with the pid and the kernel start time of
# the holder.  It is written under a temporary name inside the directory and
# renamed into place, so a reader never sees half a record and takes a live lock
# for a broken one.  A lock whose pid is gone, or whose pid now belongs to
# another program (a reused pid), is stale: it is removed and the acquire is
# retried.  A live holder is never removed; the run stops and names the path to
# delete.  The directory is removed by its owner only, after the record is read
# once more, so a release cannot take away a lock another installer just made.
# ---------------------------------------------------------------------------
_proc_starttime() { # _proc_starttime PID -> start time in clock ticks
	[ -r "/proc/$1/stat" ] || return 1
	awk '{ sub(/^[0-9]+ \(.*\) /, ""); print $20; exit }' "/proc/$1/stat" 2>/dev/null
}

_lock_holder_alive() { # _lock_holder_alive PID STARTTIME
	_lh_pid=$1
	_lh_start=$2
	kill -0 "$_lh_pid" 2>/dev/null || return 1
	# Alive.  With no recorded start time the pid is all we have; a live pid is
	# treated as a live holder (the safe answer) rather than breaking the lock.
	[ -n "$_lh_start" ] || return 0
	_lh_now=$(_proc_starttime "$_lh_pid") || return 0
	[ -n "$_lh_now" ] || return 0
	[ "$_lh_now" = "$_lh_start" ] && return 0
	return 1
}

# A lock is a directory holding "owner".  An installer from before this change
# used a plain file at the same path with the same keys; reading both means an
# upgrade that races an old installer sees a live holder instead of a path it
# cannot read, and an old leftover is still recognised as stale.
_lock_owner_path() { # _lock_owner_path LOCK -> the file that records the holder
	if [ -d "$1" ]; then
		printf '%s/owner' "$1"
	else
		printf '%s' "$1"
	fi
}

_lock_field() { # _lock_field OWNERFILE KEY -> value, empty when it is not there
	sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1
}

# The record is renamed into place: mkdir and the write cannot be one step, and
# a half-written "pid=12" would read like a stale lock that a second installer
# may remove while this one is alive.
_lock_write_owner() { # _lock_write_owner LOCKDIR PURPOSE
	_lw_tmp=$1/owner.tmp.$$
	if printf 'pid=%s\nstart=%s\npurpose=%s\nsince=%s\n' \
		"$$" "$(_proc_starttime $$)" "$2" \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$_lw_tmp" 2>/dev/null &&
	   mv -f "$_lw_tmp" "$1/owner" 2>/dev/null; then
		return 0
	fi
	rm -f "$_lw_tmp" 2>/dev/null
	return 1
}

# A directory whose owner record never appeared is what a SIGKILL between mkdir
# and the rename leaves behind.  It has no pid to judge, so it is left alone
# unless it is old enough that no installer can still be in that window.  The
# age test is not POSIX (GNU and busybox find have -mmin); when find cannot
# answer, "not old" is the safe answer, and only a directory holding no more
# than the half-written record is considered at all.
_lock_dir_abandoned() { # _lock_dir_abandoned LOCKDIR -> 0 when it is old and ownerless
	[ -d "$1" ] || return 1
	[ -n "$(find "$1" -prune -mmin +2 2>/dev/null)" ] || return 1
	# Only the half-written record of our own making may be inside; anything else
	# is not ours to remove.  find rather than a glob: the prefix is a user path
	# and may contain characters a glob would read as wildcards.
	[ -z "$(find "$1" -mindepth 1 -maxdepth 1 ! -name 'owner.tmp.*' 2>/dev/null)" ] ||
		return 1
	return 0
}

_lock_acquire() { # _lock_acquire LOCK PURPOSE -> 0 acquired, 1 held/failed ($_LK_WHY)
	_lk_lock=$1
	_lk_purpose=$2
	_lk_tries=0
	_lk_removed=0
	_LK_WHY=
	mkdir -p "$(dirname "$_lk_lock")" 2>/dev/null || {
		_LK_WHY="cannot create $(dirname "$_lk_lock")"
		return 1
	}
	while [ "$_lk_tries" -lt 3 ]; do
		_lk_tries=$((_lk_tries + 1))
		# The atomic step: mkdir creates the lock, or fails because it is there.
		if mkdir "$_lk_lock" 2>/dev/null; then
			if _lock_write_owner "$_lk_lock" "$_lk_purpose"; then
				return 0
			fi
			# We own the directory but cannot describe ourselves in it; leaving
			# it behind would block the next run with nothing to diagnose.
			rm -rf "$_lk_lock" 2>/dev/null || true
			_LK_WHY="cannot write $_lk_lock/owner"
			return 1
		fi
		if [ ! -e "$_lk_lock" ] && [ ! -L "$_lk_lock" ]; then
			# mkdir failed for a reason other than EEXIST, or the holder
			# released the lock in between: the loop is what retries this.
			_LK_WHY="cannot create $_lk_lock"
			continue
		fi
		_lk_pid=$(_lock_field "$(_lock_owner_path "$_lk_lock")" pid)
		_lk_start=$(_lock_field "$(_lock_owner_path "$_lk_lock")" start)
		if [ -z "$_lk_pid" ]; then
			if _lock_dir_abandoned "$_lk_lock"; then
				warn "removing a stale lock ($_lk_lock, its owner record never appeared)"
				rm -rf "$_lk_lock" 2>/dev/null || true
				_lk_removed=1
				continue
			fi
			_LK_WHY="$_lk_lock exists but records no owner; remove it if no installer is running"
			return 1
		fi
		if _lock_holder_alive "$_lk_pid" "$_lk_start"; then
			_LK_WHY="pid $_lk_pid is still running"
			return 1
		fi
		# The pid is gone, or the pid was reused by another program: a leftover.
		# Read the record once more right before removing it, because a second
		# installer may have cleared the stale lock and taken it over meanwhile.
		if [ "$(_lock_field "$(_lock_owner_path "$_lk_lock")" pid)" != "$_lk_pid" ]; then
			_LK_WHY="$_lk_lock changed hands while it was being examined"
			return 1
		fi
		warn "removing a stale lock ($_lk_lock, pid $_lk_pid is gone)"
		if [ -d "$_lk_lock" ]; then
			rm -rf "$_lk_lock" 2>/dev/null || true
		else
			rm -f "$_lk_lock" 2>/dev/null || true
		fi
		_lk_removed=1
	done
	if [ "$_lk_removed" = 1 ]; then
		_LK_WHY="$_lk_lock kept reappearing; remove it if no installer is running"
	elif [ -z "$_LK_WHY" ]; then
		_LK_WHY="cannot create $_lk_lock"
	fi
	return 1
}

# Remove only the lock this process wrote.  The record is checked again first:
# an installer that judged this lock stale may have removed it and created its
# own in its place, and taking that one away would hand the prefix to two
# installers at once.
_lock_release() { # _lock_release LOCK -> 0 released, 1 left alone
	_lr_lock=$1
	_lr_owner=$(_lock_owner_path "$_lr_lock")
	_lr_pid=$(_lock_field "$_lr_owner" pid)
	_lr_start=$(_lock_field "$_lr_owner" start)
	if [ "$_lr_pid" != "$$" ]; then
		warn "not removing $_lr_lock: it is held by pid ${_lr_pid:-nobody}, not $$"
		return 1
	fi
	if [ -n "$_lr_start" ] && [ "$_lr_start" != "$(_proc_starttime $$)" ]; then
		warn "not removing $_lr_lock: its start time is not this process's"
		return 1
	fi
	if [ -d "$_lr_lock" ]; then
		rm -rf "$_lr_lock" 2>/dev/null || {
			warn "cannot remove $_lr_lock"
			return 1
		}
	else
		rm -f "$_lr_lock" 2>/dev/null || {
			warn "cannot remove $_lr_lock"
			return 1
		}
	fi
	return 0
}

lock_prefix() { # lock_prefix PREFIX
	[ "$LOCK_HELD" = 1 ] && return 0
	LOCK_FILE=$(lock_for "$1")
	_lock_acquire "$LOCK_FILE" "install into $1" ||
		die "another neoproot installer is using $1 ($_LK_WHY); wait for it to finish, or remove $LOCK_FILE (rm -rf) if you are sure it is gone"
	LOCK_HELD=1
	log "lock: $LOCK_FILE"
}

release_prefix_lock() {
	if [ "$LOCK_HELD" = 1 ] && [ -n "$LOCK_FILE" ]; then
		_lock_release "$LOCK_FILE" || true
	fi
	LOCK_HELD=0
}

lock_guest() { # lock_guest ROOTFS
	_li_rootfs=$1
	mkdir -p "$_li_rootfs/opt/neoproot" ||
		die "cannot create $_li_rootfs/opt/neoproot"
	GUEST_LOCK_FILE=$_li_rootfs/opt/neoproot/.install-lock
	_lock_acquire "$GUEST_LOCK_FILE" "shim into $_li_rootfs" ||
		die "another installer is replacing the shim in $_li_rootfs ($_LK_WHY); wait for it, or remove $GUEST_LOCK_FILE (rm -rf) if you are sure it is gone"
	GUEST_LOCK_HELD=1
}

release_guest_lock() {
	if [ "$GUEST_LOCK_HELD" = 1 ] && [ -n "$GUEST_LOCK_FILE" ]; then
		_lock_release "$GUEST_LOCK_FILE" || true
	fi
	GUEST_LOCK_HELD=0
}

# ---------------------------------------------------------------------------
# The install transaction
#
# The plan lists every file this run will replace, with the backup name it will
# use.  The journal records "begin" before a step touches its target and "done"
# after it finished, so a rollback can undo a step that was interrupted in the
# middle of its rename as well as one that completed.  install-state is a step
# like any other, and it is planned last: no state file says "current" before
# every payload is in place.
#
# Rollback replays the journal backwards.  A rollback that cannot finish says
# which targets it could not restore, keeps the journal and the backups, and
# leaves .transaction in place; the next run will try again (and --recover is
# the explicit form of "try again now, do not install").
# ---------------------------------------------------------------------------
TAB=$(printf '\t')
# A path that carries a tab or a newline cannot be represented in the plan or
# the journal, so such a path is refused rather than silently mis-recorded.
_newline='
'
# The plan and the journal are tab-free: a tab is IFS whitespace, and read(1)
# collapses runs of it (so an empty field such as "no backup" would shift every
# later field).  FS (\034) is not whitespace and never appears in a path.
SEP=$(printf '\034')
TXN_DIR=
TXN_STAMP=
TXN_STEP=0
TXN_OPEN=0
STAGE_DIR=
UM_RUNTIME_COMPLETE=0
SUMS_FILE=
META_FILE=
LOCK_HELD=0
LOCK_FILE=
GUEST_LOCK_HELD=0
GUEST_LOCK_FILE=
SHIM_INSTALLED_ABI=
SHIM_INSTALLED_DEST=

txn_dir_for() { printf '%s/libexec/neoproot/.transaction' "$1"; }
lock_for() { printf '%s/libexec/neoproot/.install-lock' "$1"; }

txn_phase() { printf '%s\n' "$1" >"$TXN_DIR/phase" 2>/dev/null || true; }

txn_begin() { # txn_begin PREFIX TAG
	_tb_prefix=$1
	_tb_tag=$2
	TXN_DIR=$(txn_dir_for "$_tb_prefix")
	[ ! -d "$TXN_DIR" ] ||
		die "an unfinished transaction is still in $TXN_DIR; run with --recover first"
	TXN_STAMP=$(date +%Y%m%d-%H%M%S)
	mkdir -p "$TXN_DIR/staging" || die "cannot create the staging directory $TXN_DIR"
	: >"$TXN_DIR/plan" || die "cannot write $TXN_DIR/plan"
	: >"$TXN_DIR/journal" || die "cannot write $TXN_DIR/journal"
	{
		printf 'version=%s\n' "$_tb_tag"
		printf 'prefix=%s\n' "$_tb_prefix"
		printf 'portable=%s\n' "$PORTABLE"
		printf 'pid=%s\n' "$$"
		printf 'started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$TXN_DIR/meta" || die "cannot write $TXN_DIR/meta"
	txn_phase staging
	TXN_STEP=0
	TXN_OPEN=1
	log "transaction: staging in $TXN_DIR"
}

txn_plan() { # txn_plan KIND TARGET PAYLOAD LINKTEXT MODE
	_tp_kind=$1
	_tp_target=$2
	_tp_payload=$3
	_tp_link=$4
	_tp_mode=$5
	_tp_id=$((TXN_STEP + 1))
	_tp_backup=
	_tp_old=0
	if [ -e "$_tp_target" ] || [ -L "$_tp_target" ]; then
		_tp_old=1
		_tp_backup=$_tp_target.prev-$TXN_STAMP
		_tp_n=1
		while [ -e "$_tp_backup" ] || [ -L "$_tp_backup" ]; do
			_tp_n=$((_tp_n + 1))
			_tp_backup=$_tp_target.prev-$TXN_STAMP.$_tp_n
		done
	fi
	TXN_STEP=$_tp_id
	printf '%s\034%s\034%s\034%s\034%s\034%s\034%s\034%s\n' \
		"$_tp_id" "$_tp_kind" "$_tp_target" "$_tp_payload" "$_tp_backup" \
		"$_tp_old" "$_tp_link" "$_tp_mode" >>"$TXN_DIR/plan" ||
		die "cannot write $TXN_DIR/plan"
	if [ "$_tp_old" = 1 ]; then
		log "transaction: $_tp_target -> backup $_tp_backup"
	fi
}

txn_plan_remove() { # txn_plan_remove TARGET BACKUP
	_tpr_target=$1
	_tpr_backup=$2
	_tpr_id=$((TXN_STEP + 1))
	TXN_STEP=$_tpr_id
	printf '%s\034remove\034%s\034\034%s\0341\034\034\n' \
		"$_tpr_id" "$_tpr_target" "$_tpr_backup" >>"$TXN_DIR/plan" ||
		die "cannot write $TXN_DIR/plan"
	log "transaction: $_tpr_target -> $_tpr_backup"
}

# A step is applied with a temporary file in the target's own directory and a
# rename over the target.  The old file is copied to its .prev-<stamp> name
# first, never overwritten in place: a process that already mapped the old
# inode keeps using it, and a rollback has an exact copy to put back.
apply_step() { # apply_step KIND TARGET PAYLOAD BACKUP HAD_OLD LINKTEXT MODE
	_ap_kind=$1
	_ap_target=$2
	_ap_payload=$3
	_ap_backup=$4
	_ap_old=$5
	_ap_link=$6
	_ap_mode=$7
	_ap_dir=$(dirname "$_ap_target")
	_ap_base=$(basename "$_ap_target")
	mkdir -p "$_ap_dir" 2>/dev/null || {
		warn "cannot create $_ap_dir"
		return 1
	}
	if [ "$_ap_kind" = remove ]; then
		[ -n "$_ap_backup" ] || {
			warn "no destination to move $_ap_target to"
			return 1
		}
		mv -f "$_ap_target" "$_ap_backup" || {
			warn "cannot move $_ap_target to $_ap_backup"
			return 1
		}
		return 0
	fi
	if [ "$_ap_old" = 1 ]; then
		cp -a "$_ap_target" "$_ap_backup" || {
			warn "cannot keep a copy of $_ap_target at $_ap_backup"
			return 1
		}
	fi
	_ap_tmp=$_ap_dir/.$_ap_base.new.$$
	if [ "$_ap_kind" = link ]; then
		ln -s "$_ap_link" "$_ap_tmp" || {
			warn "cannot create the link $_ap_tmp"
			return 1
		}
	else
		if [ -z "$_ap_payload" ] || [ ! -f "$_ap_payload" ]; then
			warn "the staged payload for $_ap_target is missing: $_ap_payload"
			return 1
		fi
		cp "$_ap_payload" "$_ap_tmp" || {
			warn "cannot copy the payload to $_ap_tmp"
			return 1
		}
		chmod "$_ap_mode" "$_ap_tmp" || {
			warn "cannot set mode $_ap_mode on $_ap_tmp"
			rm -f "$_ap_tmp"
			return 1
		}
	fi
	mv -f "$_ap_tmp" "$_ap_target" || {
		warn "cannot rename $_ap_tmp over $_ap_target"
		rm -f "$_ap_tmp"
		return 1
	}
	return 0
}

undo_step() { # undo_step KIND TARGET PAYLOAD BACKUP HAD_OLD LINKTEXT MODE
	_us_kind=$1
	_us_target=$2
	_us_backup=$4
	_us_old=$5
	case "$_us_kind" in
	remove)
		if [ -e "$_us_backup" ] || [ -L "$_us_backup" ]; then
			mv -f "$_us_backup" "$_us_target" || {
				warn "rollback: cannot move $_us_backup back to $_us_target"
				return 1
			}
		elif [ -e "$_us_target" ] || [ -L "$_us_target" ]; then
			# The move never happened; nothing to undo.
			return 0
		else
			warn "rollback: $_us_target is gone and $_us_backup does not exist"
			return 1
		fi
		;;
	*)
		if [ "$_us_old" = 1 ]; then
			if [ ! -e "$_us_backup" ] && [ ! -L "$_us_backup" ]; then
				# apply_step copies the old file to its backup before it writes
				# anything, so a missing backup means this step never started:
				# the file on disk is still the old one.
				if [ -e "$_us_target" ] || [ -L "$_us_target" ]; then
					log "rollback: $_us_target was not replaced; nothing to undo"
					return 0
				fi
				warn "rollback: $_us_target is gone and its backup $_us_backup is missing"
				return 1
			fi
			_us_tmp=$(dirname "$_us_target")/.$(basename "$_us_target").restore.$$
			cp -a "$_us_backup" "$_us_tmp" || {
				warn "rollback: cannot copy $_us_backup back"
				return 1
			}
			mv -f "$_us_tmp" "$_us_target" || {
				warn "rollback: cannot rename $_us_tmp over $_us_target"
				rm -f "$_us_tmp"
				return 1
			}
		else
			rm -f "$_us_target" || {
				warn "rollback: cannot remove $_us_target"
				return 1
			}
		fi
		;;
	esac
	return 0
}

txn_commit() {
	_tc_steps=$(awk 'NF { n++ } END { print n + 0 }' "$TXN_DIR/plan" 2>/dev/null) || _tc_steps=0
	if [ "$_tc_steps" = 0 ]; then
		log "transaction: nothing to replace"
		return 0
	fi
	txn_phase committing
	while IFS="$SEP" read -r _tc_id _tc_kind _tc_target _tc_payload _tc_backup _tc_old _tc_link _tc_mode; do
		[ -n "$_tc_id" ] || continue
		printf 'begin\034%s\034%s\034%s\034%s\034%s\034%s\034%s\034%s\n' \
			"$_tc_id" "$_tc_kind" "$_tc_target" "$_tc_payload" "$_tc_backup" \
			"$_tc_old" "$_tc_link" "$_tc_mode" >>"$TXN_DIR/journal" ||
			die "cannot write $TXN_DIR/journal"
		if ! apply_step "$_tc_kind" "$_tc_target" "$_tc_payload" "$_tc_backup" \
			"$_tc_old" "$_tc_link" "$_tc_mode"; then
			warn "transaction: step $_tc_id ($_tc_kind $_tc_target) failed"
			return 1
		fi
		printf 'done\034%s\n' "$_tc_id" >>"$TXN_DIR/journal" ||
			die "cannot write $TXN_DIR/journal"
		case "$_tc_target" in
		*/libexec/neoproot/um/*)
			log "UML runtime: $(basename "$_tc_target")" ;;
		*)
			case "$_tc_kind" in
			link) log "installed $_tc_target -> $_tc_link" ;;
			remove) log "moved $_tc_target to $_tc_backup" ;;
			state) log "recorded the install state in $_tc_target" ;;
			*) log "installed $_tc_target" ;;
			esac
			;;
		esac
	done <"$TXN_DIR/plan"
	return 0
}

txn_rollback() {
	[ -n "$TXN_DIR" ] && [ -d "$TXN_DIR" ] || return 0
	_rb_failed=0
	if [ -s "$TXN_DIR/journal" ]; then
		awk -F"$SEP" '$1 == "begin" { n++; line[n] = $0 } END { for (i = n; i > 0; i--) print line[i] }' \
			"$TXN_DIR/journal" >"$TXN_DIR/journal.reverse" 2>/dev/null || {
			warn "rollback: cannot read $TXN_DIR/journal"
			return 1
		}
		while IFS="$SEP" read -r _rb_marker _rb_id _rb_kind _rb_target _rb_payload _rb_backup _rb_old _rb_link _rb_mode; do
			[ -n "$_rb_id" ] || continue
			if undo_step "$_rb_kind" "$_rb_target" "$_rb_payload" "$_rb_backup" \
				"$_rb_old" "$_rb_link" "$_rb_mode"; then
				log "rollback: $_rb_target"
			else
				warn "rollback: could not restore $_rb_target"
				_rb_failed=$((_rb_failed + 1))
			fi
		done <"$TXN_DIR/journal.reverse"
	fi
	if [ "$_rb_failed" = 0 ]; then
		return 0
	fi
	warn "rollback: $_rb_failed step(s) could not be undone; the journal and the backups are kept in $TXN_DIR"
	return 1
}

txn_close_committed() {
	txn_phase committed
	if ! rm -rf "$TXN_DIR" 2>/dev/null; then
		warn "cannot remove $TXN_DIR; the next run will record this transaction as complete"
	fi
	TXN_OPEN=0
}

txn_close_rolledback() {
	txn_phase rolled-back
	rm -rf "$TXN_DIR/staging" 2>/dev/null || true
	_rb_kept=$TXN_DIR.rolledback-$(date +%Y%m%d-%H%M%S)
	if mv "$TXN_DIR" "$_rb_kept" 2>/dev/null; then
		warn "the failed transaction is kept in $_rb_kept (plan, journal, backups)"
	else
		warn "cannot move $TXN_DIR aside; its plan and journal are still there"
	fi
	TXN_OPEN=0
}

# Any action, including --recover, starts here: an install that was killed
# before it finished is rolled back before anything else is attempted.  When
# every planned step had finished (the process died between the last step and
# the cleanup) the transaction is completed instead of undone -- the state file
# it wrote is only written after every payload was in place.
txn_recover() { # txn_recover PREFIX
	_tr_prefix=$1
	TXN_DIR=$(txn_dir_for "$_tr_prefix")
	if [ ! -d "$TXN_DIR" ]; then
		TXN_DIR=
		return 0
	fi
	_tr_plan=$(awk 'NF { n++ } END { print n + 0 }' "$TXN_DIR/plan" 2>/dev/null) || _tr_plan=0
	_tr_done=$(awk -F"$SEP" '$1 == "done" { n++ } END { print n + 0 }' "$TXN_DIR/journal" 2>/dev/null) || _tr_done=0
	_tr_version=$(sed -n 's/^version=//p' "$TXN_DIR/meta" 2>/dev/null | head -n 1)
	_tr_phase=$(cat "$TXN_DIR/phase" 2>/dev/null) || _tr_phase=
	warn "found an unfinished install transaction in $_tr_prefix"
	warn "  version=$_tr_version phase=$_tr_phase steps=$_tr_done/$_tr_plan"
	if [ "$_tr_plan" = 0 ]; then
		warn "no file had been replaced yet; removing the staging area"
		rm -rf "$TXN_DIR"
		TXN_DIR=
		return 0
	fi
	if [ "$_tr_done" -ge "$_tr_plan" ]; then
		log "every planned step had finished; recording the transaction as complete"
		txn_close_committed
		TXN_DIR=
		return 0
	fi
	warn "rolling it back before doing anything else (--recover does only this)"
	if txn_rollback; then
		txn_close_rolledback
		TXN_DIR=
		return 0
	fi
	die "the previous transaction could not be rolled back; its plan, journal and backups are in $TXN_DIR"
}

commit_or_die() {
	if txn_commit; then
		txn_close_committed
		return 0
	fi
	if txn_rollback; then
		txn_close_rolledback
		die "install failed; every file this run had replaced was restored"
	fi
	die "install failed and the rollback could not finish; the plan, journal and backups are in $TXN_DIR"
}

# ---------------------------------------------------------------------------
# Staging: everything is downloaded, built and verified before the first
# replacement.  Each stage_* function only writes inside the transaction's
# staging directory and appends to the plan; the live tree is not touched until
# txn_commit runs.
# ---------------------------------------------------------------------------
stage_copy() { # stage_copy SRC NAME MODE
	_sc_dest=$TXN_DIR/staging/$2
	cp "$1" "$_sc_dest" || return 1
	chmod "$3" "$_sc_dest" || return 1
	printf '%s\n' "$_sc_dest"
}

stage_binary() { # stage_binary SRC PREFIX
	_sb_src=$1
	_sb_prefix=$2
	[ -n "$_sb_prefix" ] || die "empty install prefix"
	[ -f "$_sb_src" ] || die "there is no binary to install at $_sb_src"
	mkdir -p "$_sb_prefix/bin" || die "cannot create $_sb_prefix/bin"
	_sb_stage=$(stage_copy "$_sb_src" payload-neoproot 755) ||
		die "cannot stage the binary"
	txn_plan file "$_sb_prefix/bin/neoproot" "$_sb_stage" "" 755
}

stage_aliases() { # stage_aliases PREFIX
	_sa_dir=$1/bin
	if [ "$WITH_UM" != 0 ]; then
		# neoproot contains the supervisor and dispatches on argv[0], so the
		# name is a relative link, not a second copy that would go stale.
		_sa_target=$_sa_dir/neoproot-um
		if [ -L "$_sa_target" ] && [ "$(readlink "$_sa_target")" = neoproot ]; then
			:
		else
			txn_plan link "$_sa_target" "" neoproot 777
		fi
		# uproot is the historical name; refresh one that exists, never create
		# one on a fresh install.
		_sa_target=$_sa_dir/uproot
		if [ -e "$_sa_target" ] || [ -L "$_sa_target" ]; then
			if [ -L "$_sa_target" ] && [ "$(readlink "$_sa_target")" = neoproot ]; then
				:
			else
				txn_plan link "$_sa_target" "" neoproot 777
			fi
		fi
	else
		# A leftover neoproot-um would run last year's supervisor beside today's
		# tracer.  Rename it rather than deleting it.
		_sa_target=$_sa_dir/neoproot-um
		if [ -e "$_sa_target" ] || [ -L "$_sa_target" ]; then
			txn_plan_remove "$_sa_target" "$_sa_target.stale-$TXN_STAMP"
		fi
	fi
}

stage_state() { # stage_state PREFIX TAG PORTABLE
	_ss_prefix=$1
	_ss_tag=$2
	_ss_portable=$3
	_ss_dir=$_ss_prefix/libexec/neoproot
	_ss_file=$_ss_dir/install-state
	_ss_with_um=1
	[ "$FORCE_NO_UM" = 1 ] && _ss_with_um=0
	# WITH_UM is "1", "0" or empty; empty means "the previous install had the
	# runtime on" (an update), and must not silently record with_um=0.
	if [ "$WITH_UM" = 0 ]; then _ss_with_um=0; fi
	mkdir -p "$_ss_dir" || die "cannot create $_ss_dir"
	_ss_stage=$TXN_DIR/staging/install-state
	{
		printf 'version=%s\n' "$_ss_tag"
		printf 'prefix=%s\n' "$_ss_prefix"
		printf 'portable=%s\n' "$_ss_portable"
		printf 'with_um=%s\n' "$_ss_with_um"
		# A runtime that was not refreshed deliberately leaves these empty, so
		# the next --update retries it instead of believing it is current.
		if [ "$_ss_with_um" = 1 ] && [ "$UM_RUNTIME_COMPLETE" != 1 ]; then
			printf 'um_kernel_tag=\num_passt_tag=\n'
		else
			printf 'um_kernel_tag=%s\n' "$UM_KERNEL_TAG"
			printf 'um_passt_tag=%s\n' "$PASST_TAG"
		fi
		printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$_ss_stage" || die "cannot stage the install state"
	chmod 644 "$_ss_stage" 2>/dev/null || true
	txn_plan state "$_ss_file" "$_ss_stage" "" 644
}

# Which libc owns this rootfs.  Kept in step with shim_abi_for_rootfs() in
# the source installer; this script is a standalone release asset, so it cannot
# source that file.  The loader name is the marker: musl and glibc cannot load
# each other's LD_PRELOAD libraries, and a wrong copy only fails inside the
# guest, after the install claimed success.
_rootfs_abi() { # _rootfs_abi ROOTFS -> musl|glibc, or 1 with a reason
	_ra_rootfs=$1
	_ra_musl=
	_ra_glibc=
	if [ -e "$_ra_rootfs/lib/ld-musl-aarch64.so.1" ] ||
		[ -L "$_ra_rootfs/lib/ld-musl-aarch64.so.1" ]; then
		_ra_musl=1
	fi
	if [ -e "$_ra_rootfs/lib/ld-linux-aarch64.so.1" ] ||
		[ -L "$_ra_rootfs/lib/ld-linux-aarch64.so.1" ] ||
		[ -e "$_ra_rootfs/lib64/ld-linux-aarch64.so.1" ] ||
		[ -L "$_ra_rootfs/lib64/ld-linux-aarch64.so.1" ]; then
		_ra_glibc=1
	fi
	if [ -n "$_ra_musl" ] && [ -z "$_ra_glibc" ]; then
		printf 'musl\n'
		return 0
	fi
	if [ -n "$_ra_glibc" ] && [ -z "$_ra_musl" ]; then
		printf 'glibc\n'
		return 0
	fi
	if [ -n "$_ra_musl" ]; then
		warn "$_ra_rootfs has both musl and glibc loaders; pass --shim-abi musl|glibc"
	else
		warn "$_ra_rootfs has no aarch64 loader (lib/ld-musl-aarch64.so.1, lib/ld-linux-aarch64.so.1 or lib64/ld-linux-aarch64.so.1); pass --shim-abi musl|glibc"
	fi
	return 1
}

# Read the ABI a .so was linked against, when readelf is available.  "unknown"
# means "cannot confirm": a downloaded shim that cannot be identified is not
# installed into a guest.
_shim_file_abi() { # _shim_file_abi FILE -> musl|glibc|unknown
	_sfa_needed=$(readelf -d "$1" 2>/dev/null || true)
	case "$_sfa_needed" in
	*libc.musl-*.so.1*) printf 'musl\n' ;;
	*libc.so.6*) printf 'glibc\n' ;;
	*) printf 'unknown\n' ;;
	esac
}

# The shim belongs to the guest, so the release asset is fetched, verified and
# only then planned for <rootfs>/opt/neoproot/libstatfast.so.  The guest's own
# copy is never a source: replacing it is the point, and copying it onto itself
# is how the "update did nothing" bug looked.
stage_shim_into() { # stage_shim_into ROOTFS TAG
	_si_rootfs=$1
	_si_tag=$2
	case "$_si_rootfs" in
	/*) ;;
	*) warn "--shim-rootfs needs an absolute path: $_si_rootfs"; return 0 ;;
	esac
	[ -d "$_si_rootfs" ] || {
		warn "no such rootfs: $_si_rootfs"
		return 0
	}
	case "$_si_rootfs" in
	*"$TAB"*|*"$_newline"*)
		die "the rootfs path contains a tab or a newline; the transaction log cannot record it"
		;;
	esac
	if [ -n "$SHIM_ABI" ]; then
		_si_abi=$SHIM_ABI
	else
		_si_abi=$(_rootfs_abi "$_si_rootfs") || return 0
	fi
	case "$_si_abi" in
	musl) _si_asset=libstatfast-musl.so ;;
	glibc) _si_asset=libstatfast.so ;;
	*)
		warn "unknown shim ABI: $_si_abi"
		return 0
		;;
	esac

	lock_guest "$_si_rootfs"

	# A release that does not publish the file is not a verification failure:
	# there is nothing to install, so the installer says so and leaves the guest
	# alone.  A file that *was* downloaded and does not match its digest is a
	# different matter and is fatal (verify_asset dies).
	if ! ensure_release_sums "$_si_tag"; then
		warn "could not download SHA256SUMS for $_si_tag; the shim is not installed into $_si_rootfs"
		return 0
	fi
	meta_load "$_si_tag" || true

	_si_stage=$TXN_DIR/staging/$_si_asset
	if ! fetch "https://github.com/$REPO/releases/download/$_si_tag/$_si_asset" "$_si_stage" 2>/dev/null; then
		rm -f "$_si_stage"
		warn "could not fetch $_si_asset from $_si_tag; the shim was not installed into $_si_rootfs"
		if [ "$_si_abi" = musl ]; then
			warn "musl roots need a source build (stat-shim/build-musl.sh) or a musl libstatfast.so placed in $_si_rootfs/opt/neoproot/libstatfast.so manually"
		fi
		return 0
	fi
	verify_asset "$_si_stage" "$_si_asset" "$SUMS_FILE" "" "$META_FILE"

	# "unknown" means readelf saw neither libc.so.6 nor libc.musl-*: a Termux
	# (bionic) build, a stray file, or a truncated download.  Copying that into
	# a guest breaks every program there, so refuse instead of guessing.
	_si_got_abi=$(_shim_file_abi "$_si_stage")
	case "$_si_got_abi" in
	"$_si_abi") ;;
	unknown)
		warn "cannot confirm the ABI of $_si_asset (neither libc.so.6 nor libc.musl-*); refusing to install it into $_si_rootfs"
		return 0
		;;
	*)
		warn "$_si_asset is a $_si_got_abi shim, not $_si_abi; refusing to install it into $_si_rootfs"
		return 0
		;;
	esac

	_si_dest=$_si_rootfs/opt/neoproot/libstatfast.so
	txn_plan file "$_si_dest" "$_si_stage" "" 755
	SHIM_INSTALLED_ABI=$_si_abi
	SHIM_INSTALLED_DEST=$_si_dest
	log "shim ($_si_abi): $_si_asset verified, staged for $_si_dest"
	return 0
}

# ---------------------------------------------------------------------------
# The UML runtime
#
# The kernel, its stub, umnet and passt are built together and only make sense
# together, so they move as one group: either all four are verified and
# replaced, or none is touched.  A runtime that could not be fetched leaves the
# old one in place and leaves um_kernel_tag/um_passt_tag empty in install-state,
# which is what makes the next --update retry instead of assuming it is current.
# A runtime that was fetched but does not match its checksum is a different
# thing: that is a broken or tampered release, and the install fails.
# ---------------------------------------------------------------------------
UM_KERNEL_TAG=$(printenv NEOPROOT_UM_KERNEL_TAG) || UM_KERNEL_TAG=
[ -n "$UM_KERNEL_TAG" ] || UM_KERNEL_TAG=um-arm64-v0.4.2
PASST_TAG=$(printenv NEOPROOT_UM_PASST_TAG) || PASST_TAG=
[ -n "$PASST_TAG" ] || PASST_TAG=v0.4.1
UM_KERNEL_REPO=Raymer8639/linux-um-arm64
PASST_REPO=Raymer8639/passt-android

ensure_release_sums() { # ensure_release_sums TAG
	[ -n "$SUMS_FILE" ] && return 0
	_es_stage=$TXN_DIR/staging/SHA256SUMS
	fetch "https://github.com/$REPO/releases/download/$1/SHA256SUMS" "$_es_stage" 2>/dev/null || {
		rm -f "$_es_stage"
		return 1
	}
	[ -s "$_es_stage" ] || return 1
	SUMS_FILE=$_es_stage
	return 0
}

stage_um_runtime() { # stage_um_runtime PREFIX
	_su_prefix=$1
	_su_dir=$_su_prefix/libexec/neoproot/um
	_su_stage=$TXN_DIR/staging/um
	UM_RUNTIME_COMPLETE=0
	_su_names="linux-bionic stub_exe umnet passt-bionic"

	mkdir -p "$_su_dir" "$_su_stage" 2>/dev/null || {
		warn "cannot create $_su_dir; the UML runtime is not installed"
		return 0
	}

	_su_base="https://github.com/$UM_KERNEL_REPO/releases/download/$UM_KERNEL_TAG"
	if ! fetch "$_su_base/MANIFEST" "$_su_stage/MANIFEST" 2>/dev/null ||
		! fetch "$_su_base/SHA256SUMS" "$_su_stage/SHA256SUMS" 2>/dev/null ||
		[ ! -s "$_su_stage/MANIFEST" ] || [ ! -s "$_su_stage/SHA256SUMS" ]; then
		warn "$UM_KERNEL_REPO@$UM_KERNEL_TAG does not publish a MANIFEST and SHA256SUMS (or they are unreachable); the UML runtime is not installed or refreshed"
		warn "the runtime in $_su_dir, if any, is left exactly as it was"
		return 0
	fi

	# The manifest has to describe every asset of the group before a single
	# byte is trusted: a partial manifest is a partial release.
	for _su_name in $_su_names; do
		manifest_lookup "$_su_stage/MANIFEST" "$_su_name" sha256 >/dev/null 2>&1 || {
			die "$UM_KERNEL_TAG MANIFEST does not describe $_su_name; the release is inconsistent, refusing to install part of the runtime"
		}
	done

	_su_missing=
	for _su_name in $_su_names; do
		if [ "$_su_name" = linux-bionic ] &&
			[ -n "$UM_KERNEL_OVERRIDE" ] && [ -f "$UM_KERNEL_OVERRIDE" ]; then
			continue
		fi
		if ! fetch "$_su_base/$_su_name" "$_su_stage/$_su_name" 2>/dev/null; then
			rm -f "$_su_stage/$_su_name"
			_su_missing="$_su_missing $_su_name"
			continue
		fi
		verify_asset "$_su_stage/$_su_name" "$_su_name" \
			"$_su_stage/SHA256SUMS" "$_su_stage/MANIFEST"
	done

	# Prefer the passt bundled with the kernel; fall back to the pinned
	# standalone release, which is verified against its own SHA256SUMS.
	if [ ! -f "$_su_stage/passt-bionic" ]; then
		_su_passt_base="https://github.com/$PASST_REPO/releases/download/$PASST_TAG"
		if fetch "$_su_passt_base/SHA256SUMS" "$_su_stage/passt-SHA256SUMS" 2>/dev/null &&
			fetch "$_su_passt_base/passt-android-arm64" "$_su_stage/passt-bionic" 2>/dev/null; then
			verify_asset "$_su_stage/passt-bionic" passt-android-arm64 \
				"$_su_stage/passt-SHA256SUMS"
			log "passt-bionic from $PASST_REPO@$PASST_TAG"
			_su_missing=$(printf '%s\n' "$_su_missing" | sed 's/ passt-bionic//')
		else
			rm -f "$_su_stage/passt-bionic"
			warn "--net needs passt-bionic; could not fetch it from $PASST_REPO@$PASST_TAG"
		fi
	fi

	if [ -n "$_su_missing" ]; then
		warn "could not fetch from $UM_KERNEL_REPO@$UM_KERNEL_TAG:$_su_missing"
		warn "the UML runtime was not changed; the next --update retries it"
		return 0
	fi

	# A kernel the user pointed at wins over the published one: it is the only
	# way to use a build for a device profile no release covers.  It is their
	# file, so there is no release digest to check it against.
	if [ -n "$UM_KERNEL_OVERRIDE" ] && [ -f "$UM_KERNEL_OVERRIDE" ]; then
		cp "$UM_KERNEL_OVERRIDE" "$_su_stage/linux-bionic" || {
			warn "cannot copy $UM_KERNEL_OVERRIDE; the UML runtime is not installed"
			return 0
		}
		chmod 755 "$_su_stage/linux-bionic" || true
		log "kernel from $UM_KERNEL_OVERRIDE"
	fi

	for _su_name in $_su_names; do
		txn_plan file "$_su_dir/$_su_name" "$_su_stage/$_su_name" "" 755
	done
	UM_RUNTIME_COMPLETE=1
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
# Termux package manager exists. Never trust an inherited PREFIX/TERMUX_VERSION
# alone -- a proot container started from Termux inherits both, and its glibc
# userland needs the release binary, not a source build.
is_termux() {
	[ -x /system/bin/linker64 ] || [ -x /system/bin/linker ] || return 1
	have pkg || return 1
	[ -n "$PREFIX" ] || return 1
	[ -d "$PREFIX/bin" ] || return 1
	return 0
}

resolve_tag() {
	if [ "$VERSION" != "latest" ]; then printf '%s' "$VERSION"; return 0; fi
	json=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest") \
		|| die "cannot reach the GitHub API; pass --version vX.Y.Z.A instead"
	tag=$(printf '%s\n' "$json" \
		| sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$tag" ] || die "could not determine the latest release; pass --version vX.Y.Z.A"
	printf '%s' "$tag"
}

check_arch() {
	case "$(uname -m)" in
		aarch64|arm64) ;;
		*) die "neoproot targets 64-bit ARM only (found $(uname -m))" ;;
	esac
}

read_state() { # read_state PREFIX -> prints saved key=value lines
	_state=$(state_file "$1")
	[ -r "$_state" ] && cat "$_state"
	return 0
}

prefix_default() {
	case "$MODE" in
	termux) printf '%s\n' "$PREFIX" ;;
	*) printf '%s\n' "$HOME/.local" ;;
	esac
}

# The interactive default matches what the script used before the transaction
# work: PREFIX when it is set (/usr/local otherwise), not the non-interactive
# $HOME/.local.
prefix_asked_default() {
	if [ -n "$PREFIX" ]; then
		printf '%s\n' "$PREFIX"
	else
		printf '%s\n' /usr/local
	fi
}

# The prefix has to be known before the lock is taken.  For --update and
# --recover it comes from --prefix or from the state file of the install being
# touched; an interactive install asks before the lock, because the answer
# decides which prefix is locked.
resolve_update_prefix() {
	[ -n "$PREFIX_DIR" ] && return 0
	for _candidate in "$PREFIX" "$HOME/.local" /usr/local; do
		[ -n "$_candidate" ] || continue
		if [ -r "$(state_file "$_candidate")" ] || [ -d "$(txn_dir_for "$_candidate")" ]; then
			PREFIX_DIR=$_candidate
			return 0
		fi
	done
	return 0
}

if [ "$MODE" = "auto" ]; then
	_npim=$(printenv NEOPROOT_INSTALL_MODE) || _npim=
	[ -n "$_npim" ] && MODE=$_npim
fi
case "$MODE" in auto|termux|linux) ;; *) die "--mode must be auto, termux or linux" ;; esac
if [ "$MODE" = "auto" ]; then
	if is_termux; then MODE=termux; else MODE=linux; fi
fi
[ "$MODE" = "termux" ] && ! is_termux && warn "forced termux mode outside Termux: the build may fail"

require_sha256

# One trap for the whole run: an interrupted transaction is rolled back, the
# locks are released and the scratch build directory is removed, whatever the
# exit path was.
finish() {
	_fin_status=$?
	if [ "$TXN_OPEN" = 1 ]; then
		if [ -s "$TXN_DIR/journal" ]; then
			warn "rolling the unfinished transaction back"
			if txn_rollback; then
				txn_close_rolledback
			else
				warn "the rollback could not finish; the transaction is kept in $TXN_DIR"
			fi
		else
			# Nothing was replaced, so there is nothing to undo: the staging
			# area is just scratch space.
			rm -rf "$TXN_DIR" 2>/dev/null || true
			TXN_OPEN=0
		fi
	fi
	release_guest_lock
	if [ -n "$STAGE_DIR" ]; then
		rm -rf "$STAGE_DIR"
	fi
	release_prefix_lock
	return "$_fin_status"
}
trap 'finish' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---------------------------------------------------------------------------
# --recover: finish what an interrupted run left behind, install nothing
# ---------------------------------------------------------------------------
if [ "$RECOVER" = 1 ]; then
	resolve_update_prefix
	[ -n "$PREFIX_DIR" ] ||
		die "--recover needs --prefix DIR (no install-state was found to read one from)"
	[ -d "$PREFIX_DIR" ] ||
		die "no install found in $PREFIX_DIR; nothing to recover"
	lock_prefix "$PREFIX_DIR"
	if [ -d "$(txn_dir_for "$PREFIX_DIR")" ]; then
		txn_recover "$PREFIX_DIR"
		log "recovery finished for $PREFIX_DIR"
	else
		log "no unfinished transaction in $PREFIX_DIR; nothing to recover"
	fi
	exit 0
fi

# ---------------------------------------------------------------------------
# --update: replace what this script owns, keep what the user chose
#
# The state file a previous install wrote says which prefix and which options
# were used, so an update does not have to ask again -- and must not silently
# switch someone from a portable build to a release one, or move their files.
# ---------------------------------------------------------------------------
if [ "$ACTION" = "update" ]; then
	resolve_update_prefix
	[ -n "$PREFIX_DIR" ] ||
		die "cannot tell which install to update; pass --prefix DIR"

	lock_prefix "$PREFIX_DIR"
	txn_recover "$PREFIX_DIR"

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
		with_um=0) FORCE_NO_UM=1; WITH_UM=0 ;;
		esac
	done

	tag=$(resolve_tag)
	# "Already current" is decided from the record, not from the file's mtime:
	# a copy or a backup restores the old one with a fresh timestamp.
	_installed_version=$(sed -n 's/^version=//p' "$(state_file "$PREFIX_DIR")" 2>/dev/null)
	if [ "$_installed_version" = "$tag" ] && [ "$FORCE_UPDATE" != 1 ]; then
		log "already at $tag (use --force to reinstall anyway)"
		# The runtime has its own tags, so it can be behind even when the
		# binary is current, on Termux as well as Linux. Keep fast-only installs
		# fast-only; refresh when pins differ or any required helper is missing.
		if [ "$FORCE_NO_UM" = 1 ] || [ "$WITH_UM" = 0 ]; then
			log "runtime: disabled for this install"
			exit 0
		fi
		_saved_kernel=$(sed -n 's/^um_kernel_tag=//p' "$(state_file "$PREFIX_DIR")" 2>/dev/null)
		_saved_passt=$(sed -n 's/^um_passt_tag=//p' "$(state_file "$PREFIX_DIR")" 2>/dev/null)
		_um_incomplete=0
		for _name in linux-bionic stub_exe umnet passt-bionic; do
			[ -x "$PREFIX_DIR/libexec/neoproot/um/$_name" ] || _um_incomplete=1
		done
		if [ "$_saved_kernel" != "$UM_KERNEL_TAG" ] ||
			[ "$_saved_passt" != "$PASST_TAG" ] || [ "$_um_incomplete" = 1 ]; then
			_runtime_from=$_saved_kernel
			[ -n "$_runtime_from" ] || _runtime_from=none
			log "runtime: $_runtime_from -> $UM_KERNEL_TAG"
			txn_begin "$PREFIX_DIR" "$tag"
			stage_um_runtime "$PREFIX_DIR"
			stage_state "$PREFIX_DIR" "$tag" "$PORTABLE"
			commit_or_die
			if [ "$UM_RUNTIME_COMPLETE" = 1 ]; then
				log "UML runtime installed into $PREFIX_DIR/libexec/neoproot/um"
			fi
		else
			log "runtime: already at $UM_KERNEL_TAG"
		fi
		exit 0
	fi
	_updating_from=$_installed_version
	[ -n "$_updating_from" ] || _updating_from="an older build"
	log "updating $_updating_from -> $tag in $PREFIX_DIR"
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

if [ -z "$LANG_CHOICE" ]; then
	LANG_CHOICE=$(printenv NEOPROOT_LANG) || LANG_CHOICE=
fi
if [ -z "$LANG_CHOICE" ]; then
	_lc_all=$(printenv LC_ALL) || _lc_all=
	_lc_messages=$(printenv LC_MESSAGES) || _lc_messages=
	_lc_lang=$(printenv LANG) || _lc_lang=
	case "$_lc_all$_lc_messages$_lc_lang" in
	*zh*|*ZH*) LANG_CHOICE=zh ;;
	*) LANG_CHOICE=en ;;
	esac
fi

if [ "$INTERACTIVE" = yes ] && [ "$ACTION" != "update" ]; then
	_np_lang=$(printenv NEOPROOT_LANG) || _np_lang=
	if [ -z "$_np_lang" ]; then
		_lang_choice=$(ask_choice "$(t lang_q)" "$([ "$LANG_CHOICE" = zh ] && echo 1 || echo 2)" \
			"$(t lang_1)" "$(t lang_2)")
		[ "$_lang_choice" = 1 ] && LANG_CHOICE=zh || LANG_CHOICE=en
	fi
	printf '\n'
	printf '%s\n' "$(t welcome)"
	printf '  %s\n\n' "$(t each_default)"

	if [ -z "$PREFIX_DIR" ]; then
		PREFIX_DIR=$(ask_text "$(t q_prefix)" "$(prefix_asked_default)")
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

# ---------------------------------------------------------------------------
# Install
#
# Both platforms stage into the same transaction: the binary, the runtime and
# the shim are all fetched or built and verified first, then committed file by
# file with a rename.  --shim-rootfs is about the guest, not the host, so it
# applies to the source build on Termux just as much as to the downloaded
# binary.
# ---------------------------------------------------------------------------
[ -n "$PREFIX_DIR" ] || PREFIX_DIR=$(prefix_default)
[ -n "$PREFIX_DIR" ] || die "cannot tell where to install; pass --prefix DIR"
case "$PREFIX_DIR" in
*"$TAB"*|*"$_newline"*)
	die "the install prefix contains a tab or a newline; the transaction log cannot record it"
	;;
esac
lock_prefix "$PREFIX_DIR"
txn_recover "$PREFIX_DIR"

if [ "$MODE" = "termux" ]; then
	check_arch
	[ -n "$PREFIX" ] || die "PREFIX is not set; this does not look like Termux"
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
	_build_tmp=$TMPDIR
	[ "$TMPDIR_SET" = 1 ] || _build_tmp=$PREFIX/tmp
	mkdir -p "$_build_tmp" 2>/dev/null || die "cannot create $_build_tmp"
	STAGE_DIR=$(mktemp -d "$_build_tmp/neoproot-build.XXXXXX") ||
		die "cannot create a build directory under $_build_tmp"
	log "cloning $REPO at $tag"
	# An annotated tag is a tag object, not a commit: --branch accepts it but git
	# then warns "refs/tags/... is not a commit" and checks out the peeled commit
	# in detached HEAD, which reads like a failure to anyone watching.  Fetching
	# the tag explicitly and checking out its commit avoids the warning and makes
	# the intent obvious.
	git init --quiet "$STAGE_DIR/repo" || die "git init failed"
	if ! ( cd "$STAGE_DIR/repo" &&
	       git remote add origin "https://github.com/$REPO.git" &&
	       git fetch --quiet --depth 1 origin "refs/tags/$tag:refs/tags/$tag" &&
	       git checkout --quiet "refs/tags/$tag" ); then
		die "git fetch failed"
	fi
	LOG=$_build_tmp/neoproot-build.log
	log "compiling (a few minutes on a phone; log: $LOG)"
	# WITH_UM from the questions decides whether the supervisor is compiled in.
	_build_flag=
	[ "$WITH_UM" = 1 ] || _build_flag=--without-um
	if ! ( cd "$STAGE_DIR/repo" && sh build.sh $_build_flag ) >"$LOG" 2>&1; then
		tail -n 20 "$LOG" >&2
		die "build failed, full log in $LOG"
	fi

	txn_begin "$PREFIX_DIR" "$tag"
	stage_binary "$STAGE_DIR/repo/src/neoproot" "$PREFIX_DIR"
	# The build produces the supervisor; the kernel and the network helpers are
	# separate and come from their own releases, on the same "backend on means
	# fetch it" rule as the Linux path.
	if [ "$WITH_UM" = 1 ]; then
		stage_um_runtime "$PREFIX_DIR"
	fi
	stage_aliases "$PREFIX_DIR"
	if [ "$WITH_SHIM" = 1 ] && [ -n "$SHIM_ROOTFS" ]; then
		stage_shim_into "$SHIM_ROOTFS" "$tag"
	fi
	stage_state "$PREFIX_DIR" "$tag" 0
	commit_or_die
	if [ "$UM_RUNTIME_COMPLETE" = 1 ]; then
		log "UML runtime installed into $PREFIX_DIR/libexec/neoproot/um"
	fi
	if [ -n "$SHIM_INSTALLED_DEST" ]; then
		log "shim ($SHIM_INSTALLED_ABI) installed into $SHIM_INSTALLED_DEST from $tag release"
	fi
	"$PREFIX_DIR/bin/neoproot" --version 2>/dev/null ||
		warn "installed binary did not report a version"
else
	check_arch
	tag=$(resolve_tag)
	asset=neoproot
	[ "$PORTABLE" = 1 ] && asset=neoproot-portable
	base="https://github.com/$REPO/releases/download/$tag"
	mkdir -p "$TMPDIR" 2>/dev/null || die "cannot create $TMPDIR"
	STAGE_DIR=$(mktemp -d "$TMPDIR/neoproot-install.XXXXXX") ||
		die "cannot create a staging directory under $TMPDIR"

	txn_begin "$PREFIX_DIR" "$tag"
	log "downloading $asset $tag"
	fetch "$base/SHA256SUMS" "$TXN_DIR/staging/SHA256SUMS" ||
		die "could not download SHA256SUMS"
	SUMS_FILE=$TXN_DIR/staging/SHA256SUMS
	meta_load "$tag" || true
	fetch "$base/$asset" "$TXN_DIR/staging/$asset" || die "download failed"
	verify_asset "$TXN_DIR/staging/$asset" "$asset" "$SUMS_FILE" "" "$META_FILE"
	stage_binary "$TXN_DIR/staging/$asset" "$PREFIX_DIR"
	if [ "$WITH_UM" = 1 ]; then
		stage_um_runtime "$PREFIX_DIR"
	fi
	stage_aliases "$PREFIX_DIR"
	if [ "$WITH_SHIM" = 1 ] && [ -n "$SHIM_ROOTFS" ]; then
		stage_shim_into "$SHIM_ROOTFS" "$tag"
	fi
	stage_state "$PREFIX_DIR" "$tag" "$PORTABLE"
	commit_or_die
	if [ "$UM_RUNTIME_COMPLETE" = 1 ]; then
		log "UML runtime installed into $PREFIX_DIR/libexec/neoproot/um"
	fi
	if [ -n "$SHIM_INSTALLED_DEST" ]; then
		log "shim ($SHIM_INSTALLED_ABI) installed into $SHIM_INSTALLED_DEST from $tag release"
	fi
	"$PREFIX_DIR/bin/neoproot" --version 2>/dev/null ||
		warn "installed binary did not report a version"
fi

next_steps
