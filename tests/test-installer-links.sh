#!/bin/sh
# The one-command installer must leave `neoproot-um` as a link to `neoproot`.
#
# neoproot contains the UML supervisor itself and selects it from argv[0], so a
# separate neoproot-um binary from an older release never follows a binary
# update: it keeps running last year's supervisor beside today's tracer.  The
# installer therefore replaces that file with a relative link (keeping the old
# one as neoproot-um.prev-<timestamp>).  `uproot` is a historical alias: an
# existing one is refreshed, but a fresh install does not invent one.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-links.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

fail() { printf '%s\n' "installer link test: $*" >&2; exit 1; }

command -v sha256sum >/dev/null 2>&1 || { echo 'skip: sha256sum unavailable'; exit 125; }

mkdir -p "$WORK/fakebin" "$WORK/release"
cat >"$WORK/release/neoproot" <<'EOF'
#!/bin/sh
printf 'fake-neoproot vTEST\n'
EOF
chmod 755 "$WORK/release/neoproot"
( cd "$WORK/release" && sha256sum neoproot >SHA256SUMS )

cat >"$WORK/fakebin/curl" <<'EOF'
#!/bin/sh
out=; url=
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift 2 ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
case "$url" in
*/SHA256SUMS) cp "$FAKE_SHA256SUMS" "$out" ;;
*/neoproot) cp "$FAKE_NEOPROOT" "$out" ;;
*/linux-bionic|*/stub_exe|*/umnet|*/passt-bionic|*/passt-android-arm64)
	printf '#!/bin/sh\nexit 0\n' >"$out" ;;
*) printf 'fake curl: unexpected %s\n' "$url" >&2; exit 22 ;;
esac
EOF
chmod 755 "$WORK/fakebin/curl"

run_install() { # run_install LOG PREFIX [extra args...]
	_run_log=$1
	_run_prefix=$2
	shift 2
	set +e
	PATH="$WORK/fakebin:$PATH" \
		FAKE_SHA256SUMS="$WORK/release/SHA256SUMS" \
		FAKE_NEOPROOT="$WORK/release/neoproot" \
		sh "$REPO_ROOT/scripts/install.sh" --version vTEST --mode linux -y \
		--prefix "$_run_prefix" "$@" >"$_run_log" 2>&1
	_run_status=$?
	set -e
	printf '%s\n' "$_run_status"
}

assert_link() { # assert_link PATH
	[ -L "$1" ] || fail "$1 is not a symlink"
	[ "$(readlink "$1")" = neoproot ] || fail "$1 does not point at neoproot"
}

# 1. An old standalone neoproot-um is replaced by a link and kept as a backup.
P1="$WORK/prefix-old-um"
mkdir -p "$P1/bin"
printf 'old-neoproot-um\n' >"$P1/bin/neoproot-um"
status=$(run_install "$WORK/old-um.log" "$P1")
[ "$status" = 0 ] || { cat "$WORK/old-um.log" >&2; fail "install with an old neoproot-um failed ($status)"; }
assert_link "$P1/bin/neoproot-um"
backup=$(ls "$P1/bin"/neoproot-um.prev-* 2>/dev/null | head -n 1)
[ -n "$backup" ] || fail 'the old neoproot-um was not backed up'
grep -qx 'old-neoproot-um' "$backup" || fail 'the backup is not the old neoproot-um'
[ "$("$P1/bin/neoproot-um" --version)" = "$("$P1/bin/neoproot" --version)" ] ||
	fail 'neoproot-um --version differs from neoproot --version'
[ ! -e "$P1/bin/uproot" ] && [ ! -L "$P1/bin/uproot" ] ||
	fail 'a fresh install created uproot, which it should not'

# 2. An existing uproot alias is kept pointing at neoproot.
P2="$WORK/prefix-uproot"
mkdir -p "$P2/bin"
ln -s neoproot "$P2/bin/uproot"
status=$(run_install "$WORK/uproot.log" "$P2")
[ "$status" = 0 ] || { cat "$WORK/uproot.log" >&2; fail "install with uproot failed ($status)"; }
assert_link "$P2/bin/uproot"

# 3. Installing without the um backend renames a stale neoproot-um instead of
#    leaving it to run against a binary that has no supervisor.
P3="$WORK/prefix-no-um"
mkdir -p "$P3/bin"
printf 'old-neoproot-um\n' >"$P3/bin/neoproot-um"
status=$(run_install "$WORK/no-um.log" "$P3" --without-um)
[ "$status" = 0 ] || { cat "$WORK/no-um.log" >&2; fail "install without um failed ($status)"; }
[ ! -e "$P3/bin/neoproot-um" ] && [ ! -L "$P3/bin/neoproot-um" ] ||
	fail 'neoproot-um survived an install without the um backend'
ls "$P3/bin"/neoproot-um.stale-* >/dev/null 2>&1 ||
	fail 'the stale neoproot-um was not renamed'

# 4. Updating a different release preserves the recorded fast-only choice.
P4="$WORK/prefix-update-no-um"
mkdir -p "$P4/libexec/neoproot"
cat >"$P4/libexec/neoproot/install-state" <<EOF
version=vOLD
prefix=$P4
portable=0
with_um=0
um_kernel_tag=old
um_passt_tag=old
EOF
status=$(run_install "$WORK/update-no-um.log" "$P4" --update)
[ "$status" = 0 ] || { cat "$WORK/update-no-um.log" >&2; fail "fast-only update failed ($status)"; }
[ ! -e "$P4/bin/neoproot-um" ] && [ ! -L "$P4/bin/neoproot-um" ] ||
	fail 'fast-only update created neoproot-um'
[ ! -d "$P4/libexec/neoproot/um" ] || fail 'fast-only update fetched a runtime'
grep -qx 'version=vTEST' "$P4/libexec/neoproot/install-state" || fail 'version was not updated'
grep -qx 'with_um=0' "$P4/libexec/neoproot/install-state" || fail 'fast-only choice was lost'

printf '%s\n' 'installer link tests passed'
