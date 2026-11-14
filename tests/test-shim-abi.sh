#!/bin/sh
# install.sh --shim-rootfs must pick the shim by the guest's libc ABI.
#
# The shim is an LD_PRELOAD library, so a glibc rootfs and an Alpine/musl
# rootfs need different builds of it.  This test fabricates both loaders in
# throw-away rootfs directories and a fake source tree whose build scripts
# produce two distinguishable .so files (their DT_NEEDED says libc.so.6 or
# libc.musl-aarch64.so.1).  It then runs the real install.sh and inspects the
# library that ended up at /opt/neoproot/libstatfast.so -- the fixed name the
# tracer auto-discovers.
#
# No real rootfs, container or guest is needed.  Exits 125 when the host has
# no C compiler or readelf (the suite treats 125 as "skipped").
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CC=${CC:-cc}

command -v "$CC" >/dev/null 2>&1 || { echo 'skip: no C compiler'; exit 125; }
command -v readelf >/dev/null 2>&1 || { echo 'skip: readelf unavailable'; exit 125; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-shim-abi.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

fail() { printf '%s\n' "shim ABI test: $*" >&2; exit 1; }

# A .so whose NEEDED entry names a libc, without linking against the real one:
# SONAME-only stub libraries let the linker record any NEEDED string on any
# host, so this works on glibc, musl and Termux/bionic alike.
mkdir -p "$WORK/fixtures"
printf '%s\n' 'void neoproot_abi_stub(void) {}' >"$WORK/fixtures/stub.c"
printf '%s\n' 'void neoproot_abi_fixture(void) {}' >"$WORK/fixtures/fixture.c"
"$CC" -shared -fPIC -nostdlib -Wl,-soname,libc.so.6 \
	-o "$WORK/fixtures/libc.so.6" "$WORK/fixtures/stub.c"
"$CC" -shared -fPIC -nostdlib -Wl,-soname,libc.musl-aarch64.so.1 \
	-o "$WORK/fixtures/libc.musl-aarch64.so.1" "$WORK/fixtures/stub.c"
"$CC" -shared -fPIC -nostdlib -Wl,--no-as-needed \
	-o "$WORK/fixtures/libstatfast-glibc.so" "$WORK/fixtures/fixture.c" \
	-L"$WORK/fixtures" -l:libc.so.6
"$CC" -shared -fPIC -nostdlib -Wl,--no-as-needed \
	-o "$WORK/fixtures/libstatfast-musl.so" "$WORK/fixtures/fixture.c" \
	-L"$WORK/fixtures" -l:libc.musl-aarch64.so.1

assert_abi() { # assert_abi FILE musl|glibc
	_case_abi=$2
	if [ "$_case_abi" = musl ]; then
		_pattern=libc.musl-aarch64.so.1
	else
		_pattern=libc.so.6
	fi
	if ! readelf -d "$1" 2>/dev/null | grep -F "NEEDED" | grep -F "$_pattern" >/dev/null; then
		printf '%s\n' "expected $_case_abi ($_pattern) in $1, got:" >&2
		readelf -d "$1" 2>/dev/null | grep -F NEEDED >&2 || true
		exit 1
	fi
}

assert_abi "$WORK/fixtures/libstatfast-glibc.so" glibc
assert_abi "$WORK/fixtures/libstatfast-musl.so" musl

# A fake source tree: install.sh only needs build.sh to produce src/neoproot,
# and the two stat-shim build scripts to produce their named artifacts.
mkdir -p "$WORK/project/stat-shim" "$WORK/project/src"
cp "$REPO_ROOT/install.sh" "$WORK/project/install.sh"
cat >"$WORK/project/build.sh" <<EOF
#!/bin/sh
set -eu
here=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
mkdir -p "\$here/src" "\$here/stat-shim"
cp "$WORK/fixtures/libstatfast-glibc.so" "\$here/stat-shim/libstatfast.so"
printf '#!/bin/sh\\nprintf \\\"fake-neoproot\\\\n\\\"\\n' >"\$here/src/neoproot"
chmod 755 "\$here/src/neoproot"
EOF
cat >"$WORK/project/stat-shim/build-musl.sh" <<EOF
#!/bin/sh
set -eu
here=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
echo 'fake build-musl'
cp "$WORK/fixtures/libstatfast-musl.so" "\$here/libstatfast-musl.so"
EOF
chmod 755 "$WORK/project/build.sh" "$WORK/project/stat-shim/build-musl.sh"

# Rootfs markers: exactly what install.sh looks at, nothing else.
mkdir -p "$WORK/rootfs-musl/lib" "$WORK/rootfs-glibc/lib" "$WORK/rootfs-glibc64/lib64"
mkdir -p "$WORK/rootfs-both/lib" "$WORK/rootfs-both/lib64" "$WORK/rootfs-none"
: >"$WORK/rootfs-musl/lib/ld-musl-aarch64.so.1"
: >"$WORK/rootfs-glibc/lib/ld-linux-aarch64.so.1"
: >"$WORK/rootfs-glibc64/lib64/ld-linux-aarch64.so.1"
: >"$WORK/rootfs-both/lib/ld-musl-aarch64.so.1"
: >"$WORK/rootfs-both/lib64/ld-linux-aarch64.so.1"

run_install() { # run_install LOG ROOTFS PREFIX [extra args...]
	_run_log=$1
	_run_rootfs=$2
	_run_prefix=$3
	shift 3
	set +e
	( cd "$WORK/project" && sh ./install.sh --prefix="$_run_prefix" \
		--without-um --non-interactive --shim-rootfs="$_run_rootfs" "$@" ) \
		>"$_run_log" 2>&1
	_run_status=$?
	set -e
	printf '%s\n' "$_run_status"
}

check_installed() { # check_installed ROOTFS ABI LOG
	_ci_so=$1/opt/neoproot/libstatfast.so
	[ -f "$_ci_so" ] || { cat "$3" >&2; fail "no $_ci_so after install"; }
	assert_abi "$_ci_so" "$2"
}

# musl rootfs: build-musl.sh must supply libstatfast-musl.so, then the copy
# must still be named libstatfast.so.
status=$(run_install "$WORK/musl.log" "$WORK/rootfs-musl" "$WORK/prefix-musl")
[ "$status" = 0 ] || { cat "$WORK/musl.log" >&2; fail "musl install failed ($status)"; }
grep -F 'fake build-musl' "$WORK/musl.log" >/dev/null ||
	fail 'musl rootfs did not trigger stat-shim/build-musl.sh'
grep -F 'shim (musl)' "$WORK/musl.log" >/dev/null ||
	fail 'musl install did not report the musl variant'
check_installed "$WORK/rootfs-musl" musl "$WORK/musl.log"
assert_abi "$WORK/prefix-musl/libexec/neoproot/libstatfast.so" glibc

# glibc rootfs: lib/ld-linux-aarch64.so.1 and the merged-/usr lib64 spelling.
for root in "$WORK/rootfs-glibc" "$WORK/rootfs-glibc64"; do
	prefix="$WORK/prefix-$(basename "$root")"
	log="$WORK/$(basename "$root").log"
	status=$(run_install "$log" "$root" "$prefix")
	[ "$status" = 0 ] || { cat "$log" >&2; fail "glibc install failed ($status)"; }
	grep -F 'shim (glibc)' "$log" >/dev/null || fail 'glibc install did not report the glibc variant'
	check_installed "$root" glibc "$log"
done

# Ambiguous and unrecognisable rootfs: stop before building and name the fix.
status=$(run_install "$WORK/both.log" "$WORK/rootfs-both" "$WORK/prefix-both")
[ "$status" = 2 ] || { cat "$WORK/both.log" >&2; fail "both-loaders exit $status, want 2"; }
grep -F '同时有 musl 和 glibc' "$WORK/both.log" >/dev/null ||
	fail 'both-loaders error does not explain the ambiguity'

status=$(run_install "$WORK/none.log" "$WORK/rootfs-none" "$WORK/prefix-none")
[ "$status" = 2 ] || { cat "$WORK/none.log" >&2; fail "no-loader exit $status, want 2"; }
grep -F '没有找到 aarch64 loader' "$WORK/none.log" >/dev/null ||
	fail 'no-loader error does not mention the missing loader'

# The override rescues an unusual layout and still uses the musl artifact.
status=$(run_install "$WORK/override.log" "$WORK/rootfs-none" "$WORK/prefix-override" --shim-abi=musl)
[ "$status" = 0 ] || { cat "$WORK/override.log" >&2; fail "override install failed ($status)"; }
check_installed "$WORK/rootfs-none" musl "$WORK/override.log"

# The one-command installer (scripts/install.sh) has the same rule, but takes
# its artifacts from the release.  A fake curl serves a release with and
# without libstatfast-musl.so so neither the network nor GitHub is needed.
command -v sha256sum >/dev/null 2>&1 || { echo 'skip: sha256sum unavailable'; exit 125; }
mkdir -p "$WORK/fakebin" "$WORK/release"
printf '#!/bin/sh\nprintf \"test-neoproot\\n\"\n' >"$WORK/release/neoproot"
chmod 755 "$WORK/release/neoproot"
( cd "$WORK/release" && sha256sum neoproot >SHA256SUMS )
cat >"$WORK/fakebin/curl" <<'EOF'
#!/bin/sh
out=
url=
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
*/libstatfast-musl.so)
	[ "${FAKE_MUSL_ASSET:-1}" = 1 ] && cp "$FAKE_MUSL_SO" "$out" || exit 22
	;;
*/libstatfast.so)
	[ "${FAKE_GLIBC_ASSET:-1}" = 1 ] && cp "$FAKE_GLIBC_SO" "$out" || exit 22
	;;
*) exit 22 ;;
esac
EOF
chmod 755 "$WORK/fakebin/curl"

run_release_install() { # run_release_install LOG ROOTFS PREFIX MUSL_ASSET
	set +e
	PATH="$WORK/fakebin:$PATH" PREFIX="$WORK/empty-prefix" TMPDIR="$WORK" \
		FAKE_SHA256SUMS="$WORK/release/SHA256SUMS" \
		FAKE_NEOPROOT="$WORK/release/neoproot" \
		FAKE_MUSL_SO="$WORK/fixtures/libstatfast-musl.so" \
		FAKE_GLIBC_SO="${6:-$WORK/fixtures/libstatfast-glibc.so}" \
		FAKE_MUSL_ASSET="$4" FAKE_GLIBC_ASSET="${5:-1}" \
		sh "$REPO_ROOT/scripts/install.sh" --version vTEST --mode linux -y \
		--prefix "$3" --without-um --shim-rootfs "$2" >"$1" 2>&1
	_run_status=$?
	set -e
	printf '%s\n' "$_run_status"
}

mkdir -p "$WORK/rel-rootfs-musl/lib" "$WORK/rel-rootfs-glibc/lib"
: >"$WORK/rel-rootfs-musl/lib/ld-musl-aarch64.so.1"
: >"$WORK/rel-rootfs-glibc/lib/ld-linux-aarch64.so.1"

# A release without the musl asset: install succeeds, the shim is skipped, and
# the user is told how to get one.
status=$(run_release_install "$WORK/rel-missing.log" "$WORK/rel-rootfs-musl" "$WORK/rel-prefix-missing" 0)
[ "$status" = 0 ] || { cat "$WORK/rel-missing.log" >&2; fail "release-without-musl failed ($status)"; }
grep -F 'could not fetch libstatfast-musl.so' "$WORK/rel-missing.log" >/dev/null ||
	fail 'release installer does not report a missing musl asset'
[ ! -e "$WORK/rel-rootfs-musl/opt/neoproot/libstatfast.so" ] ||
	fail 'release installer copied a shim when the musl asset was missing'

# With the asset published, musl gets libstatfast-musl.so under the fixed name.
status=$(run_release_install "$WORK/rel-musl.log" "$WORK/rel-rootfs-musl" "$WORK/rel-prefix-musl" 1)
[ "$status" = 0 ] || { cat "$WORK/rel-musl.log" >&2; fail "release musl install failed ($status)"; }
grep -F 'shim (musl)' "$WORK/rel-musl.log" >/dev/null ||
	fail 'release installer did not report the musl variant'
check_installed "$WORK/rel-rootfs-musl" musl "$WORK/rel-musl.log"

# And glibc still takes libstatfast.so.
status=$(run_release_install "$WORK/rel-glibc.log" "$WORK/rel-rootfs-glibc" "$WORK/rel-prefix-glibc" 1)
[ "$status" = 0 ] || { cat "$WORK/rel-glibc.log" >&2; fail "release glibc install failed ($status)"; }
grep -F 'shim (glibc)' "$WORK/rel-glibc.log" >/dev/null ||
	fail 'release installer did not report the glibc variant'
check_installed "$WORK/rel-rootfs-glibc" glibc "$WORK/rel-glibc.log"

# A rootfs that already holds a matching-ABI shim must still be refreshed from
# the release.  The old code took the guest file as its own source, cp failed
# with "are the same file" and the error was swallowed: the stale file stayed
# and no shim line was printed at all.
printf 'stale-marker' >>"$WORK/rel-rootfs-glibc/opt/neoproot/libstatfast.so"
status=$(run_release_install "$WORK/rel-refresh.log" "$WORK/rel-rootfs-glibc" "$WORK/rel-prefix-refresh" 1)
[ "$status" = 0 ] || { cat "$WORK/rel-refresh.log" >&2; fail "release shim refresh failed ($status)"; }
grep -F 'shim (glibc) installed into' "$WORK/rel-refresh.log" >/dev/null ||
	fail 'release installer did not report refreshing an existing guest shim'
cmp -s "$WORK/rel-rootfs-glibc/opt/neoproot/libstatfast.so" "$WORK/fixtures/libstatfast-glibc.so" ||
	fail 'release installer did not replace the stale guest shim'

# Download failures must not put bionic, unknown or musl cache files into glibc.
"$CC" -shared -fPIC -nostdlib -Wl,-soname,libc.so \
	-o "$WORK/fixtures/libc.so" "$WORK/fixtures/stub.c"
"$CC" -shared -fPIC -nostdlib -Wl,--no-as-needed \
	-o "$WORK/fixtures/libstatfast-bionic.so" "$WORK/fixtures/fixture.c" \
	-L"$WORK/fixtures" -l:libc.so
printf 'truncated' >"$WORK/fixtures/libstatfast-unknown.so"
mkdir -p "$WORK/empty-prefix/libexec/neoproot"
for kind in bionic unknown musl; do
	guard_root="$WORK/guard-$kind"
	mkdir -p "$guard_root/lib"
	: >"$guard_root/lib/ld-linux-aarch64.so.1"
	cp "$WORK/fixtures/libstatfast-$kind.so" "$WORK/empty-prefix/libexec/neoproot/libstatfast.so"
	status=$(run_release_install "$WORK/guard-$kind.log" "$guard_root" "$WORK/guard-prefix-$kind" 1 0)
	[ "$status" = 0 ] || fail "guard install failed ($kind, $status)"
	[ ! -e "$guard_root/opt/neoproot/libstatfast.so" ] || fail "$kind cache entered glibc guest"
	grep -F 'ignoring it' "$WORK/guard-$kind.log" >/dev/null || fail "$kind rejection was silent"
done

# A downloaded file with an unconfirmed ABI is refused too.
status=$(run_release_install "$WORK/guard-download.log" "$WORK/guard-bionic" "$WORK/guard-download-prefix" 1 1 "$WORK/fixtures/libstatfast-bionic.so")
[ "$status" = 0 ] || fail "download guard failed ($status)"
[ ! -e "$WORK/guard-bionic/opt/neoproot/libstatfast.so" ] || fail 'bionic download entered glibc guest'
grep -F 'refusing to install' "$WORK/guard-download.log" >/dev/null || fail 'download rejection was silent'

# A confirmed glibc cache remains a valid fallback when the release is offline.
cp "$WORK/fixtures/libstatfast-glibc.so" "$WORK/empty-prefix/libexec/neoproot/libstatfast.so"
status=$(run_release_install "$WORK/guard-cache.log" "$WORK/guard-bionic" "$WORK/guard-cache-prefix" 1 0)
[ "$status" = 0 ] || fail "matching cache failed ($status)"
check_installed "$WORK/guard-bionic" glibc "$WORK/guard-cache.log"
grep -F 'from cached' "$WORK/guard-cache.log" >/dev/null || fail 'matching cache was not used'

printf '%s\n' 'shim ABI install tests passed'
