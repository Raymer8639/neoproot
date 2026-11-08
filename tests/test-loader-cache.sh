#!/bin/sh
# The embedded loader is identical on every run.  A stable, verified copy in
# the temp directory must be reused instead of writing a new file each time,
# and a damaged copy must be replaced rather than executed.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
CC=${CC:-cc}

case "$(uname -m)" in
    aarch64|arm64) ;;
    *)
        printf '%s\n' 'SKIP: loader cache test requires ARM64'
        exit 125
        ;;
esac

BASE=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-loader-cache.XXXXXX")
ROOT=$BASE/root
CACHE=$BASE/cache

cleanup() {
	rm -rf "$BASE"
}
trap cleanup EXIT INT TERM

mkdir -p "$ROOT" "$CACHE"
cat > "$BASE/probe.c" <<'EOF'
int main(void) { return 42; }
EOF
if "$CC" -static -O2 -o "$ROOT/probe" "$BASE/probe.c" 2>/dev/null; then
	BINDS=
else
	"$CC" -O2 -o "$ROOT/probe" "$BASE/probe.c"
	if [ -n "${PREFIX:-}" ]; then
		BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
	else
		BINDS="-b /usr -b /lib -b /lib64"
	fi
fi

run_probe() {
	set +e
	PROOT_UNSET_DONE=1 PROOT_TMP_DIR="$CACHE" "$PROOT" -r "$ROOT" $BINDS /probe
	status=$?
	set -e
	if [ "$status" -ne 42 ]; then
		printf 'loader cache test: probe returned %s, expected 42\n' "$status" >&2
		exit 1
	fi
}

run_probe
set -- "$CACHE"/proot-loader-v1-*
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	printf '%s\n' 'loader cache test: no cached loader after the first run' >&2
	ls -la "$CACHE" >&2
	exit 1
fi
LOADER=$1
FIRST_INODE=$(ls -i "$LOADER" | awk '{print $1}')

run_probe
SECOND_INODE=$(ls -i "$LOADER" | awk '{print $1}')
if [ "$FIRST_INODE" != "$SECOND_INODE" ]; then
	printf '%s\n' 'loader cache test: second run replaced the cached loader' >&2
	exit 1
fi

chmod u+w "$LOADER"
printf 'truncated cache entry' > "$LOADER"
run_probe
if [ "$(wc -c < "$LOADER")" -lt 1024 ]; then
	printf '%s\n' 'loader cache test: damaged cache entry was not republished' >&2
	exit 1
fi

FIRST_BYTE=$(od -An -tx1 -N4 "$LOADER" | tr -d ' \n')
if [ "$FIRST_BYTE" != "7f454c46" ]; then
	printf '%s\n' 'loader cache test: cache entry is not an ELF file' >&2
	exit 1
fi

set +e
PROOT_UNSET_DONE=1 PROOT_MEMFD_LOADER=0 PROOT_TMP_DIR="$CACHE" \
	"$PROOT" -r "$ROOT" $BINDS /probe
status=$?
set -e
if [ "$status" -ne 42 ]; then
	printf 'loader cache test: opt-out probe returned %s\n' "$status" >&2
	exit 1
fi
set -- "$CACHE"/proot-loader-v1-*
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	printf '%s\n' 'loader cache test: opt-out changed the cache directory' >&2
	exit 1
fi

printf '%s\n' 'loader cache test passed'
