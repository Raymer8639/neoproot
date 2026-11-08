#!/bin/sh
# The C launcher replaced "sh -c" but must keep what that script promised:
# clear the LD_* variables before the guest starts and cap the soft descriptor
# limit at 16384 without touching the hard limit.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
CC=${CC:-cc}

case "$(uname -m)" in
    aarch64|arm64) ;;
    *)
        printf '%s\n' 'SKIP: launcher environment test requires ARM64'
        exit 125
        ;;
esac

BASE=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-launcher-env.XXXXXX")
ROOT=$BASE/root
cleanup() {
	rm -rf "$BASE"
}
trap cleanup EXIT INT TERM
mkdir -p "$ROOT"

cat > "$BASE/probe.c" <<'EOF'
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	static const char *const leaks[] = {
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_BIND_NOW"
	};
	struct rlimit limit;
	int i;

	for (i = 0; i < 3; i++) {
		if (getenv(leaks[i]) != NULL) {
			printf("leaked %s\n", leaks[i]);
			return 10 + i;
		}
	}
	if (getrlimit(RLIMIT_NOFILE, &limit) == 0
	    && (limit.rlim_max == RLIM_INFINITY || limit.rlim_max >= 16384)
	    && limit.rlim_cur != 16384) {
		printf("soft nofile is %llu\n",
		       (unsigned long long)limit.rlim_cur);
		return 20;
	}
	return 0;
}
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

set +e
"$PROOT" -r "$ROOT" $BINDS /probe
status=$?
set -e
if [ "$status" -ne 0 ]; then
	printf 'launcher environment test: probe failed with %s\n' "$status" >&2
	exit 1
fi

printf '%s\n' 'launcher environment test passed'
