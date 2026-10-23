#!/bin/sh
#
# --seccomp and --quiet are kernel command-line arguments, not guest options.
# A mock kernel records the vector so the contract can be checked without a
# real UML kernel or rootfs image.
#
# SECCOMP is deliberately opt-in: the UML kernel documentation says the filter
# is not restrictive enough to keep an untrusted guest out of all physical
# memory.  The default must therefore stay ptrace, and only the explicit modes
# may add the argument.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor="$script_directory/../src/neoproot-um"

if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: UML supervisor seccomp test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-seccomp.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

argv_file="$temporary_directory/argv"
rootfs="$temporary_directory/rootfs"
kernel="$temporary_directory/kernel"
mkdir "$rootfs"

cat >"$kernel" <<MOCK_KERNEL
#!/bin/sh
: >"$argv_file"
for argument in "\$@"; do
	printf '%s\n' "\$argument" >>"$argv_file"
done
exit 0
MOCK_KERNEL
chmod 755 "$kernel"

fail() {
	echo "FAIL: $1" >&2
	if [ -f "$argv_file" ]; then
		echo "--- kernel vector ---" >&2
		cat "$argv_file" >&2
	fi
	exit 1
}

run() {
	rm -f "$argv_file"
	TMPDIR="$temporary_directory" "$um_supervisor" \
		--kernel="$kernel" --stub="$kernel" \
		--rootfs="$rootfs" --hostfs "$@" -- /bin/true \
		>/dev/null 2>&1 || true
	[ -s "$argv_file" ] || fail "the mock kernel was not reached for: $*"
}

has() {
	grep -qx -- "$1" "$argv_file" || fail "kernel vector is missing '$1' (for: $2)"
}

has_not() {
	if grep -qx -- "$1" "$argv_file"; then
		fail "kernel vector unexpectedly contains '$1' (for: $2)"
	fi
}

# Default: the kernel stays in its safe ptrace mode and boot output is not
# suppressed.  This is the security-relevant assertion.
run
has_not "seccomp=auto" "default"
has_not "seccomp=on" "default"
has_not "seccomp=off" "default"
has_not "quiet" "default"
has_not "loglevel=1" "default"

# The two safe spellings of the explicit modes.
run --seccomp=auto
has "seccomp=auto" "--seccomp=auto"
has_not "quiet" "--seccomp=auto"

run --seccomp=on
has "seccomp=on" "--seccomp=on"

# off means the kernel default; no argument is needed (and adding one would
# make the default path look different from an omitted option).
run --seccomp=off
has_not "seccomp=off" "--seccomp=off"
has_not "seccomp=auto" "--seccomp=off"

# Quiet is independent of the syscall mode.
run --quiet
has "quiet" "--quiet"
has "loglevel=1" "--quiet"
has_not "seccomp=auto" "--quiet"

run --seccomp=auto --quiet
has "seccomp=auto" "--seccomp=auto --quiet"
has "quiet" "--seccomp=auto --quiet"
has "loglevel=1" "--seccomp=auto --quiet"

# The option must also survive neoproot's dispatcher.  That path is the one a
# user actually types; testing only neoproot-um would leave a pass-through
# regression invisible.
neoproot="$script_directory/../src/neoproot"
if [ -x "$neoproot" ]; then
	rm -f "$argv_file"
	NEOPROOT_UM_KERNEL="$kernel" NEOPROOT_UM_STUB="$kernel" \
		TMPDIR="$temporary_directory" "$neoproot" --backend=um \
		-r "$rootfs" --hostfs --seccomp=auto --quiet -- /bin/true \
		>/dev/null 2>&1 || true
	[ -s "$argv_file" ] || fail "neoproot dispatch did not reach the mock kernel"
	has "seccomp=auto" "neoproot dispatch"
	has "quiet" "neoproot dispatch"
fi

echo "UM supervisor seccomp/quiet argv tests passed"
