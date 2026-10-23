#!/bin/sh
#
# --cpus and --rootflags are UML kernel command-line options.  This test uses
# a mock kernel to assert the vector without a real kernel or rootfs.
#
# --cpus > 1 is only meaningful with seccomp userspace: ptrace can drive one
# CPU thread, and the supervisor must say so instead of silently clamping.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor="$script_directory/../src/neoproot-um"

if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: UML supervisor optimization test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-optim.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

argv_file="$temporary_directory/argv"
rootfs="$temporary_directory/rootfs"
image="$temporary_directory/rootfs.ext4"
kernel="$temporary_directory/kernel"
mkdir "$rootfs"
dd if=/dev/zero of="$image" bs=1 count=2048 2>/dev/null
printf '\123\357' | dd of="$image" bs=1 seek=1080 conv=notrunc 2>/dev/null

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
		--kernel="$kernel" --stub="$kernel" "$@" -- /bin/true \
		>"$temporary_directory/out" 2>&1 || true
	[ -s "$argv_file" ] || { cat "$temporary_directory/out" >&2; fail "the mock kernel was not reached for: $*"; }
}

has() {
	grep -qx -- "$1" "$argv_file" || fail "kernel vector is missing '$1' (for: $2)"
}

has_not() {
	if grep -qx -- "$1" "$argv_file"; then
		fail "kernel vector unexpectedly contains '$1' (for: $2)"
	fi
}

# Default: one CPU, matching the pre-SMP supervisor behaviour.  The SMP kernel
# defaults to the host CPU count when ncpus= is absent, which would be a
# surprising change for every existing invocation.
run --rootfs="$rootfs" --hostfs
has "ncpus=1" "default"
has_not "rootflags=" "default"

# Explicit SMP is accepted when seccomp is also selected.
run --rootfs="$rootfs" --hostfs --cpus=4 --seccomp=auto
has "ncpus=4" "--cpus=4"
has "seccomp=auto" "--cpus=4"

# The alias is useful for callers coming from the harness, which spells the
# kernel argument ncpus=.
run --rootfs="$rootfs" --hostfs --ncpus=2 --seccomp=auto
has "ncpus=2" "--ncpus=2"

# Asking for SMP under ptrace is a request the kernel cannot honour.  Fail with
# a message that names the missing option rather than letting the kernel clamp
# it to one CPU after the caller has already sized the workload for four.
rm -f "$argv_file"
if TMPDIR="$temporary_directory" "$um_supervisor" \
	--kernel="$kernel" --stub="$kernel" --rootfs="$rootfs" --hostfs \
	--cpus=4 -- /bin/true >"$temporary_directory/out" 2>&1; then
	fail "--cpus=4 without seccomp succeeded"
fi
grep -q -F -- "--cpus greater than 1 requires --seccomp=auto" \
	"$temporary_directory/out" ||
	fail "the supervisor did not explain that --cpus needs seccomp"

# rootflags is an ext4 mount option; hostfs has no such mount.
rm -f "$argv_file"
if TMPDIR="$temporary_directory" "$um_supervisor" \
	--kernel="$kernel" --stub="$kernel" --rootfs="$rootfs" --hostfs \
	--rootflags=noatime -- /bin/true >"$temporary_directory/out" 2>&1; then
	fail "--rootflags on hostfs succeeded"
fi
grep -q -F -- "--rootflags requires an ext4 rootfs image" \
	"$temporary_directory/out" ||
	fail "the supervisor did not explain that --rootflags needs ext4"

# Read-only ext4 always keeps noload: replaying the journal would write the
# base image, which is exactly what --readonly forbids.  Caller options are
# appended after it and must survive intact.
run --rootfs="$image" --readonly
has "rootflags=noload" "readonly default"

run --rootfs="$image" --readonly --rootflags=commit=60,data=writeback
has "rootflags=noload,commit=60,data=writeback" "--rootflags readonly"

echo "UM supervisor cpus/rootflags argv tests passed"
