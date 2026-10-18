#!/bin/sh
#
# The command separator has to mean the same thing on every backend.
#
# neoproot's own CLI treats `--` as "everything after this is the guest
# command".  The UM backend also needs the delimiter in the vector it is handed,
# because that is its documented syntax; the PRoot path must not receive it at
# all, because the guest command's own parser does not know it.
#
# The two were conflated: prepare_backend_argv() set its "command started" flag
# and copied `--` into the forwarded vector, unconditionally.  So
#
#     neoproot -r /rootfs -- /bin/sh
#
# failed with "unknown option '--'" on every backend except UM, and one command
# line could not be reused with a different --backend -- which is precisely what
# `auto` has to make possible.  Nothing caught it because the CLI tests only
# exercise option validation and the UM tests pass `--` deliberately.
#
# Checked without a real kernel or rootfs: what matters is how the separator is
# routed, and the mock kernel records the vector it was given.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
neoproot="$script_directory/../src/neoproot"

if [ ! -x "$neoproot" ]; then
	echo "skip: $neoproot is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: backend CLI test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-backend.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

argv_file="$temporary_directory/argv"
rootfs="$temporary_directory/rootfs"
kernel="$temporary_directory/kernel"
mkdir "$rootfs"

# The mock kernel is resolved by path, so it only has to be executable.  It
# records the vector it was exec'd with.
cat >"$kernel" <<MOCK_KERNEL
#!/bin/sh
: >"$argv_file"
for argument do
	printf '%s\\n' "\$argument" >>"$argv_file"
done
exit 0
MOCK_KERNEL
chmod 755 "$kernel"

fail() {
	echo "FAIL: $1" >&2
	if [ -f "$argv_file" ]; then
		echo "--- forwarded vector ---" >&2
		cat "$argv_file" >&2
	fi
	exit 1
}

# --- the UM backend is reached, with or without the separator -------------
#
# What proves the delimiter arrived is that the kernel was started at all: the
# supervisor refuses to run without it, so an empty record means the separator
# never made it.  The kernel's own vector carries kernel arguments, not the
# guest command, so the guest command cannot be asserted here -- the point is
# only that the run got through.
#
# Both spellings matter.  With `--` it is the documented syntax; without it, the
# CLI still knows where the command began, and the backend it dispatches to must
# not see the difference.
for spelling in with without; do
	rm -f "$argv_file"
	if [ "$spelling" = with ]; then
		NEOPROOT_UM_KERNEL="$kernel" NEOPROOT_UM_STUB="$kernel" \
			"$neoproot" --backend=um -r "$rootfs" -- /guest-command \
			>/dev/null 2>&1 || true
	else
		NEOPROOT_UM_KERNEL="$kernel" NEOPROOT_UM_STUB="$kernel" \
			"$neoproot" --backend=um -r "$rootfs" /guest-command \
			>/dev/null 2>&1 || true
	fi
	[ -s "$argv_file" ] ||
		fail "the UM backend was not reached ($spelling the separator)"
done

# --- no other backend may see it ------------------------------------------
#
# They do not get as far as a vector without a real rootfs, so the check is on
# what they say: an unknown-option complaint about `--` means the separator
# leaked through, and that is the bug.
for mode in "" "--backend=fast" "--backend=auto" "--backend=default"; do
	output=$("$neoproot" $mode -r "$rootfs" -- /guest-command 2>&1 || true)
	case "$output" in
	*"unknown option '--'"*)
		fail "the separator leaked through to the ${mode:-default} backend" ;;
	esac
done

# --- an image rootfs is UML-only ------------------------------------------
#
# PRoot translates guest paths into host paths and an image has none, so it
# cannot use one.  The dispatcher must say that, rather than let PRoot bind the
# image as a rootfs and fail on its first path translation -- or complain that
# --cow-file is an unknown option.
image="$temporary_directory/image"
dd if=/dev/zero of="$image" bs=1024 count=8 2>/dev/null
for mode in "" "--backend=fast" "--backend=auto" "--backend=default"; do
	output=$("$neoproot" $mode -r "$image" -- /guest-command 2>&1 || true)
	case "$output" in
	*"only the um backend can use it"*) ;;
	*) fail "the ${mode:-default} backend did not explain the image rootfs: $output" ;;
	esac
done

# --cow-file is an image-only option, and says so instead of "unknown option".
output=$("$neoproot" --backend=fast -r "$rootfs" --cow-file "$image" -- 	/guest-command 2>&1 || true)
case "$output" in
*"filesystem image"*) ;;
*) fail "--cow-file without UML was not explained: $output" ;;
esac

# The UML backend still gets the image (the mock kernel is what runs).
rm -f "$argv_file"
NEOPROOT_UM_KERNEL="$kernel" NEOPROOT_UM_STUB="$kernel" 	"$neoproot" --backend=um -r "$image" -- /guest-command 	>/dev/null 2>&1 || true
[ -s "$argv_file" ] ||
	fail "the UML backend did not receive an image rootfs"

echo "backend CLI separator tests passed"
