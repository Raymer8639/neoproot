#!/bin/sh
#
# CLI contract for --cow-file.
#
# What is checked here is everything the supervisor decides before the guest
# starts: which arguments are rejected and with which first line, what UBD
# vector is built, and who owns the COW file after the run.  The mock in place
# of the kernel reads the vector and touches the COW file itself, which is what
# the real kernel does with it.
#
# A real UML run is the only thing that can show that the guest sees its old
# writes again; tests/stability-um-backend.sh covers that on a Termux host.
#
# Exit: 0 passed, 1 failed, 125 nothing could be attempted.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor=${UM_SUPERVISOR:-"$script_directory/../src/neoproot-um"}
neoproot=${NEOPROOT:-"$script_directory/../src/neoproot"}
if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
if [ ! -x "$neoproot" ]; then
	echo "skip: $neoproot is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: UML supervisor test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-cow.XXXXXX")
runtime_parent="$temporary_directory/runtime"
mkdir "$runtime_parent"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

image="$temporary_directory/rootfs.ext4"
fake_kernel="$temporary_directory/kernel"
stub="$temporary_directory/stub"
args_file="$temporary_directory/args"
mode_file="$temporary_directory/mode"
status_value_file="$temporary_directory/status-value"
log_file="$temporary_directory/log"

# A minimal ext4 image: the supervisor only reads the magic at 1024+0x38.
dd if=/dev/zero of="$image" bs=1 count=2048 2>/dev/null
printf '\123\357' | dd of="$image" bs=1 seek=1080 conv=notrunc 2>/dev/null
image_size=$(wc -c <"$image" | tr -d ' ')
TZ=UTC touch -t 200902132331.30 "$image"
image_mtime=1234567890

# Emit one byte through printf's octal escape, which POSIX defines.
cow_byte() {
	printf "\\$(printf '%03o' "$1")"
}

cow_be32() {
	value=$1
	cow_byte $(( (value / 16777216) % 256 ))
	cow_byte $(( (value / 65536) % 256 ))
	cow_byte $(( (value / 256) % 256 ))
	cow_byte $(( value % 256 ))
}

# The header the kernel writes for this image (COW v3, big-endian fields).
write_cow_header() {
	target=$1
	mtime=$2
	size=$3
	{
		cow_byte 79
		cow_byte 79
		cow_byte 79
		cow_byte 77
		cow_byte 0
		cow_byte 0
		cow_byte 0
		cow_byte 3
		cow_be32 "$mtime"
		cow_be32 0
		cow_be32 "$size"
		cow_be32 512
		cow_be32 4096
		cow_be32 0
	} >"$target"
}

cat >"$fake_kernel" <<EOF
#!/bin/sh
set -eu
args_file='$args_file'
mode_file='$mode_file'
status_value_file='$status_value_file'
log_file='$log_file'
: >"\$args_file"
cow=
hostfs=
session=
for argument do
    printf '%s\n' "\$argument" >>"\$args_file"
    case "\$argument" in
        ubd0=*)
            cow=\${argument#ubd0=}
            cow=\${cow%%,*}
            ;;
        hostfs=*) hostfs=\${argument#hostfs=} ;;
        neoproot_session=*) session=\${argument#neoproot_session=} ;;
    esac
done
case \$(cat "\$mode_file") in
status)
    printf '%s\n' "\$(cat "\$status_value_file")" >"\$hostfs\$session/status"
    ;;
status-cow)
    printf '%s\n' "\$(cat "\$status_value_file")" >"\$hostfs\$session/status"
    : >"\$hostfs\$session/root.cow"
    ;;
cow-create)
    printf '%s\n' "\$(cat "\$status_value_file")" >"\$hostfs\$session/status"
    printf 'first-run\n' >>"\$cow"
    printf '%s\n' "\$cow" >"\$log_file"
    ;;
cow-reuse)
    printf '%s\n' "\$(cat "\$status_value_file")" >"\$hostfs\$session/status"
    cat "\$cow" >"\$log_file"
    printf 'second-run\n' >>"\$cow"
    ;;
*)
    printf '%s\n' "unknown mock mode: \$(cat "\$mode_file")" >&2
    exit 125
    ;;
esac
exit 0
EOF
cat >"$stub" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 755 "$fake_kernel" "$stub"

assert_clean() {
	if find "$runtime_parent" -mindepth 1 -maxdepth 1 -print -quit | grep . >/dev/null; then
		echo "FAIL: ext4 runtime files were not cleaned" >&2
		find "$runtime_parent" -mindepth 1 -maxdepth 2 -print >&2
		exit 1
	fi
}

# run_supervisor MODE EXPECTED_RC [ARGUMENTS...]
run_supervisor() {
	mode=$1
	expected=$2
	shift 2

	printf '%s\n' "$mode" >"$mode_file"
	rm -f "$args_file" "$log_file"
	set +e
	TMPDIR="$runtime_parent" "$um_supervisor" \
		--kernel="$fake_kernel" --stub="$stub" --timeout=5 "$@" \
		>"$temporary_directory/stdout" 2>"$temporary_directory/stderr"
	actual=$?
	set -e
	if [ "$actual" -ne "$expected" ]; then
		echo "FAIL: $mode returned $actual, expected $expected" >&2
		cat "$temporary_directory/stdout" >&2
		cat "$temporary_directory/stderr" >&2
		exit 1
	fi
}

# expect_failure NAME EXPECTED_FIRST_LINE [ARGUMENTS...]
expect_failure() {
	name=$1
	expected_line=$2
	shift 2

	set +e
	TMPDIR="$runtime_parent" "$um_supervisor" \
		--kernel="$fake_kernel" --stub="$stub" --timeout=5 "$@" \
		>"$temporary_directory/stdout" 2>"$temporary_directory/stderr"
	actual=$?
	set -e
	if [ "$actual" -eq 0 ]; then
		echo "FAIL: $name unexpectedly succeeded" >&2
		exit 1
	fi
	first_line=$(head -n 1 "$temporary_directory/stderr")
	case "$first_line" in
	*"$expected_line"*) ;;
	*)
		echo "FAIL: $name: first line was '$first_line'" >&2
		echo "      expected it to contain '$expected_line'" >&2
		exit 1
		;;
	esac
}

# --- argument validation -------------------------------------------------
#
# Every message is checked on its first line: that is the line a caller and a
# test can key on, and it is what the manual promises.

expect_failure "empty value" \
	"invalid or duplicate option" --rootfs="$image" --cow-file= -- /bin/true
expect_failure "duplicate option" \
	"invalid or duplicate option" --rootfs="$image" \
	--cow-file="$temporary_directory/a.cow" \
	--cow-file="$temporary_directory/b.cow" -- /bin/true
expect_failure "relative path" \
	"cow file must be an absolute path" --rootfs="$image" \
	--cow-file=cow.img -- /bin/true
expect_failure "kernel separator" \
	"cow file contains an unsupported character" --rootfs="$image" \
	--cow-file="$temporary_directory/a,b.cow" -- /bin/true
expect_failure "missing directory" \
	"cow file directory is not usable" --rootfs="$image" \
	--cow-file="$temporary_directory/missing/cow.img" -- /bin/true
expect_failure "readonly conflict" \
	"--cow-file and --readonly are mutually exclusive" --rootfs="$image" \
	--readonly --cow-file="$temporary_directory/a.cow" -- /bin/true
mkdir "$temporary_directory/rootdir"
expect_failure "hostfs root" \
	"--cow-file requires an ext4 rootfs image" \
	--rootfs="$temporary_directory/rootdir" \
	--cow-file="$temporary_directory/a.cow" -- /bin/true
expect_failure "the image itself" \
	"cow file must not be the rootfs image" --rootfs="$image" \
	--cow-file="$image" -- /bin/true

ln -s "$temporary_directory/a.cow" "$temporary_directory/link.cow"
expect_failure "symlink" \
	"cow file must not be a symlink" --rootfs="$image" \
	--cow-file="$temporary_directory/link.cow" -- /bin/true

printf 'not a cow file, just some text that is long enough to read\n' \
	>"$temporary_directory/garbage.cow"
expect_failure "not a COW file" \
	"cow file is not a UML COW file" --rootfs="$image" \
	--cow-file="$temporary_directory/garbage.cow" -- /bin/true

write_cow_header "$temporary_directory/stale.cow" $((image_mtime + 1)) "$image_size"
expect_failure "stale backing image" \
	"was created for a different rootfs image" --rootfs="$image" \
	--cow-file="$temporary_directory/stale.cow" -- /bin/true

# --- the default stays a temporary COW -----------------------------------

run_supervisor status-cow 0 --rootfs="$image" -- /bin/true
grep -F 'ubd0=' "$args_file" | grep -F ',/proc/self/fd/' >/dev/null
grep -F '/.neoproot-um-' "$args_file" | grep -F '/root.cow,' >/dev/null
assert_clean

# --- a named COW file is built and kept ----------------------------------

cow="$temporary_directory/keep.cow"
printf '%s\n' 0 >"$status_value_file"
run_supervisor cow-create 0 --rootfs="$image" --cow-file="$cow" -- /bin/true
[ -f "$cow" ] || { echo "FAIL: --cow-file did not create $cow" >&2; exit 1; }
grep -qxF "$cow" "$log_file" || {
	echo "FAIL: the kernel was not given the named COW file" >&2
	exit 1
}
# The image is named directly here, not through /proc/self/fd: the COW header
# records that name, and it has to be stable for the next run to reuse it.
grep -F "ubd0=$cow,$image" "$args_file" >/dev/null
if grep -F 'ubd0=' "$args_file" | grep -F '/proc/self/fd/' >/dev/null; then
	echo "FAIL: a named COW still uses the descriptor as backing" >&2
	exit 1
fi
assert_clean

# --- the same file is reused by the next run ------------------------------

write_cow_header "$cow" "$image_mtime" "$image_size"
printf 'first-run\n' >>"$cow"
size_before=$(wc -c <"$cow" | tr -d ' ')
run_supervisor cow-reuse 0 --rootfs="$image" --cow-file="$cow" -- /bin/true
grep -q 'first-run' "$log_file" || {
	echo "FAIL: the second run did not see the first run's COW" >&2
	exit 1
}
# The header is untouched and the mock's append is the only change: the file
# the caller named is neither rewritten nor truncated by the run.
[ "$(head -c 4 "$cow")" = "OOOM" ] || {
	echo "FAIL: the COW header did not survive the second run" >&2
	exit 1
}
size_after=$(wc -c <"$cow" | tr -d ' ')
if [ "$((size_after - size_before))" -ne 11 ]; then
	echo "FAIL: the COW file changed unexpectedly ($size_before -> $size_after)" >&2
	exit 1
fi
assert_clean

# A guest that fails does not take the caller's COW file with it.
printf '7\n' >"$status_value_file"
run_supervisor cow-reuse 7 --rootfs="$image" --cow-file="$cow" -- /bin/true
[ -f "$cow" ] || { echo "FAIL: COW file removed after a failed run" >&2; exit 1; }
assert_clean

# --- an empty file is a placeholder, not an error ------------------------

placeholder="$temporary_directory/placeholder.cow"
: >"$placeholder"
printf '0\n' >"$status_value_file"
run_supervisor cow-create 0 --rootfs="$image" --cow-file="$placeholder" -- /bin/true
[ -s "$placeholder" ] || {
	echo "FAIL: an empty placeholder was not replaced by a COW file" >&2
	exit 1
}
assert_clean

# --- the neoproot CLI forwards the option --------------------------------

cow="$temporary_directory/cli.cow"
write_cow_header "$cow" "$image_mtime" "$image_size"
printf '0\n' >"$status_value_file"
for form in equals separate; do
	: >"$args_file"
	if [ "$form" = equals ]; then
		NEOPROOT_UM_KERNEL="$fake_kernel" NEOPROOT_UM_STUB="$stub" \
			TMPDIR="$runtime_parent" "$neoproot" --backend=um \
			--rootfs="$image" --cow-file="$cow" -- /bin/true
	else
		NEOPROOT_UM_KERNEL="$fake_kernel" NEOPROOT_UM_STUB="$stub" \
			TMPDIR="$runtime_parent" "$neoproot" --backend=um \
			--rootfs="$image" --cow-file "$cow" -- /bin/true
	fi
	grep -F "ubd0=$cow,$image" "$args_file" >/dev/null || {
		echo "FAIL: neoproot ($form) did not forward --cow-file" >&2
		exit 1
	}
	assert_clean
done

echo "UM supervisor --cow-file CLI tests passed"
