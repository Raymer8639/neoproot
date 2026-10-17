#!/bin/sh
#
# CLI contract for ext4 binds.
#
# An ext4 guest root is an image, so a bind source cannot be reached through the
# guest's own path namespace.  The supervisor describes each bind in the session
# directory and the guest init mounts it; this test fixes that description (the
# "binds" file), the wrapper's protocol gate, and what happens when the image's
# /um-init predates the feature.
#
# The mock kernel stands in for the guest init: it copies the files the
# supervisor wrote, optionally declares support, and reports a status.  The
# mounts themselves are exercised against real UML by
# tests/stability-um-backend.sh.
#
# Exit: 0 passed, 1 failed, 125 nothing could be attempted.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor=${UM_SUPERVISOR:-"$script_directory/../src/neoproot-um"}
if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: UML supervisor test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-binds.XXXXXX")
runtime_parent="$temporary_directory/runtime"
log_dir="$temporary_directory/log"
mkdir "$runtime_parent" "$log_dir"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

image="$temporary_directory/rootfs.ext4"
fake_kernel="$temporary_directory/kernel"
stub="$temporary_directory/stub"
args_file="$temporary_directory/args"
mode_file="$temporary_directory/mode"
status_value_file="$temporary_directory/status-value"

dd if=/dev/zero of="$image" bs=1 count=2048 2>/dev/null
printf '\123\357' | dd of="$image" bs=1 seek=1080 conv=notrunc 2>/dev/null

bind_directory="$temporary_directory/hostdir"
mkdir "$bind_directory"
printf 'hello\n' >"$bind_directory/hello.txt"
bind_file="$temporary_directory/hostfile"
printf 'file\n' >"$bind_file"

cat >"$fake_kernel" <<'EOF'
#!/bin/sh
set -eu
args_file=@ARGS@
mode_file=@MODE@
status_value_file=@STATUS@
log_dir=@LOG@
: >"$args_file"
hostfs=
session=
for argument do
    printf '%s\n' "$argument" >>"$args_file"
    case "$argument" in
        hostfs=*) hostfs=${argument#hostfs=} ;;
        neoproot_session=*) session=${argument#neoproot_session=} ;;
    esac
done
session_dir="$hostfs$session"
[ -f "$session_dir/binds" ] && cp "$session_dir/binds" "$log_dir/binds"
[ -f "$session_dir/init.sh" ] && cp "$session_dir/init.sh" "$log_dir/init.sh"
case $(cat "$mode_file") in
legacy) ;;
aware)
    printf '%s\n' 'neoproot-init-protocol=2' 'feature=binds' \
        >"$session_dir/init-features"
    ;;
guest-error)
    printf '%s\n' 'neoproot-init-protocol=2' 'feature=binds' \
        >"$session_dir/init-features"
    printf '%s\n' 'UM_BIND_ERROR=source-missing' \
        >"$session_dir/protocol-error"
    ;;
*)
    printf '%s\n' "unknown mock mode: $(cat "$mode_file")" >&2
    exit 125
    ;;
esac
printf '%s\n' "$(cat "$status_value_file")" >"$session_dir/status"
exit 0
EOF
sed -e "s|@ARGS@|$args_file|" -e "s|@MODE@|$mode_file|" \
	-e "s|@STATUS@|$status_value_file|" -e "s|@LOG@|$log_dir|" \
	"$fake_kernel" >"$fake_kernel.tmp"
mv "$fake_kernel.tmp" "$fake_kernel"
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
	if find "$temporary_directory" -maxdepth 1 -name '.neoproot-um-*' \
		-print -quit | grep . >/dev/null; then
		echo "FAIL: a session directory was left behind" >&2
		find "$temporary_directory" -maxdepth 1 -name '.neoproot-um-*' -print >&2
		exit 1
	fi
}

# run_case MODE EXPECTED_RC STATUS [ARGUMENTS...]
run_case() {
	mode=$1
	expected=$2
	status=$3
	shift 3

	printf '%s\n' "$mode" >"$mode_file"
	printf '%s\n' "$status" >"$status_value_file"
	rm -f "$args_file" "$log_dir/binds" "$log_dir/init.sh"
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

# record FIELD VALUE: print the field of the record whose target is VALUE.
record() {
	field=$1
	target=$2
	awk -F'\t' -v target="$target" -v field="$field" '
		$2 == target { print $field }
	' "$log_dir/binds"
}

# --- the bind description handed to the guest ----------------------------

run_case aware 0 0 --rootfs="$image" \
	--bind="$bind_directory:/mnt/data" \
	--bind="$bind_file:/mnt/file:ro" -- /bin/true

[ -f "$log_dir/binds" ] || { echo "FAIL: no binds file was written" >&2; exit 1; }
head -n 1 "$log_dir/binds" | grep -F '# neoproot binds v1' >/dev/null || {
	echo "FAIL: the binds file has no version line" >&2
	cat "$log_dir/binds" >&2
	exit 1
}
if awk -F'\t' 'NF != 0 && $1 !~ /^#/ && NF != 5 { exit 1 }' "$log_dir/binds"; then
	:
else
	echo "FAIL: a binds record does not have five fields" >&2
	cat "$log_dir/binds" >&2
	exit 1
fi
[ "$(record 3 /mnt/data)" = "dir" ] || { echo "FAIL: directory bind type" >&2; exit 1; }
[ "$(record 4 /mnt/data)" = "rw" ] || { echo "FAIL: directory bind mode" >&2; exit 1; }
[ "$(record 5 /mnt/data)" = "-" ] || { echo "FAIL: directory bind name" >&2; exit 1; }
[ "$(record 3 /mnt/file)" = "file" ] || { echo "FAIL: file bind type" >&2; exit 1; }
[ "$(record 4 /mnt/file)" = "ro" ] || { echo "FAIL: file bind mode" >&2; exit 1; }
[ "$(record 5 /mnt/file)" = "$(basename "$bind_file")" ] || {
	echo "FAIL: file bind name" >&2
	exit 1
}
directory_source=$(record 1 /mnt/data)
file_source=$(record 1 /mnt/file)
case "$directory_source" in
../*/$(basename "$bind_directory")) ;;
*)
	echo "FAIL: directory source '$directory_source' is not relative to hostfs" >&2
	exit 1
	;;
esac
case "$file_source" in
../*/$(basename "$temporary_directory")) ;;
*)
	# A file bind is mounted through its parent directory.
	echo "FAIL: file source '$file_source' is not the parent directory" >&2
	exit 1
	;;
esac
assert_clean

# Shortest target first, so a bind inside another bind lands after its parent.
run_case aware 0 0 --rootfs="$image" \
	--bind="$bind_directory:/mnt/data/inner" \
	--bind="$bind_file:/mnt/data" -- /bin/true
first_target=$(awk -F'\t' '$1 !~ /^#/ { print $2; exit }' "$log_dir/binds")
[ "$first_target" = "/mnt/data" ] || {
	echo "FAIL: binds are not ordered by target depth" >&2
	cat "$log_dir/binds" >&2
	exit 1
}
assert_clean

# --- the wrapper gate ----------------------------------------------------

run_case aware 0 0 --rootfs="$image" \
	--bind="$bind_directory:/mnt/data" -- /bin/true
grep -q 'feature=binds' "$log_dir/init.sh" || {
	echo "FAIL: init.sh does not check for the binds declaration" >&2
	cat "$log_dir/init.sh" >&2
	exit 1
}
if grep -F 'mount --bind' "$log_dir/init.sh" >/dev/null; then
	echo "FAIL: an ext4 wrapper contains hostfs-mode bind commands" >&2
	exit 1
fi
assert_clean

# Without binds the wrapper carries no gate: an old image keeps working.
run_case legacy 0 0 --rootfs="$image" -- /bin/true
if grep -q 'feature=binds' "$log_dir/init.sh" 2>/dev/null; then
	echo "FAIL: init.sh gates a run that asked for no binds" >&2
	exit 1
fi
[ ! -f "$log_dir/binds" ]
assert_clean

# --- an init that predates the feature -----------------------------------

# The mock reports success without declaring anything: the run must not be
# reported as a success, because the command ran without its binds.
run_case legacy 1 0 --rootfs="$image" \
	--bind="$bind_directory:/mnt/data" -- /bin/true
grep -F 'does not support binds' "$temporary_directory/stderr" >/dev/null || {
	echo "FAIL: no diagnosis for a legacy init" >&2
	cat "$temporary_directory/stderr" >&2
	exit 1
}
assert_clean

# --- a guest-side bind failure is reported -------------------------------

run_case guest-error 1 125 --rootfs="$image" \
	--bind="$bind_directory:/mnt/data" -- /bin/true
grep -F 'UM_BIND_ERROR=source-missing' "$temporary_directory/stderr" >/dev/null || {
	echo "FAIL: the guest's protocol error was not reported" >&2
	cat "$temporary_directory/stderr" >&2
	exit 1
}
assert_clean

# --- readonly ext4 still accepts binds -----------------------------------

run_case aware 0 0 --rootfs="$image" --readonly \
	--bind="$bind_directory:/mnt/data:ro" -- /bin/true
grep -F 'ubd0r=' "$args_file" >/dev/null
grep -F 'rootflags=noload' "$args_file" >/dev/null
[ "$(record 4 /mnt/data)" = "ro" ]
assert_clean

# --- the hostfs-only restrictions do not come back -----------------------

# A source outside any rootfs is exactly the point of an ext4 bind; only the
# guest target keeps the old validation.
run_case aware 0 0 --rootfs="$image" \
	--bind="$temporary_directory:/mnt/host" -- /bin/true
[ "$(record 2 /mnt/host)" = "/mnt/host" ]
assert_clean

expect_failure "relative guest target" "bind target must be an absolute path" \
	--rootfs="$image" --bind="$bind_directory:relative" -- /bin/true
expect_failure "controlled target" "invalid or duplicate option" \
	--rootfs="$image" --bind="$bind_directory:/proc/x" -- /bin/true
expect_failure "duplicate target" "invalid or duplicate option" \
	--rootfs="$image" --bind="$bind_directory:/mnt/x" \
	--bind="$bind_file:/mnt/x" -- /bin/true
expect_failure "unknown option" "invalid or duplicate option" \
	--rootfs="$image" --bind="$bind_directory:/mnt/x:rwx" -- /bin/true
expect_failure "missing source" "cannot resolve bind source" \
	--rootfs="$image" --bind="$temporary_directory/missing:/mnt/x" -- /bin/true

echo "UM supervisor ext4 binds CLI tests passed"
