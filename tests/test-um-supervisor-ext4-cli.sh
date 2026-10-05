#!/bin/sh
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

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-ext4.XXXXXX")
runtime_parent="$temporary_directory/runtime"
mkdir "$runtime_parent"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

image="$temporary_directory/rootfs.ext4"
fake_kernel="$temporary_directory/kernel"
stub="$temporary_directory/stub"
args_file="$temporary_directory/args"
mode_file="$temporary_directory/mode"
status_value_file="$temporary_directory/status-value"
kernel_pid_file="$temporary_directory/kernel-pid"
sleeper_pid_file="$temporary_directory/sleeper-pid"

dd if=/dev/zero of="$image" bs=1 count=2048 2>/dev/null
printf '\123\357' | dd of="$image" bs=1 seek=1080 conv=notrunc 2>/dev/null

cat >"$fake_kernel" <<EOF
#!/bin/sh
set -eu
args_file='$args_file'
mode_file='$mode_file'
status_value_file='$status_value_file'
kernel_pid_file='$kernel_pid_file'
sleeper_pid_file='$sleeper_pid_file'
printf '%s\\n' "\$\$" >"\$kernel_pid_file"
:" >"\$args_file"
hostfs=
session=
for argument do
    printf '%s\\n' "\$argument" >>"\$args_file"
    case "\$argument" in
        hostfs=*) hostfs="\${argument#hostfs=}" ;;
        neoproot_session=*) session="\${argument#neoproot_session=}" ;;
    esac
done
status_path="\$hostfs\$session/status"
mode=\$(cat "\$mode_file")
case "\$mode" in
    status|status-cow)
        printf '%s\\n' "\$(cat "\$status_value_file")" >"\$status_path"
        if [ "\$mode" = status-cow ]; then
            : >"\$hostfs\$session/root.cow"
        fi
        exit 0
        ;;
    missing-status)
        exit 9
        ;;
    invalid-status)
        printf '%s\\n' 'not-an-exit-code' >"\$status_path"
        exit 11
        ;;
    timeout|signal)
        sleep 30 &
        sleeper=\$!
        printf '%s\\n' "\$sleeper" >"\$sleeper_pid_file"
        wait "\$sleeper"
        ;;
    *)
        printf '%s\\n' "unknown mock mode: \$mode" >&2
        exit 125
        ;;
esac
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

assert_status() {
	name=$1
	expected=$2
	shift 2
	printf '%s\n' status >"$mode_file"
	printf '%s\n' "$expected" >"$status_value_file"
	rm -f "$args_file" "$kernel_pid_file" "$sleeper_pid_file"
	set +e
	TMPDIR="$runtime_parent" "$um_supervisor" \
		--kernel="$fake_kernel" --stub="$stub" --rootfs="$image" \
		--timeout=5 "$@" -- /bin/true >"$temporary_directory/stdout" \
		2>"$temporary_directory/stderr"
	actual=$?
	set -e
	if [ "$actual" -ne "$expected" ]; then
		echo "FAIL: $name returned $actual, expected $expected" >&2
		cat "$temporary_directory/stdout" >&2
		cat "$temporary_directory/stderr" >&2
		exit 1
	fi
	assert_clean
}

assert_fallback_status() {
	name=$1
	expected=$2
	mode=$3
	printf '%s\n' "$mode" >"$mode_file"
	rm -f "$args_file" "$kernel_pid_file" "$sleeper_pid_file"
	set +e
	TMPDIR="$runtime_parent" "$um_supervisor" \
		--kernel="$fake_kernel" --stub="$stub" --rootfs="$image" \
		--timeout=5 -- /bin/true >"$temporary_directory/stdout" \
		2>"$temporary_directory/stderr"
	actual=$?
	set -e
	if [ "$actual" -ne "$expected" ]; then
		echo "FAIL: $name returned $actual, expected $expected" >&2
		cat "$temporary_directory/stdout" >&2
		cat "$temporary_directory/stderr" >&2
		exit 1
	fi
	assert_clean
}

assert_process_stopped() {
	name=$1
	pid_file=$2
	if [ ! -s "$pid_file" ]; then
		return
	fi
	pid=$(cat "$pid_file")
	for attempt in 1 2 3 4 5 6 7 8 9 10; do
		if [ ! -r "/proc/$pid/stat" ]; then
			return
		fi
		state=$(awk '{ print $3 }' "/proc/$pid/stat")
		[ "$state" = Z ] && return
		sleep 0.1
	done
	echo "FAIL: $name left process $pid running" >&2
	exit 1
}

assert_status "guest status 0" 0
assert_status "guest status 7" 7
assert_status "guest status 125" 125
printf '%s\n' status-cow >"$mode_file"
printf '%s\n' 7 >"$status_value_file"
set +e
TMPDIR="$runtime_parent" "$um_supervisor" \
	--kernel="$fake_kernel" --stub="$stub" --rootfs="$image" \
	--timeout=5 -- /bin/true >/dev/null 2>"$temporary_directory/stderr"
actual=$?
set -e
[ "$actual" -eq 7 ]
assert_clean
assert_fallback_status "missing guest status" 9 missing-status
assert_fallback_status "invalid guest status" 11 invalid-status

printf '%s\n' timeout >"$mode_file"
rm -f "$args_file" "$kernel_pid_file" "$sleeper_pid_file"
set +e
start_time=$(date +%s)
TMPDIR="$runtime_parent" "$um_supervisor" \
	--kernel="$fake_kernel" --stub="$stub" --rootfs="$image" \
	--timeout=0.2 -- /bin/true >"$temporary_directory/stdout" \
	2>"$temporary_directory/stderr"
actual=$?
set -e
elapsed=$(( $(date +%s) - start_time ))
if [ "$actual" -ne 124 ] || [ "$elapsed" -ge 10 ]; then
	echo "FAIL: timeout returned $actual after ${elapsed}s" >&2
	cat "$temporary_directory/stderr" >&2
	exit 1
fi
assert_process_stopped "timeout" "$sleeper_pid_file"
assert_clean

printf '%s\n' signal >"$mode_file"
rm -f "$args_file" "$kernel_pid_file" "$sleeper_pid_file"
set +e
TMPDIR="$runtime_parent" "$um_supervisor" \
	--kernel="$fake_kernel" --stub="$stub" --rootfs="$image" \
	--timeout=30 -- /bin/true >"$temporary_directory/stdout" \
	2>"$temporary_directory/stderr" &
supervisor_pid=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
	[ -s "$sleeper_pid_file" ] && break
	sleep 0.1
done
if [ ! -s "$sleeper_pid_file" ]; then
	echo "FAIL: signal mock did not start" >&2
	kill -KILL "$supervisor_pid" 2>/dev/null || true
	wait "$supervisor_pid" 2>/dev/null || true
	exit 1
fi
kill -TERM "$supervisor_pid"
wait "$supervisor_pid"
actual=$?
set -e
if [ "$actual" -ne 143 ]; then
	echo "FAIL: forwarded SIGTERM returned $actual, expected 143" >&2
	cat "$temporary_directory/stderr" >&2
	exit 1
fi
assert_process_stopped "forwarded SIGTERM" "$sleeper_pid_file"
assert_clean

grep -F 'init=/um-init' "$args_file" >/dev/null
grep -F 'rw' "$args_file" >/dev/null
grep -F 'root=/dev/ubda' "$args_file" >/dev/null
grep -F 'rootfstype=ext4' "$args_file" >/dev/null
grep -F "neoproot_cwd=/" "$args_file" >/dev/null
grep -F 'hostfs=' "$args_file" >/dev/null
grep -F 'neoproot_protocol=session-v1' "$args_file" >/dev/null
grep -F 'neoproot_session=/' "$args_file" >/dev/null
grep -F 'ubd0=' "$args_file" | grep -F ',/proc/self/fd/' >/dev/null
if grep -F "rootflags=$image" "$args_file" >/dev/null; then
	echo "FAIL: ext4 image was passed as rootflags" >&2
	exit 1
fi

printf '%s\n' status >"$mode_file"
printf '%s\n' 0 >"$status_value_file"
: >"$args_file"
TMPDIR="$runtime_parent" "$um_supervisor" \
	--kernel="$fake_kernel" --stub="$stub" --rootfs="$image" \
	--readonly -- /bin/true
grep -F 'ubd0r=/proc/self/fd/' "$args_file" >/dev/null
grep -F 'rootflags=noload' "$args_file" >/dev/null
if grep -F 'ubd0=' "$args_file" >/dev/null; then
	echo "FAIL: readonly mode created a COW UBD" >&2
	exit 1
fi
assert_clean

printf '%s\n' status >"$mode_file"
printf '%s\n' 0 >"$status_value_file"
: >"$args_file"
NEOPROOT_UM_KERNEL="$fake_kernel" NEOPROOT_UM_STUB="$stub" \
	TMPDIR="$runtime_parent" "$neoproot" --backend=um --rootfs="$image" -- /bin/true
grep -F 'neoproot_protocol=session-v1' "$args_file" >/dev/null
assert_clean
echo "UM supervisor ext4 mock tests passed"
