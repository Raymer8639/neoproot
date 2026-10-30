#!/bin/sh
#
# The session daemon end to end, against a mock kernel.
#
# A real UML boot is the one thing this test cannot do (it needs the kernel,
# a rootfs and an untraced process), but everything above the kernel is the
# daemon's own code: the state directory and its lock, the control socket,
# the queue/results exchange, the status/timeout/signal mapping and the
# cleanup.  The mock kernel stands in for the boot: it reads the same kernel
# command line the real one would get, runs the generated init.sh exactly as
# /um-init would, and exits when the loop powers the guest down.
#
# Covered here:
#   start    the daemon comes up, the guest reaches the loop, the socket is
#            in a 0700 directory and holds the right pid
#   busy     a second start is refused while the session is live
#   run      two commands in a row, stdout and stderr separated, exit codes
#            preserved (including a non-zero one)
#   timeout  124, and the session is still usable afterwards
#   signal   128+n when the caller is interrupted
#   stop     the daemon and the guest are gone, and nothing is left behind
#
# Exit: 0 passed, 1 failed, 125 nothing could be attempted.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor=${UM_SUPERVISOR:-$script_directory/../src/neoproot-um}
if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: the UML supervisor must run untraced" >&2
	exit 125
fi

# The state directory ends up as <TMPDIR>/neoproot-um-sessions/<name>/ctl.sock,
# and a unix socket path is capped at 108 bytes.  Termux already spends 41 on
# $PREFIX/tmp, so the work directory here keeps its own name short instead of
# following the long "neoproot-um-session.XXXXXX" spelling.
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/nus.XXXXXX")
runtime="$temporary_directory/state"
rootfs="$temporary_directory/rootfs"
mkdir -p "$runtime" "$rootfs/bin"
session_name=mock
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

state_path="$runtime/neoproot-um-sessions/$session_name"

fail() {
	echo "FAIL: $1" >&2
	if [ -f "$state_path/log" ]; then
		echo "--- daemon log ---" >&2
		cat "$state_path/log" >&2
	fi
	exit 1
}

# The mock kernel: it is what /um-init is for an ext4 root and what the
# kernel itself is for a hostfs root -- it starts init.sh and waits.
cat >"$temporary_directory/kernel" <<'EOF'
#!/bin/sh
root=
init=
for argument do
	case "$argument" in
	rootflags=*) root=${argument#rootflags=} ;;
	init=*) init=${argument#init=} ;;
	esac
done
[ -n "$root" ] && [ -n "$init" ] || {
	echo "mock kernel: no rootflags/init on the command line" >&2
	exit 1
}
case "$init" in
/*/init.sh) session_directory=${init%/init.sh} ;;
*) echo "mock kernel: unexpected init $init" >&2; exit 1 ;;
esac
# The guest sees its rootfs as /, so the session directory is found under it.
cd "$root" || exit 1
exec /bin/sh ".$session_directory/init.sh"
EOF
chmod 755 "$temporary_directory/kernel"
printf '#!/bin/sh\nexit 0\n' >"$temporary_directory/stub"
chmod 755 "$temporary_directory/stub"

run_session() {
	TMPDIR="$runtime" NEOPROOT_UM_KERNEL="$temporary_directory/kernel" \
		NEOPROOT_UM_STUB="$temporary_directory/stub" \
		"$um_supervisor" session --session-name="$session_name" "$@"
}

# --- start ---------------------------------------------------------------
run_session start --rootfs="$rootfs" --hostfs --timeout=60 -- /bin/true \
	>"$temporary_directory/start.out" 2>"$temporary_directory/start.err" ||
	fail "session start failed: $(cat "$temporary_directory/start.err")"
grep -q 'started' "$temporary_directory/start.out" ||
	fail "session start did not say the session started"
[ -S "$state_path/ctl.sock" ] || {
	ls -la "$state_path" >&2 2>/dev/null || echo "state dir missing: $state_path" >&2
	fail "no control socket was created"
}
# POSIX test has no -O, and stat's mode flag is not portable either: read the
# mode out of ls, whose first field is the same everywhere.  GNU ls appends a
# trailing "." or "+" when an SELinux/ACL marker is present (every Termux path
# has one), and that marker is not part of the mode.
state_mode=$(ls -ld "$state_path" | awk '{ print $1 }' | sed 's/[.+]$//')
case "$state_mode" in
drwx------) ;;
*) fail "the state directory is $state_mode, not drwx------" ;;
esac
daemon_pid=$(cat "$state_path/pid")
kill -0 "$daemon_pid" 2>/dev/null || fail "the recorded daemon pid is not running"
run_session status >"$temporary_directory/status.out" 2>&1 ||
	fail "status failed on a live session"
grep -q READY "$temporary_directory/status.out" ||
	fail "status did not report a ready session: $(cat "$temporary_directory/status.out")"

# --- a second start is refused ------------------------------------------
if TMPDIR="$runtime" NEOPROOT_UM_KERNEL="$temporary_directory/kernel" \
	NEOPROOT_UM_STUB="$temporary_directory/stub" \
	"$um_supervisor" session --session-name="$session_name" \
	start --rootfs="$rootfs" --hostfs --timeout=60 -- /bin/true \
	>"$temporary_directory/again.out" 2>"$temporary_directory/again.err"; then
	fail "a second start on a live session succeeded"
fi
grep -q 'in use' "$temporary_directory/again.err" ||
	fail "the second start did not say the session is in use"

# --- two commands in a row ----------------------------------------------
set +e
run_session run -- /bin/sh -c 'echo first-out; echo first-err >&2; exit 7' \
	>"$temporary_directory/run1.out" 2>"$temporary_directory/run1.err"
run_rc=$?
set -e
[ "$run_rc" -eq 7 ] || fail "the first command returned $run_rc, expected 7"
[ "$(cat "$temporary_directory/run1.out")" = "first-out" ] ||
	fail "the first command's stdout was [$(cat "$temporary_directory/run1.out")]"
[ "$(cat "$temporary_directory/run1.err")" = "first-err" ] ||
	fail "the first command's stderr was [$(cat "$temporary_directory/run1.err")]"

run_session run --cwd=/tmp -- /bin/sh -c 'pwd' \
	>"$temporary_directory/run2.out" 2>"$temporary_directory/run2.err"
[ "$(cat "$temporary_directory/run2.out")" = "/tmp" ] ||
	fail "the second command's cwd was [$(cat "$temporary_directory/run2.out")]"

run_session run -- /bin/sh -c 'exit 0' >/dev/null 2>&1 ||
	fail "a successful command did not return 0"

# --- timeout -------------------------------------------------------------
start_seconds=$(date +%s)
set +e
run_session run --timeout=1 -- /bin/sh -c 'sleep 20; echo late' \
	>"$temporary_directory/timeout.out" 2>"$temporary_directory/timeout.err"
timeout_rc=$?
set -e
[ "$timeout_rc" -eq 124 ] || fail "a timed-out command returned $timeout_rc, expected 124"
grep -q late "$temporary_directory/timeout.out" 2>/dev/null &&
	fail "the timed-out command ran to completion anyway"
elapsed=$(( $(date +%s) - start_seconds ))
[ "$elapsed" -lt 15 ] || fail "the timeout took ${elapsed}s to take effect"

# The session is not collateral damage: the next command still runs.
run_session run -- /bin/sh -c 'echo alive' >"$temporary_directory/alive.out" \
	2>"$temporary_directory/alive.err" ||
	fail "the session was unusable after a timeout"
[ "$(cat "$temporary_directory/alive.out")" = "alive" ] ||
	fail "the command after a timeout printed [$(cat "$temporary_directory/alive.out")]"

# --- signals -------------------------------------------------------------
# The client forwards INT/TERM to the guest and reports 128+n.
run_session run --timeout=30 -- /bin/sh -c 'sleep 20' \
	>"$temporary_directory/signal.out" 2>"$temporary_directory/signal.err" &
client_pid=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
	attempt=$((attempt + 1))
	if [ "$attempt" -eq 15 ]; then
		kill -TERM "$client_pid" 2>/dev/null || true
	fi
	kill -0 "$client_pid" 2>/dev/null || break
	sleep 0.1
done
set +e
wait "$client_pid"
signal_rc=$?
set -e
[ "$signal_rc" -eq 143 ] ||
	fail "an interrupted command returned $signal_rc, expected 143 (128+TERM)"

# --- stop ----------------------------------------------------------------
run_session stop >/dev/null 2>&1 || fail "session stop failed"
attempt=0
while kill -0 "$daemon_pid" 2>/dev/null; do
	attempt=$((attempt + 1))
	[ "$attempt" -gt 150 ] && fail "the daemon is still running after stop"
	sleep 0.1
done
[ ! -e "$state_path" ] || fail "the state directory survived the stop"
if ls -d "$rootfs"/.neoproot-um-* 2>/dev/null; then
	fail "the session directory survived the stop"
fi
set +e
run_session status >"$temporary_directory/after.out" 2>&1
after_rc=$?
set -e
[ "$after_rc" -ne 0 ] || fail "status on a stopped session reported success"
grep -q 'not running' "$temporary_directory/after.out" ||
	fail "status said [$(cat "$temporary_directory/after.out")] for a stopped session"
if TMPDIR="$runtime" NEOPROOT_UM_KERNEL="$temporary_directory/kernel" \
	NEOPROOT_UM_STUB="$temporary_directory/stub" \
	"$um_supervisor" session --session-name="$session_name" run -- /bin/true \
	>"$temporary_directory/gone.out" 2>"$temporary_directory/gone.err"; then
	fail "run on a stopped session succeeded"
fi

echo "UM session daemon tests passed"
