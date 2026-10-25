#!/bin/sh
#
# The guest request loop, exercised without a kernel.
#
# The loop is plain POSIX sh and the channel is a directory, so the whole
# queue/results contract can be checked by running the real generated script
# against a hand-made channel: no UML kernel, no rootfs, no privileges.  What
# this covers is exactly what the daemon and the guest agree on:
#
#   ready      published only after queue/ and results/ exist
#   claim      a request is claimed by moving it out of queue/
#   stdout     goes to results/<id>/stdout, stderr to results/<id>/stderr
#   status     published before done, and done only after it
#   cwd        honoured, and an impossible one is the documented 126
#   kill       ends the command and its process group, leaving none behind
#   stop       powers the guest down (here: exits) instead of looping
#
# Exit: 0 passed, 1 failed, 125 nothing could be attempted.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor=${UM_SUPERVISOR:-"$script_directory/../src/neoproot-um"}

if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
# The loop runs as the guest's init, so the shell that runs it here must be a
# POSIX sh and not something that has been taught new syntax by its distro.
command -v sh >/dev/null 2>&1 || {
	echo "skip: no /bin/sh to run the loop with" >&2
	exit 125
}

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-loop.XXXXXX")
loop_pid=
trap 'if [ -n "$loop_pid" ]; then kill -9 "$loop_pid" 2>/dev/null || true; fi
      rm -rf "$temporary_directory"' EXIT HUP INT TERM

channel="$temporary_directory/channel"
mkdir -p "$channel/queue" "$channel/results"
"$um_supervisor" session --print-loop >"$temporary_directory/init.sh"

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

wait_for() {
	path=$1
	attempt=0
	while [ ! -e "$path" ]; do
		attempt=$((attempt + 1))
		if [ "$attempt" -gt 400 ]; then
			return 1
		fi
		sleep 0.05
	done
	return 0
}

# send ID CWD -- command...: write one request the way the daemon does.
send() {
	request_id=$1
	shift
	request_cwd=$1
	shift
	[ "$1" = "--" ] && shift
	{
		printf '%s\n' 'neoproot-exec-v1'
		printf '%s\n' "$request_cwd"
		for request_arg in "$@"; do
			printf '%s\n' "${#request_arg}"
			printf '%s\n' "$request_arg"
		done
	} >"$channel/queue/$request_id"
	wait_for "$channel/results/$request_id/done" || {
		echo "FAIL: request $request_id never finished" >&2
		exit 1
	}
}

status_of() {
	cat "$channel/results/$1/status"
}

# The loop reads its channel from its own path, so it must be started as the
# file inside the directory that holds the channel.
sh "$temporary_directory/init.sh" &
loop_pid=$!
wait_for "$channel/ready" || fail "the loop never published ready"
grep -q 'neoproot-session-loop-v1' "$channel/ready" ||
	fail "the ready marker is not the documented one"
[ -d "$channel/queue" ] && [ -d "$channel/results" ] ||
	fail "ready was published before the queue/ and results/ existed"

# --- a command's streams and status --------------------------------------
send 1 "" -- /bin/sh -c 'echo out-line; echo err-line >&2; exit 9'
[ "$(status_of 1)" = 9 ] || fail "exit status 9 came back as $(status_of 1)"
[ "$(cat "$channel/results/1/stdout")" = "out-line" ] ||
	fail "stdout was not the command's"
[ "$(cat "$channel/results/1/stderr")" = "err-line" ] ||
	fail "stderr was not the command's"
[ ! -e "$channel/queue/1" ] || fail "the claimed request is still in queue/"

# --- a working directory, and one that cannot exist ----------------------
send 2 "/tmp" -- /bin/sh -c 'pwd'
[ "$(status_of 2)" = 0 ] || fail "the /tmp run failed with $(status_of 2)"
[ "$(cat "$channel/results/2/stdout")" = "/tmp" ] ||
	fail "the working directory was not honoured"

send 3 "/nonexistent-directory-for-this-test" -- /bin/true
[ "$(status_of 3)" = 126 ] ||
	fail "an impossible cwd reported $(status_of 3), expected 126"

# --- a command that is not there -----------------------------------------
send 4 "" -- /nonexistent-command-for-this-test
[ "$(status_of 4)" = 127 ] ||
	fail "a missing command reported $(status_of 4), expected 127"

# --- kill: the command, its group, and no leftovers ----------------------
# The request is sent without waiting, because the kill has to arrive while
# the command is still running.
{
	printf '%s\n' 'neoproot-exec-v1'
	printf '\n'
	printf '9\n/bin/sh\n3\n-c\n36\nsleep 30 & sleep 30; echo never\n'
} >"$channel/queue/5"
wait_for "$channel/results/5/pid" || fail "the running request has no pid"
command_pid=$(cat "$channel/results/5/pid")
kill -0 "$command_pid" 2>/dev/null || fail "the recorded pid is not running"
: >"$channel/results/5/kill"
wait_for "$channel/results/5/done" || fail "kill did not end the command"
kill_status=$(status_of 5)
# 128+SIGTERM is what a shell reports for a command it terminated.
case "$kill_status" in
143 | 137) ;;
*) fail "a killed command reported $kill_status" ;;
esac
grep -q never "$channel/results/5/stdout" 2>/dev/null &&
	fail "the killed command ran to completion anyway"

attempt=0
while pgrep -f 'sleep 30' >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	[ "$attempt" -gt 100 ] && fail "a killed command's child survived"
	sleep 0.05
done

# --- stop ends the loop --------------------------------------------------
: >"$channel/stop"
attempt=0
while kill -0 "$loop_pid" 2>/dev/null; do
	attempt=$((attempt + 1))
	[ "$attempt" -gt 200 ] && fail "the loop ignored the stop file"
	sleep 0.05
done
loop_pid=

echo "UM session guest loop tests passed"
