# neoproot-um session loop.
#
# This file is the guest's init.sh tail in session mode: the supervisor
# appends it to the generated wrapper, so it runs as PID 1 (hostfs root) or
# from /um-init (ext4 root) and stays in this loop until the session is
# stopped.  It is kept as a real shell file -- not a C string -- so it can be
# run directly by tests/test-um-session-loop.sh and checked with sh -n.
#
# The channel lives next to this script: <session>/channel/ for a hostfs root
# and /run/neoproot/channel/ for an ext4 one, which is the same directory the
# host writes commands into.  Its layout:
#
#   queue/<id>            one request; moved out to claim it
#   results/<id>/         created for a claimed request
#     request             the claimed request
#     stdout, stderr      the command's streams
#     pid                 the command's pid, also its process group
#     kill                written by the host to stop the command
#     status              the exit status, published before done
#     done                published last; its presence means status is final
#   state/<id>            the loop's own "this id finished" marker, which the
#                         host must not touch (it deletes results/<id> as soon
#                         as it has the status, and a marker in there would be
#                         gone before this side could look)
#   ready                 written once the loop is polling
#   stop                  written by the host to shut the guest down

#   state/<id>            the loop's own "this id finished" marker, which the
#                         host must not touch (it deletes results/<id> as soon
#                         as it has the status, and a marker in there would be
#                         gone before this side could look)
#   ready                 written once the loop is polling
#   stop                  written by the host to shut the guest down
#
# Why a FIFO and not a poll: a 20 ms poll looks free but is not.  Every
# wakeup of a UML guest costs a host context switch, and on a phone one was
# measured at roughly 15 ms.  The host knows when it queued something, so it
# says so once: opening the FIFO for writing leaves a byte in it until the
# loop reads it, and the loop blocks on that read instead of spinning.  A
# guest whose channel cannot hold a FIFO falls back to polling, with an
# interval chosen so a guest that only has whole-second sleep is not slowed
# to a second per command.

case "$0" in
*/*) um_channel=${0%/*}/channel ;;
*) um_channel=channel ;;
esac
mkdir -p "$um_channel/queue" "$um_channel/results" "$um_channel/state" 2>/dev/null
# An absolute path is what keeps every later "cd" out of the picture.
um_channel=$(CDPATH= cd -- "$um_channel" 2>/dev/null && pwd)
[ -n "$um_channel" ] || exit 1

# Poll intervals for the fallback path, and the kill grace period.  "sleep
# 0.02" is coreutils/busybox, not POSIX sh: a minimal guest has no fractional
# sleep at all, and the loop then falls through to whole seconds.
um_poll=1
um_kill_sleep=1
if sleep 0.05 2>/dev/null; then
	um_poll=0.02
	um_kill_sleep=0.05
elif sleep 1 2>/dev/null; then
	um_poll=0.2
	um_kill_sleep=0.2
fi
um_kill_wait=40
# While a command runs, the loop only has to watch for a kill request, so it
# can poll much less often than when it is waiting for work: every poll is a
# guest wakeup, and wakeups are what the session is trying to stop paying for.
um_busy_poll=0.2
sleep 0.2 2>/dev/null && um_busy_poll=0.2 || um_busy_poll=1

# Publish NAME=value atomically: a reader must never see a half-written file.
um_publish() {
	printf '%s\n' "$3" >"$1/.$2" 2>/dev/null && mv "$1/.$2" "$1/$2" 2>/dev/null
}

# A bounded trace.  A guest that stops looping is otherwise invisible from the
# host, and "the command never ran" has several possible causes.
um_trace() {
	printf '%s\n' "$*" >>"$um_channel/trace" 2>/dev/null
}

um_signal_tree() {
	um_sig=$1
	um_target=$2
	case "$um_target" in '' | *[!0-9]*) return 1 ;; esac
	if kill -s "$um_sig" -- "-$um_target" 2>/dev/null; then return 0; fi
	if kill -"$um_sig" "-$um_target" 2>/dev/null; then return 0; fi
	if kill -s "$um_sig" "$um_target" 2>/dev/null; then return 0; fi
	kill -"$um_sig" "$um_target" 2>/dev/null
}

# TERM, then KILL after the grace period: a command that ignores TERM must not
# be able to hold the session open forever.
um_terminate() {
	um_target=$1
	um_signal_tree TERM "$um_target" || return 1
	um_wait=0
	while [ "$um_wait" -lt "$um_kill_wait" ]; do
		kill -0 "$um_target" 2>/dev/null || return 0
		sleep "$um_kill_sleep" 2>/dev/null || sleep 1
		um_wait=$((um_wait + 1))
	done
	um_signal_tree KILL "$um_target"
}

# um_run_one DIR NAME -- command...
#
# The command runs in a subshell that waits for it, so the loop keeps polling
# while it runs: a kill request has to be seen while the command is still
# running, and a blocking wait in the loop itself would not see it.
um_run_one() {
	um_dir=$1
	um_name=$2
	shift 2
	um_finished=$um_channel/state/$um_name
	(
		if command -v setsid >/dev/null 2>&1; then
			setsid "$@" </dev/null >"$um_dir/stdout" 2>"$um_dir/stderr" &
		else
			"$@" </dev/null >"$um_dir/stdout" 2>"$um_dir/stderr" &
		fi
		um_child=$!
		um_publish "$um_dir" pid "$um_child"
		wait "$um_child"
		um_rc=$?
		um_publish "$um_dir" status "$um_rc"
		um_publish "$um_dir" done done
		um_publish "$um_channel/state" "$um_name" done
	) &
	um_runner=$!
	while :; do
		[ -e "$um_finished" ] && break
		if [ -e "$um_dir/kill" ]; then
			um_terminate "$(cat "$um_dir/pid" 2>/dev/null)"
			while :; do
				[ -e "$um_finished" ] && break
				sleep "$um_kill_sleep" 2>/dev/null || sleep 1
			done
			break
		fi
		sleep "$um_busy_poll" 2>/dev/null || sleep 1
	done
	wait "$um_runner" 2>/dev/null
	rm -f "$um_finished" 2>/dev/null
}

# um_wait: one idle pass.
#
# This is a poll, not a blocking read, on purpose.  A FIFO in the channel looks
# like the obvious way to wake the loop -- the host knows exactly when it
# queued something -- but a hostfs mount does not carry FIFO semantics between
# the host and the guest: the host's open() of a FIFO the guest created
# answers ENXIO, so the wake byte can never be delivered.  A poll costs one
# guest wakeup per interval, which is why the interval is as long as the guest
# can afford (see above) and why the host writes the request as a single file.
um_wait() {
	sleep "$um_poll" 2>/dev/null || sleep 1
}

um_publish "$um_channel" ready neoproot-session-loop-v1
um_trace "ready poll=$um_poll kill_sleep=$um_kill_sleep"

while :; do
	if [ -e "$um_channel/stop" ]; then
		sync 2>/dev/null
		poweroff -f 2>/dev/null
		exit 0
	fi
	um_entry=
	for um_candidate in "$um_channel"/queue/*; do
		[ -e "$um_candidate" ] || continue
		um_entry=$um_candidate
		break
	done
	if [ -z "$um_entry" ]; then
		um_wait
		continue
	fi
	um_name=${um_entry##*/}
	case "$um_name" in '' | *[!0-9]*) rm -f "$um_entry"; continue ;; esac
	um_dir=$um_channel/results/$um_name
	if ! mkdir -p "$um_dir" 2>/dev/null; then
		sleep "$um_kill_sleep" 2>/dev/null || sleep 1
		continue
	fi
	# Claiming is the rename: a request is either in queue/ or in results/,
	# never both, so it cannot be started twice.
	if ! mv "$um_entry" "$um_dir/request" 2>/dev/null; then
		continue
	fi
	um_marker=
	um_cwd=
	set --
	um_argc=0
	exec 3<"$um_dir/request"
	IFS= read -r um_marker <&3
	IFS= read -r um_cwd <&3
	# One "<length>" line per argument.  The length is what lets an argument
	# contain anything but a newline, and the loop does not need to count.
	while :; do
		um_size=
		IFS= read -r um_size <&3 || break
		case "$um_size" in '' | *[!0-9]*) break ;; esac
		um_arg=
		IFS= read -r um_arg <&3 || um_arg=
		set -- "$@" "$um_arg"
		um_argc=$((um_argc + 1))
	done
	exec 3<&-
	um_trace "claim id=$um_name cwd=$um_cwd argc=$um_argc"
	if [ "$um_marker" != "neoproot-exec-v1" ] || [ "$um_argc" -eq 0 ]; then
		um_publish "$um_dir" status 125
		um_publish "$um_dir" done done
		um_publish "$um_channel/state" "$um_name" done
		continue
	fi
	if [ -n "$um_cwd" ] && ! cd "$um_cwd" 2>/dev/null; then
		um_publish "$um_dir" status 126
		um_publish "$um_dir" done done
		um_publish "$um_channel/state" "$um_name" done
		continue
	fi
	um_trace "run id=$um_name"
	um_run_one "$um_dir" "$um_name" "$@"
	um_trace "done id=$um_name status=$(cat "$um_dir/status" 2>/dev/null)"
	if [ -n "$um_cwd" ]; then cd / 2>/dev/null; fi
done
