#!/bin/sh
#
# Reference /um-init for an ext4 guest image.
#
# It implements the neoproot session protocol the supervisor drives:
#
#   session-v1   neoproot_protocol=session-v1, neoproot_session=/.neoproot-um-*
#                and neoproot_cwd=/guest/path on the kernel command line; mount
#                the hostfs session at /run/neoproot, run its init.sh, write the
#                command's exit status to /run/neoproot/status.
#
#   init-protocol 2
#                Before running init.sh, declare what this init implements in
#                /run/neoproot/init-features.  The supervisor refuses to run a
#                command whose binds were requested but not declared, so an
#                image with an older init fails loudly instead of running the
#                command without its binds.
#
#   binds v1     /run/neoproot/binds, one record per line, tab separated:
#
#                    source<TAB>target<TAB>dir|file<TAB>ro|rw<TAB>name
#
#                source is a hostfs mount option (a path relative to the
#                kernel's hostfs= root), target is an absolute guest path,
#                name is the basename for a file bind and "-" otherwise.
#                Lines starting with '#' are ignored.
#
# The same file is installed into test images by tests/stability-um-backend.sh;
# keep the two in step.  The UM harness's own um-init is a separate copy that
# needs the same two additions (see the report that shipped this file).

set +e

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
# devtmpfs gives /dev/ptmx but not /dev/pts: without a devpts mount, opening a
# pty fails with ENXIO and anything that allocates one -- sudo, sshd, screen,
# a terminal multiplexer -- says "unable to allocate pty".  Mount it after
# devtmpfs so the pts directory can be created under it.
mkdir -p /dev/pts 2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
# /run holds the session mount point and the scratch mounts for file binds.
# A tmpfs keeps them out of the image and works with a read-only root too.
mount -t tmpfs tmpfs /run 2>/dev/null

session_error() {
	printf '%s\n' 'UM_SESSION_ERROR=125'
	sync
	poweroff -f
	while :; do sleep 3600; done
}

bind_error=
protocol=
session=
cwd=
for argument in $(cat /proc/cmdline 2>/dev/null); do
	case "$argument" in
	neoproot_protocol=*) protocol=${argument#neoproot_protocol=} ;;
	neoproot_session=*) session=${argument#neoproot_session=} ;;
	neoproot_cwd=*) cwd=${argument#neoproot_cwd=} ;;
	esac
done

if [ "$protocol" != "session-v1" ] || [ -z "$session" ]; then
	session_error
fi
case "$session" in
/*) ;;
*) session_error ;;
esac

mkdir -p /run/neoproot || session_error
mount none /run/neoproot -t hostfs -o "$session" || session_error

# The declaration goes in before init.sh runs: init.sh checks it before it
# executes the caller's command.
{
	printf '%s\n' 'neoproot-init-protocol=2'
	printf '%s\n' 'feature=binds'
} >/run/neoproot/init-features 2>/dev/null

# The directory a file bind is mounted through.  hostfs cannot mount a file as
# a filesystem root, so the parent directory is mounted and the file is bound
# out of it.
mount_bind_file() {
	bind_index=$1
	bind_source=$2
	bind_target=$3
	bind_mode=$4
	bind_name=$5
	bind_scratch=/run/.neoproot-bind-$bind_index

	case "$bind_target" in
	*/*) bind_parent=${bind_target%/*} ;;
	*) bind_parent= ;;
	esac
	[ -n "$bind_parent" ] || bind_parent=/
	mkdir -p "$bind_parent" 2>/dev/null
	[ -e "$bind_target" ] || : >"$bind_target" 2>/dev/null
	if [ ! -e "$bind_target" ]; then
		bind_error="UM_BIND_ERROR=$bind_target:missing-target"
		return 1
	fi
	mkdir -p "$bind_scratch" 2>/dev/null
	if ! mount -t hostfs -o "$bind_source" none "$bind_scratch" 2>/dev/null; then
		bind_error="UM_BIND_ERROR=$bind_target:mount-failed"
		return 1
	fi
	if [ "$bind_mode" = "ro" ]; then
		# Making the scratch mount read-only makes the bind out of it
		# read-only as well, and keeps it private to this one bind.
		if ! mount -o remount,ro "$bind_scratch" 2>/dev/null; then
			bind_error="UM_BIND_ERROR=$bind_target:readonly-failed"
			return 1
		fi
	fi
	if ! mount --bind "$bind_scratch/$bind_name" "$bind_target" 2>/dev/null; then
		bind_error="UM_BIND_ERROR=$bind_target:bind-failed"
		return 1
	fi
	return 0
}

mount_binds() {
	bind_index=0
	bind_tab=$(printf '\t')
	while IFS=$bind_tab read -r bind_source bind_target bind_type bind_mode bind_name; do
		case "$bind_source" in
		'' | '#'*) continue ;;
		esac
		bind_index=$((bind_index + 1))
		case "$bind_target" in
		/run/neoproot | /run/neoproot/*)
			bind_error="UM_BIND_ERROR=$bind_target:target-inside-session"
			return 1
			;;
		/*) ;;
		*)
			bind_error="UM_BIND_ERROR=$bind_target:relative-target"
			return 1
			;;
		esac
		case "$bind_type" in
		dir)
			mkdir -p "$bind_target" 2>/dev/null
			if [ ! -d "$bind_target" ]; then
				bind_error="UM_BIND_ERROR=$bind_target:missing-target"
				return 1
			fi
			if ! mount -t hostfs -o "$bind_source" none "$bind_target" 2>/dev/null; then
				bind_error="UM_BIND_ERROR=$bind_target:mount-failed"
				return 1
			fi
			if [ "$bind_mode" = "ro" ] &&
				! mount -o remount,ro "$bind_target" 2>/dev/null; then
				bind_error="UM_BIND_ERROR=$bind_target:readonly-failed"
				return 1
			fi
			;;
		file)
			mount_bind_file "$bind_index" "$bind_source" "$bind_target" \
				"$bind_mode" "$bind_name" || return 1
			;;
		*)
			bind_error="UM_BIND_ERROR=$bind_target:bad-type"
			return 1
			;;
		esac
	done </run/neoproot/binds
	return 0
}

if [ -f /run/neoproot/binds ]; then
	if ! mount_binds; then
		# The supervisor reports this line instead of a bare failure, so a
		# missing target or a refused mount is traceable to the bind.
		printf '%s\n' "$bind_error" >/run/neoproot/protocol-error
		printf '%s\n' "$bind_error"
		printf '%s\n' 125 >/run/neoproot/status
		sync
		poweroff -f
		while :; do sleep 3600; done
	fi
fi

[ -n "$cwd" ] && cd "$cwd" 2>/dev/null

/bin/sh /run/neoproot/init.sh
rc=$?
printf '%s\n' "$rc" >/run/neoproot/status
printf 'UM_COMMAND_EXIT=%s\n' "$rc"
sync
poweroff -f
while :; do sleep 3600; done
