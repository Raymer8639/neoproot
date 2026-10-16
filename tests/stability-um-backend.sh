#!/bin/sh
#
# Stability matrix for the UML backend of neoproot-um.
#
# The existing tests each check one contract with mocks (argv shape, CLI
# validation) or check the network path through umnet directly.  None of them
# answers the question a user actually asks -- does the backend survive being
# driven the way it is really driven, over and over, in every mode, without
# leaving anything behind?
#
# So this drives the real kernel, the real hostfs root and the real bridge, and
# after each run checks four things that have all been wrong at some point:
#
#   rc        -- the guest's exit code reaches the caller unchanged
#   marker    -- the command the caller asked for is the one that ran, and it
#                ran to completion rather than being cut off mid-way
#   processes -- no umnet, passt or kernel outlives the run
#   residue   -- no umid directory and no runtime directory is left behind
#
# The exit code and the marker are separate on purpose: a run that reports the
# right code having executed nothing is the failure this backend has produced
# before (a truncated argv dropped the session parameters and the guest
# reported success for a command it never ran).
#
# Usage:
#   stability-um-backend.sh [--iterations N] [--workdir DIR] [--assets DIR]
#
# Environment it needs, all of which the gate also needs:
#   <workdir>/netroot        Alpine hostfs root, with um-init installed
#   <workdir>/umnet          bridge, for the --net cases
#   <workdir>/passt-bionic   passt, for the --net cases
#   <assets>/linux-bionic    UML kernel       (default $PREFIX/tmp/um-arm64/new)
#   <assets>/stub_exe        stub for the kernel
#   NEOPROOT_UM              the supervisor under test
#
# Exit: 0 all cases passed, 1 at least one failed, 77 nothing could be attempted.

set -u

iterations=1
workdir=${WORKDIR:-${PREFIX:-/data/data/com.termux/files/usr}/tmp/um-network}
assets=${ASSETS:-${PREFIX:-/data/data/com.termux/files/usr}/tmp/um-arm64/new}
supervisor=${NEOPROOT_UM:-}
# A static busybox to put a shell inside the ext4 image.  Without one the
# guest cannot run a shell-script init at all -- see prepare_ext4().
bbstatic=${BBSTATIC:-${PREFIX:-/data/data/com.termux/files/usr}/tmp/asset-builder/bbstatic/bin/busybox.static}

while [ $# -gt 0 ]; do
	case "$1" in
	--iterations) iterations=$2; shift 2 ;;
	--workdir) workdir=$2; shift 2 ;;
	--assets) assets=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

kernel=$assets/linux-bionic
stub=$assets/stub_exe
netroot=$workdir/netroot
umnet=$workdir/umnet
passt=$workdir/passt-bionic

pass=0
fail=0
skip=0

problem() {
	echo "  FAIL: $1"
	fail=$((fail + 1))
	return 1
}

# --- preconditions -------------------------------------------------------
#
# Missing assets mean this judges nothing, and saying so is the point: a
# release record has to keep "not tested" apart from "broken".

missing=
[ -x "$supervisor" ] || missing="$missing supervisor($supervisor)"
[ -x "$kernel" ] || missing="$missing kernel"
[ -x "$stub" ] || missing="$missing stub"
[ -d "$netroot" ] || missing="$missing netroot"
if [ ! -d "$netroot" ]; then
	:
elif [ ! -f "$netroot/um-init" ]; then
	# Everything below boots the guest through the hostfs root, and without
	# the init the kernel panics with a message that reads like a kernel
	# fault.  Name the real cause instead.
	missing="$missing netroot/um-init"
fi
if [ -n "$missing" ]; then
	echo "SKIP: cannot attempt the stability matrix:$missing" >&2
	echo "verdict=SKIP" >&2
	exit 77
fi

# --- helpers -------------------------------------------------------------

leftover_processes() {
	for stat in /proc/[0-9]*/comm; do
		comm=$(cat "$stat" 2>/dev/null) || continue
		case "$comm" in
		linux-bionic | umnet | passt-bionic) printf '%s ' "$comm" ;;
		esac
	done
}

umid_count() {
	if [ -d "$HOME/.uml" ]; then
		ls -1A "$HOME/.uml" 2>/dev/null | wc -l
	else
		echo 0
	fi
}

runtime_dirs() {
	# The supervisor makes these next to the rootfs, or in TMPDIR.
	count=0
	for dir in "$workdir"/.neoproot-um-* "$workdir"/neoproot-um-*; do
		[ -e "$dir" ] && count=$((count + 1))
	done
	echo "$count"
}

# Write the guest command, run one case, and judge it.
#
# $1 case name, $2 expected rc, $3 expected marker, rest: supervisor arguments
run_case() {
	name=$1
	expected_rc=$2
	expected_marker=$3
	shift 3

	command="$netroot/stability-command.sh"
	cat >"$command" <<EOF
#!/bin/sh
echo "MARKER=$expected_marker"
exit $expected_rc
EOF
	chmod 755 "$command"

	umid_before=$(umid_count)
	runtime_before=$(runtime_dirs)
	log=$workdir/stability-$name.log

	NEOPROOT_UM_NET="$umnet" NEOPROOT_UM_PASST="$passt" \
		timeout 200 "$supervisor" --kernel="$kernel" --stub="$stub" \
		--timeout=120 "$@" -- /stability-command.sh \
		>"$log" 2>&1
	actual_rc=$?
	sleep 1

	umid_after=$(umid_count)
	runtime_after=$(runtime_dirs)
	leftover=$(leftover_processes)

	printf '%-22s ' "$name"

	ok=1
	if [ "$actual_rc" != "$expected_rc" ]; then
		problem "rc=$actual_rc, expected $expected_rc"
		ok=0
	fi
	if ! grep -qa "MARKER=$expected_marker" "$log"; then
		problem "marker MARKER=$expected_marker not in the output"
		ok=0
	fi
	if [ -n "$leftover" ]; then
		problem "processes survived the run: $leftover"
		ok=0
	fi
	if [ "$umid_after" -gt "$umid_before" ]; then
		problem "left $((umid_after - umid_before)) umid directory behind"
		ok=0
	fi
	if [ "$runtime_after" -gt "$runtime_before" ]; then
		problem "left $((runtime_after - runtime_before)) runtime directory behind"
		ok=0
	fi

	if [ "$ok" = 1 ]; then
		echo "rc=$actual_rc ok"
		pass=$((pass + 1))
	else
		echo "  log: $log"
	fi
}

# --- the matrix ----------------------------------------------------------

echo "stability matrix: supervisor=$supervisor"
echo "                  workdir=$workdir assets=$assets iterations=$iterations"
echo

i=1
while [ "$i" -le "$iterations" ]; do
	[ "$iterations" -gt 1 ] && echo "--- iteration $i/$iterations ---"

	# hostfs, no network: the plainest path, and the one a user hits first.
	run_case hostfs 0 hostfs-ok --rootfs="$netroot" --hostfs

	# hostfs with the bridge: exercises the umnet handoff and teardown.
	run_case hostfs-net 0 hostfs-net-ok --rootfs="$netroot" --hostfs --net

	# Exit codes have to survive the whole chain: supervisor -> kernel ->
	# guest init -> the command's own exit.
	run_case exit-7 7 exit-7-ok --rootfs="$netroot" --hostfs
	run_case exit-125 125 exit-125-ok --rootfs="$netroot" --hostfs

	i=$((i + 1))
done

# --- ext4 ---------------------------------------------------------------
#
# The mode that has broken this backend before.  In ext4 the guest is started
# through /um-init and the session-v1 protocol, and a truncated argv there does
# not fail loudly -- it drops the session parameters, and the guest then runs
# the bare fallback, ignores the caller's command and reports success.  So the
# marker check matters more here than anywhere else.

ext4_image=$workdir/stability-root.ext4

prepare_ext4() {
	stage=$workdir/stability-stage
	rm -rf "$stage"
	mkdir -p "$stage"

	if ! command -v mke2fs >/dev/null 2>&1; then
		return 1
	fi

	# A session-aware init: this is what neoproot_protocol=session-v1 tells
	# the guest to do, and what the hostfs init is not.
	cat >"$stage/um-init" <<'INIT'
#!/bin/sh
set +e
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /run/neoproot

session=
cwd=
for argument in $(cat /proc/cmdline); do
	case "$argument" in
	neoproot_session=*) session=${argument#neoproot_session=} ;;
	neoproot_cwd=*) cwd=${argument#neoproot_cwd=} ;;
	esac
done

if [ -z "$session" ] || ! mount none /run/neoproot -t hostfs -o "$session"; then
	# The supervisor scores UM_SESSION_ERROR as its own distinguishable
	# failure; a bare panic here would look like a kernel problem.
	echo "UM_SESSION_ERROR=125"
	poweroff -f
	while :; do sleep 3600; done
fi

[ -n "$cwd" ] && cd "$cwd" 2>/dev/null
/bin/sh /run/neoproot/init.sh
rc=$?
printf '%s\n' "$rc" >/run/neoproot/status
echo "UM_COMMAND_EXIT=$rc"
poweroff -f
while :; do sleep 3600; done
INIT
	chmod 755 "$stage/um-init"

	dd if=/dev/zero of="$ext4_image" bs=1M count=64 status=none 2>/dev/null || return 1
	mke2fs -q -t ext4 -F "$ext4_image" >/dev/null 2>&1 || return 1
	mke2fs -q -t ext4 -F -d "$stage" "$ext4_image" >/dev/null 2>&1 || return 1
	return 0
}

# The guest command has to live inside the image, and the marker differs per
# case, so the image is rebuilt for each one.  It is 64 MB against a local
# mke2fs, which costs about a second.
run_ext4_case() {
	name=$1
	expected_rc=$2
	expected_marker=$3
	shift 3

	stage=$workdir/stability-stage
	rm -rf "$stage"
	mkdir -p "$stage"
	populate_ext4_stage "$stage" || return 1
	cp "$ext4_init" "$stage/um-init" 2>/dev/null || return 1
	cat >"$stage/stability-command.sh" <<EOF
#!/bin/sh
echo "MARKER=$expected_marker"
exit $expected_rc
EOF
	chmod 755 "$stage/um-init" "$stage/stability-command.sh"

	if ! dd if=/dev/zero of="$ext4_image" bs=1M count=64 status=none 2>/dev/null; then
		return 1
	fi
	if ! mke2fs -q -t ext4 -F -d "$stage" "$ext4_image" >/dev/null 2>&1; then
		return 1
	fi

	run_case "$name" "$expected_rc" "$expected_marker" \
		--rootfs="$ext4_image" "$@"
}

# The guest's init is a shell script, and a script is only executable if its
# interpreter exists.  An image holding just um-init and the command -- which is
# what this test built first -- makes the kernel fail the exec with -ENOENT and
# report
#
#	Kernel panic - not syncing: Requested init /um-init failed (error -2).
#
# which reads exactly like a missing init, or a filesystem the guest cannot
# read, and is neither: the shebang interpreter was missing.  So the image has
# to carry a shell, and the mount points the init needs.
populate_ext4_stage() {
	stage_dir=$1

	if [ ! -x "$bbstatic" ]; then
		return 1
	fi

	mkdir -p "$stage_dir/bin" "$stage_dir/proc" "$stage_dir/sys" \
		"$stage_dir/dev" "$stage_dir/run/neoproot" "$stage_dir/tmp"
	cp "$bbstatic" "$stage_dir/bin/busybox" || return 1
	chmod 755 "$stage_dir/bin/busybox"
	for applet in sh mount cat mkdir sleep poweroff ls echo; do
		ln -sf busybox "$stage_dir/bin/$applet"
	done
	return 0
}

if command -v mke2fs >/dev/null 2>&1; then
	# Kept outside the per-case stage so rebuilding the image does not have
	# to re-create the init every time.
	ext4_init=$workdir/stability-um-init
	cat >"$ext4_init" <<'INIT'
#!/bin/sh
set +e
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /run/neoproot

session=
cwd=
for argument in $(cat /proc/cmdline); do
	case "$argument" in
	neoproot_session=*) session=${argument#neoproot_session=} ;;
	neoproot_cwd=*) cwd=${argument#neoproot_cwd=} ;;
	esac
done

if [ -z "$session" ] || ! mount none /run/neoproot -t hostfs -o "$session"; then
	echo "UM_SESSION_ERROR=125"
	poweroff -f
	while :; do sleep 3600; done
fi

[ -n "$cwd" ] && cd "$cwd" 2>/dev/null
/bin/sh /run/neoproot/init.sh
rc=$?
printf '%s\n' "$rc" >/run/neoproot/status
echo "UM_COMMAND_EXIT=$rc"
poweroff -f
while :; do sleep 3600; done
INIT
	chmod 755 "$ext4_init"

	echo "ext4 image: $ext4_image"
	echo
	run_ext4_case ext4 0 ext4-ok
	run_ext4_case ext4-net 0 ext4-net-ok --net
	run_ext4_case ext4-readonly 0 ext4-ro-ok --readonly
elif [ ! -x "$bbstatic" ]; then
	echo "ext4 cases skipped: no static busybox at $bbstatic (set BBSTATIC=)"
	echo "  the image needs a shell: um-init is a #!/bin/sh script, and without"
	echo "  an interpreter the kernel reports the init as missing"
	skip=$((skip + 3))
else
	echo "ext4 cases skipped: no mke2fs"
	skip=$((skip + 3))
fi

# --- timeout and signals ------------------------------------------------
#
# These two judge a different contract: not "did the guest do the right thing"
# but "does the supervisor come back, with the documented code, leaving nothing
# running".  124 is the timeout convention, 128+15 the requested-signal one.

run_timeout_case() {
	# A guest command that cannot finish inside --timeout=5.
	cat >"$netroot/stability-command.sh" <<'EOF'
#!/bin/sh
echo "MARKER=timeout-started"
sleep 120
EOF
	chmod 755 "$netroot/stability-command.sh"

	umid_before=$(umid_count)
	NEOPROOT_UM_NET="$umnet" NEOPROOT_UM_PASST="$passt" \
		timeout 90 "$supervisor" --kernel="$kernel" --stub="$stub" \
		--rootfs="$netroot" --hostfs --timeout=5 -- /stability-command.sh \
		>"$workdir/stability-timeout.log" 2>&1
	actual_rc=$?
	sleep 2

	printf '%-22s ' "timeout"
	ok=1
	if [ "$actual_rc" != 124 ]; then
		problem "rc=$actual_rc, expected 124"
		ok=0
	fi
	leftover=$(leftover_processes)
	if [ -n "$leftover" ]; then
		problem "processes survived the timeout: $leftover"
		ok=0
	fi
	[ "$(umid_count)" -gt "$umid_before" ] && { problem "umid residue"; ok=0; }
	[ "$ok" = 1 ] && { echo "rc=124 ok"; pass=$((pass + 1)); }
}

run_sigterm_case() {
	cat >"$netroot/stability-command.sh" <<'EOF'
#!/bin/sh
echo "MARKER=sigterm-started"
sleep 120
EOF
	chmod 755 "$netroot/stability-command.sh"

	umid_before=$(umid_count)
	NEOPROOT_UM_NET="$umnet" NEOPROOT_UM_PASST="$passt" \
		"$supervisor" --kernel="$kernel" --stub="$stub" \
		--rootfs="$netroot" --hostfs --timeout=120 -- /stability-command.sh \
		>"$workdir/stability-sigterm.log" 2>&1 &
	job=$!

	# Wait for the guest to actually be up before signalling, or the test
	# would be measuring how fast the supervisor handles a race.
	tries=0
	while [ "$tries" -lt 60 ]; do
		grep -qa "MARKER=sigterm-started" "$workdir/stability-sigterm.log" 2>/dev/null && break
		sleep 0.5
		tries=$((tries + 1))
	done
	kill -TERM "$job" 2>/dev/null
	wait "$job"
	actual_rc=$?
	sleep 2

	printf '%-22s ' "sigterm"
	ok=1
	if [ "$actual_rc" != 143 ]; then
		problem "rc=$actual_rc, expected 143 (128+SIGTERM)"
		ok=0
	fi
	leftover=$(leftover_processes)
	if [ -n "$leftover" ]; then
		problem "processes survived SIGTERM: $leftover"
		ok=0
	fi
	[ "$(umid_count)" -gt "$umid_before" ] && { problem "umid residue"; ok=0; }
	[ "$ok" = 1 ] && { echo "rc=143 ok"; pass=$((pass + 1)); }
}

run_timeout_case
run_sigterm_case

# --- summary -------------------------------------------------------------

total=$((pass + fail))
echo
echo "cases: $total  pass: $pass  fail: $fail  skip: $skip"
if [ "$fail" -gt 0 ]; then
	echo "verdict=FAIL"
	exit 1
fi
echo "verdict=PASS"
exit 0
