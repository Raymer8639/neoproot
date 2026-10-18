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

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
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
# Set by a case that needs a check run_case cannot make on its own.
post_check=

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

# A UML run started outside this matrix -- an interactive session the developer
# left open -- looks exactly like a survivor.  Record what is already running
# before the first case and subtract it, so the check judges this run only.
baseline_processes=

# Count only processes this matrix is not already aware of.  $1 is the
# baseline captured before the first case: a map of pid -> comm.
leftover_processes() {
	for stat in /proc/[0-9]*/comm; do
		comm=$(cat "$stat" 2>/dev/null) || continue
		case "$comm" in
		linux-bionic | umnet | passt-bionic) ;;
		*) continue ;;
		esac
		pid=${stat#/proc/}
		pid=${pid%/comm}
		if [ -n "${baseline_processes:-}" ] &&
		   printf '%s\n' "$baseline_processes" | grep -qx "$pid"; then
			continue
		fi
		printf '%s ' "$comm"
	done
}

# Snapshot the pids of our process names before any case runs.
snapshot_processes() {
	for stat in /proc/[0-9]*/comm; do
		comm=$(cat "$stat" 2>/dev/null) || continue
		case "$comm" in
		linux-bionic | umnet | passt-bionic)
			pid=${stat#/proc/}
			printf '%s\n' "${pid%/comm}"
			;;
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
	# The supervisor makes these next to the rootfs, or in TMPDIR.  ext4 mode
	# puts the runtime directory in TMPDIR, not next to the image, so both
	# places have to be counted or the check would pass without looking.
	count=0
	for dir in "$workdir"/.neoproot-um-* "$workdir"/neoproot-um-* \
		"${TMPDIR:-/tmp}"/.neoproot-um-* "${TMPDIR:-/tmp}"/neoproot-um-*; do
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
	# An empty marker means the case expects the guest command not to run at
	# all -- a protocol refusal, for instance.
	if [ -n "$expected_marker" ] &&
		! grep -qa "MARKER=$expected_marker" "$log"; then
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
	# Contracts the log cannot show -- a write that had to land on the host, an
	# image that had to stay byte-identical.  Set post_check before the call;
	# the hook reports through problem() like everything else.
	if [ "$ok" = 1 ] && [ -n "$post_check" ]; then
		"$post_check" || ok=0
	fi
	post_check=

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
#
# Two contracts beyond the plain boot live here as well: the COW file, which is
# temporary and deleted unless --cow-file names it, and binds, which the guest
# init has to mount and declare support for.

ext4_image=$workdir/stability-root.ext4
ext4_init_source=${EXT4_INIT:-"$script_directory/um-init-ext4.sh"}
ext4_case_count=12

# The guest command has to live inside the image, and the marker differs per
# case, so the image is rebuilt for each one.  It is 64 MB against a local
# mke2fs, which costs about a second.
build_ext4_image() {
	command_body=$1

	stage=$workdir/stability-stage
	rm -rf "$stage"
	mkdir -p "$stage"
	populate_ext4_stage "$stage" || return 1
	cp "$ext4_init" "$stage/um-init" 2>/dev/null || return 1
	printf '%s\n' "$command_body" >"$stage/stability-command.sh"
	chmod 755 "$stage/um-init" "$stage/stability-command.sh"

	if ! dd if=/dev/zero of="$ext4_image" bs=1M count=64 status=none 2>/dev/null; then
		return 1
	fi
	if ! mke2fs -q -t ext4 -F -d "$stage" "$ext4_image" >/dev/null 2>&1; then
		return 1
	fi
	return 0
}

run_ext4_case() {
	name=$1
	expected_rc=$2
	expected_marker=$3
	shift 3

	build_ext4_image "#!/bin/sh
echo \"MARKER=$expected_marker\"
exit $expected_rc" || return 1

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
		"$stage_dir/dev" "$stage_dir/run/neoproot" "$stage_dir/tmp" \
		"$stage_dir/mnt/hostdir" "$stage_dir/mnt/ro"
	# A file bind needs a file to mount over, and the target has to exist in
	# the image: the guest root is not writable in --readonly mode.
	: >"$stage_dir/mnt/hostfile"
	: >"$stage_dir/mnt/rofile"
	cp "$bbstatic" "$stage_dir/bin/busybox" || return 1
	chmod 755 "$stage_dir/bin/busybox"
	for applet in sh mount cat mkdir sleep poweroff ls echo; do
		ln -sf busybox "$stage_dir/bin/$applet"
	done
	return 0
}

image_sha() {
	sha256sum "$ext4_image" | cut -d' ' -f1
}

check_image_unchanged() {
	if [ "$(image_sha)" != "$image_sha_before" ]; then
		problem "the ext4 base image changed"
		return 1
	fi
	return 0
}

# The guest command for the COW cases: run 1 writes, run 2 looks.  The same
# image is used for both runs, so only the COW can carry the file across.
cow_persist_command='#!/bin/sh
if [ -e /cow-persist.txt ]; then
	echo "COW_PERSIST=$(cat /cow-persist.txt)"
	echo "MARKER=cow-file-second"
else
	printf "written-in-run-1\n" >/cow-persist.txt
	echo "COW_PERSIST=absent"
	echo "MARKER=cow-file-first"
fi
exit 0'

check_cow_created() {
	if [ ! -f "$cow_file" ]; then
		problem "the named COW file was not created"
		return 1
	fi
	check_image_unchanged
}

check_cow_persisted() {
	if ! grep -qa 'COW_PERSIST=written-in-run-1' \
		"$workdir/stability-ext4-cow-file-2.log"; then
		problem "the second run did not see the first run's write"
		return 1
	fi
	if [ ! -s "$cow_file" ]; then
		problem "the COW file did not survive the second run"
		return 1
	fi
	check_image_unchanged
}

check_cow_not_persisted() {
	if ! grep -qa 'COW_PERSIST=absent' \
		"$workdir/stability-ext4-cow-temp-2.log"; then
		problem "a run without --cow-file persisted its writes"
		return 1
	fi
	# The temporary COW lives in the session directory; nothing named root.cow
	# may be left anywhere under TMPDIR once the run is over.
	if find "${TMPDIR:-/tmp}" -maxdepth 3 -name 'root.cow' -print -quit |
		grep . >/dev/null; then
		problem "a temporary COW file was left behind"
		return 1
	fi
	check_image_unchanged
}

# Host-side sources for the bind cases.  The guest reaches them through hostfs
# mount options the supervisor computes, which is what makes this worth running
# against the real kernel.
bind_root=$workdir/stability-bind

prepare_bind_sources() {
	rm -rf "$bind_root"
	mkdir -p "$bind_root/dir" "$bind_root/ro"
	printf 'host-hello\n' >"$bind_root/dir/hello.txt"
	printf 'host-file\n' >"$bind_root/file.txt"
	printf 'host-ro\n' >"$bind_root/ro/keep.txt"
	printf 'host-ro-file\n' >"$bind_root/rofile.txt"
}

binds_command='#!/bin/sh
set +e
rc=0
hello=$(cat /mnt/hostdir/hello.txt 2>/dev/null)
[ "$hello" = "host-hello" ] || rc=1
printf "written-by-guest\n" >/mnt/hostdir/from-guest.txt || rc=1
if printf "nope\n" >/mnt/ro/from-guest.txt 2>/dev/null; then
	echo "BIND_RO_DIR=write-allowed"
	rc=1
else
	echo "BIND_RO_DIR=write-denied"
fi
file=$(cat /mnt/hostfile 2>/dev/null)
[ "$file" = "host-file" ] || rc=1
printf "written-by-guest-file\n" >/mnt/hostfile || rc=1
if printf "nope\n" >/mnt/rofile 2>/dev/null; then
	echo "BIND_RO_FILE=write-allowed"
	rc=1
else
	echo "BIND_RO_FILE=write-denied"
fi
[ "$(cat /mnt/ro/keep.txt 2>/dev/null)" = "host-ro" ] || rc=1
[ "$(cat /mnt/rofile 2>/dev/null)" = "host-ro-file" ] || rc=1
echo "BIND_HELLO=$hello BIND_FILE=$file RC=$rc"
if [ "$rc" -eq 0 ]; then
	echo "MARKER=binds-ok"
else
	echo "MARKER=binds-broken"
	exit 1
fi
exit 0'

# A guest that exits non-zero still reports its own code with binds mounted.
binds_exit_command='#!/bin/sh
hello=$(cat /mnt/hostdir/hello.txt 2>/dev/null)
echo "BIND_HELLO=$hello"
echo "MARKER=binds-exit-7"
[ "$hello" = "host-hello" ] || exit 1
exit 7'

check_binds_host() {
	binds_ok=1
	if [ "$(cat "$bind_root/dir/from-guest.txt" 2>/dev/null)" != \
		"written-by-guest" ]; then
		problem "the guest's write did not reach the bound host directory"
		binds_ok=0
	fi
	if [ "$(cat "$bind_root/file.txt" 2>/dev/null)" != \
		"written-by-guest-file" ]; then
		problem "the guest's write did not reach the bound host file"
		binds_ok=0
	fi
	if [ -e "$bind_root/ro/from-guest.txt" ]; then
		problem "a read-only directory bind accepted a write"
		binds_ok=0
	fi
	if [ "$(cat "$bind_root/rofile.txt" 2>/dev/null)" != "host-ro-file" ]; then
		problem "a read-only file bind was modified"
		binds_ok=0
	fi
	[ "$binds_ok" = 1 ] || return 1
	check_image_unchanged
}

check_binds_and_cow() {
	if [ ! -s "$bind_cow_file" ]; then
		problem "the COW file used with binds was not created"
		return 1
	fi
	check_binds_host
}

check_legacy_refused() {
	if ! grep -qa 'does not support binds' \
		"$workdir/stability-ext4-binds-legacy.log"; then
		problem "an init without the binds feature was not refused"
		return 1
	fi
	check_image_unchanged
}

check_missing_target() {
	if ! grep -qa 'UM_BIND_ERROR=/mnt/absent:missing-target' \
		"$workdir/stability-ext4-binds-missing.log"; then
		problem "a bind whose target cannot be created was not reported"
		return 1
	fi
	check_image_unchanged
}

baseline_processes=$(snapshot_processes)

if command -v mke2fs >/dev/null 2>&1 && [ -x "$bbstatic" ] &&
	[ -f "$ext4_init_source" ]; then
	# Kept outside the per-case stage so rebuilding the image does not have
	# to re-create the init every time.
	ext4_init=$workdir/stability-um-init
	cp "$ext4_init_source" "$ext4_init" || exit 1
	chmod 755 "$ext4_init"

	echo "ext4 image: $ext4_image"
	echo "ext4 init:  $ext4_init_source"
	echo

	run_ext4_case ext4 0 ext4-ok
	run_ext4_case ext4-net 0 ext4-net-ok --net
	run_ext4_case ext4-readonly 0 ext4-ro-ok --readonly

	# --- a named COW file keeps its writes, a temporary one does not -------
	cow_file=$workdir/stability-persist.cow
	rm -f "$cow_file"
	build_ext4_image "$cow_persist_command" || exit 1
	image_sha_before=$(image_sha)
	post_check=check_cow_created
	run_case ext4-cow-file-1 0 cow-file-first --rootfs="$ext4_image" \
		--cow-file="$cow_file"
	post_check=check_cow_persisted
	run_case ext4-cow-file-2 0 cow-file-second --rootfs="$ext4_image" \
		--cow-file="$cow_file"

	build_ext4_image "$cow_persist_command" || exit 1
	image_sha_before=$(image_sha)
	run_case ext4-cow-temp-1 0 cow-file-first --rootfs="$ext4_image"
	post_check=check_cow_not_persisted
	run_case ext4-cow-temp-2 0 cow-file-first --rootfs="$ext4_image"
	rm -f "$cow_file"

	# --- binds -------------------------------------------------------------
	prepare_bind_sources
	build_ext4_image "$binds_command" || exit 1
	image_sha_before=$(image_sha)
	post_check=check_binds_host
	run_case ext4-binds 0 binds-ok --rootfs="$ext4_image" \
		-b "$bind_root/dir:/mnt/hostdir" \
		-b "$bind_root/file.txt:/mnt/hostfile" \
		-b "$bind_root/ro:/mnt/ro:ro" \
		-b "$bind_root/rofile.txt:/mnt/rofile:ro"

	# Exit codes travel through the bind path unchanged.
	prepare_bind_sources
	build_ext4_image "$binds_exit_command" || exit 1
	image_sha_before=$(image_sha)
	post_check=check_image_unchanged
	run_case ext4-binds-exit-7 7 binds-exit-7 --rootfs="$ext4_image" \
		-b "$bind_root/dir:/mnt/hostdir"

	prepare_bind_sources
	bind_cow_file=$workdir/stability-binds.cow
	rm -f "$bind_cow_file"
	build_ext4_image "$binds_command" || exit 1
	image_sha_before=$(image_sha)
	post_check=check_binds_and_cow
	run_case ext4-binds-cow 0 binds-ok --rootfs="$ext4_image" \
		--cow-file="$bind_cow_file" \
		-b "$bind_root/dir:/mnt/hostdir" \
		-b "$bind_root/file.txt:/mnt/hostfile" \
		-b "$bind_root/ro:/mnt/ro:ro" \
		-b "$bind_root/rofile.txt:/mnt/rofile:ro"
	rm -f "$bind_cow_file"

	# An image whose /um-init predates the feature must fail loudly: the
	# command must not run with its binds silently missing.
	legacy_init=$workdir/stability-um-init-legacy
	cat >"$legacy_init" <<'INIT'
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
	chmod 755 "$legacy_init"
	prepare_bind_sources
	ext4_init=$legacy_init
	build_ext4_image "$binds_command" || exit 1
	image_sha_before=$(image_sha)
	post_check=check_legacy_refused
	run_case ext4-binds-legacy 1 "" --rootfs="$ext4_image" \
		-b "$bind_root/dir:/mnt/hostdir"
	ext4_init=$workdir/stability-um-init

	# A bind whose target cannot be created (read-only root) is reported as a
	# protocol error, not as a bare failure or a silent success.
	prepare_bind_sources
	build_ext4_image "$binds_command" || exit 1
	image_sha_before=$(image_sha)
	post_check=check_missing_target
	run_case ext4-binds-missing 1 "" --rootfs="$ext4_image" --readonly \
		-b "$bind_root/dir:/mnt/absent"
elif [ ! -x "$bbstatic" ]; then
	echo "ext4 cases skipped: no static busybox at $bbstatic (set BBSTATIC=)"
	echo "  the image needs a shell: um-init is a #!/bin/sh script, and without"
	echo "  an interpreter the kernel reports the init as missing"
	skip=$((skip + ext4_case_count))
elif [ ! -f "$ext4_init_source" ]; then
	echo "ext4 cases skipped: no reference init at $ext4_init_source (set EXT4_INIT=)"
	skip=$((skip + ext4_case_count))
else
	echo "ext4 cases skipped: no mke2fs"
	skip=$((skip + ext4_case_count))
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
