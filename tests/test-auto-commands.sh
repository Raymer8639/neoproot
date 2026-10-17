#!/bin/sh
#
# --backend=auto has to choose by what the guest command needs.
#
# auto used to be a single question -- "are the UML prerequisites configured?" --
# so a caller who had a kernel set up for one container got the UML backend for
# every command, including the ones PRoot runs faster.  It now asks the command
# too: PRoot stays the default, and the UML backend is taken only for a command
# that needs a real kernel, or that the caller named with --auto-um-commands.
#
# The mock kernel stands in for the whole UML path: it is resolved, exec'd and
# records its own argv, so "was the UML backend reached" is a file that exists.
# The default PRoot path cannot be reached here (it needs a real rootfs and a
# container to trace), so "the default backend was chosen" is asserted from what
# neoproot says on stderr, which is the same sentence a user sees.
#
# The messages themselves are pinned by tests/test-auto-backend.c, which links
# the policy directly.  This file checks the dispatch: which backend ran, and
# that the option is consumed rather than forwarded.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
neoproot="$script_directory/../src/neoproot"

if [ ! -x "$neoproot" ]; then
	echo "skip: $neoproot is not available" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: auto backend test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-auto.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

argv_file="$temporary_directory/kernel-argv"
rootfs="$temporary_directory/rootfs"
kernel="$temporary_directory/kernel"
mkdir "$rootfs"

# A mock kernel: records the vector it was exec'd with, then stops.  The UM
# supervisor gets past its own prerequisite checks, which is all this needs.
cat >"$kernel" <<MOCK_KERNEL
#!/bin/sh
: >"$argv_file"
for argument do
	printf '%s\\n' "\$argument" >>"$argv_file"
done
exit 0
MOCK_KERNEL
chmod 755 "$kernel"

um_environment() {
	NEOPROOT_UM_KERNEL="$kernel" NEOPROOT_UM_STUB="$kernel" "$@"
}

fail() {
	echo "FAIL: $1" >&2
	if [ -f "$argv_file" ]; then
		echo "--- mock kernel argv ---" >&2
		cat "$argv_file" >&2
	fi
	exit 1
}

# Run one command line and keep both what it said and whether UML ran.
output=
reached=
run_auto() {
	rm -f "$argv_file"
	output=$(um_environment "$neoproot" "$@" 2>&1 || true)
	if [ -f "$argv_file" ]; then
		reached=yes
	else
		reached=no
	fi
}

require_um() {
	[ "$reached" = yes ] || fail "the UML backend was not reached for: $*"
	case "$output" in
	*"selected the um backend"*) ;;
	*) fail "no selection notice on stderr for: $*" ;;
	esac
}

require_default() {
	[ "$reached" = no ] || fail "the UML backend was reached for: $*"
	case "$output" in
	*"selected the um backend"*)
		fail "the UML backend was announced for: $*" ;;
	esac
}

# --- a command that needs a real kernel selects UML ------------------------
#
# Configured prerequisites plus a command from the default set is exactly the
# case the feature exists for.
run_auto --backend=auto -r "$rootfs" -- docker
require_um "docker"
case "$output" in
*"command 'docker' needs a real kernel"*) ;;
*) fail "the selection notice does not name the command: $output" ;;
esac

# A second name from the set, and the basename rule: a path is the same command.
run_auto --backend=auto -r "$rootfs" -- mount
require_um "mount"
run_auto --backend=auto -r "$rootfs" -- /usr/bin/mount
require_um "/usr/bin/mount"

# Wrappers that only start the command are looked through: the decision is
# about what actually runs.
run_auto --backend=auto -r "$rootfs" -- env FOO=1 docker
require_um "env FOO=1 docker"
case "$output" in
*"command 'docker' needs a real kernel"*) ;;
*) fail "the wrapper hid the command: $output" ;;
esac
run_auto --backend=auto -r "$rootfs" -- env -i /usr/bin/env docker
require_um "env -i /usr/bin/env docker"
run_auto --backend=auto -r "$rootfs" -- env -u PATH sudo -u root docker
require_um "env -u PATH sudo -u root docker"

# --- ordinary commands stay on the fast path ------------------------------
#
# The whole point: PRoot is the default and stays it.
run_auto --backend=auto -r "$rootfs" -- true
require_default "true"
run_auto --backend=auto -r "$rootfs" -- sh
require_default "sh"
case "$output" in
*"selected the default backend"*) ;;
*) fail "the default selection is not reported: $output" ;;
esac

# A shell string is one command, and it is the shell: auto does not parse the
# guest's shell code to find a name inside it.
run_auto --backend=auto -r "$rootfs" -- sh -c 'docker run hello'
require_default "sh -c 'docker run hello'"

# --- the invariant: no prerequisites, no UML ------------------------------
#
# Even for a command that needs a kernel, auto must not start a backend the
# caller never configured.  It says so instead of failing later.
rm -f "$argv_file"
output=$("$neoproot" --backend=auto -r "$rootfs" -- docker 2>&1 || true)
case "$output" in
*"would use the um backend for 'docker'"*) ;;
*) fail "no warning for an unconfigured docker run: $output" ;;
esac
case "$output" in
*"no kernel/stub/rootfs is configured"*) ;;
*) fail "the warning does not say what is missing: $output" ;;
esac
[ ! -f "$argv_file" ] || fail "UML ran without a configured kernel"

# An empty NEOPROOT_UM_KERNEL is not configuration, and the command-sensitive
# decision must not change that.
rm -f "$argv_file"
output=$(NEOPROOT_UM_KERNEL= NEOPROOT_UM_STUB="$kernel" \
	"$neoproot" --backend=auto -r "$rootfs" -- docker 2>&1 || true)
case "$output" in
*"no kernel/stub/rootfs is configured"*) ;;
*) fail "an empty NEOPROOT_UM_KERNEL counted as configuration: $output" ;;
esac
[ ! -f "$argv_file" ] || fail "UML ran with an empty NEOPROOT_UM_KERNEL"

# --- the list is configurable --------------------------------------------
#
# none: never choose a backend by command, and never warn about it either.
run_auto --backend=auto --auto-um-commands=none -r "$rootfs" -- docker
require_default "--auto-um-commands=none docker"
case "$output" in
*"would use the um backend"*) fail "none still warned about docker" ;;
esac

# A list replaces the default set: the named command selects UML, and the
# names that used to are no longer special.
run_auto --backend=auto --auto-um-commands=mycmd -r "$rootfs" -- mycmd
require_um "--auto-um-commands=mycmd mycmd"
run_auto --backend=auto --auto-um-commands=mycmd -r "$rootfs" -- docker
require_default "--auto-um-commands=mycmd docker"

# An empty value is the default set.
run_auto --backend=auto --auto-um-commands= -r "$rootfs" -- docker
require_um "--auto-um-commands= docker"

# The environment variable is the same list, and the option wins over it.
rm -f "$argv_file"
output=$(um_environment env NEOPROOT_UM_AUTO_COMMANDS=envcmd \
	"$neoproot" --backend=auto -r "$rootfs" -- envcmd 2>&1 || true)
[ -f "$argv_file" ] || fail "NEOPROOT_UM_AUTO_COMMANDS was ignored"
rm -f "$argv_file"
output=$(um_environment env NEOPROOT_UM_AUTO_COMMANDS=envcmd \
	"$neoproot" --backend=auto --auto-um-commands=none -r "$rootfs" -- \
	envcmd 2>&1 || true)
[ ! -f "$argv_file" ] || fail "--auto-um-commands did not win over the environment"

# --- the option belongs to neoproot, not to a backend --------------------
#
# It is consumed by the dispatcher; a backend that saw it would reject it as an
# unknown option, and the PRoot path proves that by not complaining.
output=$("$neoproot" --backend=auto --auto-um-commands=none -r "$rootfs" -- true 2>&1 || true)
case "$output" in
*"unknown option"*) fail "the option leaked into the forwarded vector: $output" ;;
esac

# --- only --backend=auto is affected --------------------------------------
#
# --backend=um still runs UML for anything, and the default backend is still
# the default whatever the command is.
run_auto --backend=um -r "$rootfs" -- true
[ "$reached" = yes ] || fail "--backend=um did not run UML for true"
case "$output" in
*"--backend=auto"*) fail "--backend=um printed an auto selection notice" ;;
esac
rm -f "$argv_file"
output=$("$neoproot" -r "$rootfs" -- docker 2>&1 || true)
[ ! -f "$argv_file" ] || fail "the default backend started UML for docker"

echo "auto backend command tests passed"
