#!/bin/sh
#
# Where neoproot looks for the UML runtime.
#
# neoproot does not contain a kernel; it execs one, and --net runs umnet and
# passt.  install.sh puts all four in <prefix>/libexec/neoproot/um and neoproot
# finds them from its own path, so the user exports nothing.  That discovery is
# what this test pins down: it runs the binary with each layout and reads the
# NEOPROOT_UM_* it would have set, through --help's environment report.
#
# No kernel is booted.  What is checked is the decision, not the boot.
#
# Exit: 0 passed, 1 failed, 125 nothing could be attempted.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$repo_root/src/neoproot
if [ ! -x "$binary" ]; then
	echo "skip: $binary is not built" >&2
	exit 125
fi

# The binary refuses to start under a tracer, and so does every layout below.
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: neoproot must run untraced" >&2
	exit 125
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/nprd.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }

# A fake runtime: four files, and a binary that will never exec them.
make_runtime() {
	mkdir -p "$1"
	for name in linux-bionic stub_exe umnet passt-bionic; do
		printf 'not a real %s\n' "$name" >"$1/$name"
	done
}

# What the binary resolved.  --help is the one path that prints the environment
# it would use without starting anything.
resolved() {
	# $1 binary, rest environment
	_binary=$1
	shift
	env -i "$@" "$_binary" --backend=um --help 2>&1 || true
}

layout_prefix() {
	# <prefix>/bin/neoproot + <prefix>/libexec/neoproot/um
	mkdir -p "$work/p1/bin" "$work/p1/libexec/neoproot"
	cp "$binary" "$work/p1/bin/neoproot"
	make_runtime "$work/p1/libexec/neoproot/um"
	out=$(resolved "$work/p1/bin/neoproot" PATH=/usr/bin:/bin)
	echo "$out" | grep -F "$work/p1/libexec/neoproot/um/linux-bionic" >/dev/null ||
		fail "prefix layout not found: $out"
}

layout_home() {
	# $NEOPROOT_HOME/libexec/neoproot/um, binary somewhere unrelated
	mkdir -p "$work/p2/bin" "$work/home2/libexec/neoproot"
	cp "$binary" "$work/p2/bin/neoproot"
	make_runtime "$work/home2/libexec/neoproot/um"
	out=$(resolved "$work/p2/bin/neoproot" PATH=/usr/bin:/bin \
		NEOPROOT_HOME="$work/home2")
	echo "$out" | grep -F "$work/home2/libexec/neoproot/um/linux-bionic" >/dev/null ||
		fail "NEOPROOT_HOME layout not found: $out"
}

layout_beside() {
	# everything in one directory
	mkdir -p "$work/p3"
	cp "$binary" "$work/p3/neoproot"
	make_runtime "$work/p3"
	out=$(resolved "$work/p3/neoproot" PATH=/usr/bin:/bin)
	echo "$out" | grep -F "$work/p3/linux-bionic" >/dev/null ||
		fail "side-by-side layout not found: $out"
}

layout_explicit_wins() {
	# an explicit variable is never overwritten
	mkdir -p "$work/p4/bin" "$work/p4/libexec/neoproot"
	cp "$binary" "$work/p4/bin/neoproot"
	make_runtime "$work/p4/libexec/neoproot/um"
	out=$(resolved "$work/p4/bin/neoproot" PATH=/usr/bin:/bin \
		NEOPROOT_UM_KERNEL=/somewhere/else/kernel)
	echo "$out" | grep -F "/somewhere/else/kernel" >/dev/null ||
		fail "explicit NEOPROOT_UM_KERNEL was overwritten: $out"
}

layout_absent() {
	# nothing to find: no variable invented, and no crash
	mkdir -p "$work/p5/bin"
	cp "$binary" "$work/p5/bin/neoproot"
	out=$(resolved "$work/p5/bin/neoproot" PATH=/usr/bin:/bin)
	echo "$out" | grep -F "$work/p5" >/dev/null &&
		fail "invented a runtime that is not there: $out"
	:
}

layout_prefix
layout_home
layout_beside
layout_explicit_wins
layout_absent
echo "UML runtime discovery tests passed"
