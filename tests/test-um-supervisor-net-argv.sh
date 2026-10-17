#!/bin/sh
#
# Regression test: --net must hand umnet the complete UML command line.
#
# With --net the supervisor execs umnet, and umnet re-execs the kernel with the
# argument vector it was given.  A truncated vector therefore loses rootfs
# parameters instead of failing loudly.  In ext4 mode that is destructive rather
# than cosmetic: /um-init keys the whole session off neoproot_protocol and
# neoproot_session, so without them it takes the bare harness fallback path,
# ignores the caller's command and reports success.  A guest asked for `exit 7`
# came back as 0, and the CLI tests did not notice because they only exercise
# option validation.
#
# The same file covers --net-ipv6: IPv6 is a second helper inside umnet, so it
# is one switch and up to three values on umnet's own command line, and the
# kernel vector behind the separator must be unchanged.
#
# A mock umnet records its argv, so the contract is checked without a kernel, a
# rootfs image or passt.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
um_supervisor="$script_directory/../src/neoproot-um"

if [ ! -e "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not available" >&2
	exit 125
fi
if [ ! -x "$um_supervisor" ]; then
	echo "skip: $um_supervisor is not executable" >&2
	exit 125
fi
if awk '$1 == "TracerPid:" { exit ($2 != 0 ? 0 : 1) }' /proc/self/status; then
	echo "skip: UML supervisor test must run untraced" >&2
	exit 125
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-net-argv.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

argv_file="$temporary_directory/umnet-argv"
rootfs="$temporary_directory/rootfs"
image="$temporary_directory/rootfs.ext4"
mkdir "$rootfs"
dd if=/dev/zero of="$image" bs=1 count=2048 2>/dev/null
printf '\123\357' | dd of="$image" bs=1 seek=1080 conv=notrunc 2>/dev/null

# The mock has to be a real executable file: the supervisor resolves umnet
# through access(X_OK) and refuses the run otherwise.
cat >"$temporary_directory/umnet" <<EOF
#!/bin/sh
: >'$argv_file'
for argument do
	printf '%s\n' "\$argument" >>'$argv_file'
done
exit 0
EOF
cat >"$temporary_directory/passt" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$temporary_directory/kernel" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 755 "$temporary_directory/umnet" "$temporary_directory/passt" \
	"$temporary_directory/kernel"

export NEOPROOT_UM_NET="$temporary_directory/umnet"
export NEOPROOT_UM_PASST="$temporary_directory/passt"

fail() {
	echo "FAIL: $1" >&2
	if [ -f "$argv_file" ]; then
		echo "--- umnet argv ---" >&2
		cat "$argv_file" >&2
	fi
	exit 1
}

# Run the supervisor with the given arguments and require that the mock umnet
# was reached.
run_with_net() {
	rm -f "$argv_file"
	TMPDIR="$temporary_directory" "$um_supervisor" \
		--kernel="$temporary_directory/kernel" \
		--stub="$temporary_directory/kernel" "$@" -- /bin/true \
		>/dev/null 2>&1 || true
	if [ ! -s "$argv_file" ]; then
		fail "umnet was not reached for: $*"
	fi
}

# The options umnet expects before `--` have to be there, in order, or umnet
# will not parse the vector at all.
#
# No `--dns` here on purpose.  The supervisor used to pass a literal 1.1.1.1,
# which is a claim about the network rather than about the build: on a network
# that blocks that resolver the guest loses DNS while every other check still
# passes, and nothing in the output says where the address came from.  umnet
# now picks the host's own resolver unless the caller names one.
require_options() {
	expected="--passt
$temporary_directory/passt
--addr
10.0.2.15
--mask
24
--gw
10.0.2.2
--"
	actual=$(head -n 9 "$argv_file")
	[ "$actual" = "$expected" ] || fail "umnet options are malformed"
	[ "$(sed -n '10p' "$argv_file")" = "$temporary_directory/kernel" ] ||
		fail "umnet argv does not start with the kernel path"
}

# --net-dns= has to reach umnet, and be the only thing that puts `--dns` there.
require_dns_option() {
	expected="--passt
$temporary_directory/passt
--addr
10.0.2.15
--mask
24
--gw
10.0.2.2
--dns
$1
--"
	actual=$(head -n 11 "$argv_file")
	[ "$actual" = "$expected" ] || fail "umnet options are malformed with --net-dns"
	[ "$(sed -n '12p' "$argv_file")" = "$temporary_directory/kernel" ] ||
		fail "umnet argv does not start with the kernel path"
}

# The final argument of the real kernel vector.  Its presence proves the copy
# was not cut off at the end, which is exactly how the original bug hid: a
# fixed-size bound truncated the vector and dropped trailing parameters.
require_tail() {
	tail_argument=$(tail -n 1 "$argv_file")
	[ "$tail_argument" = "$1" ] ||
		fail "umnet argv ends with '$tail_argument', expected '$1'"
}

require_argument() {
	grep -q -F -- "$1" "$argv_file" ||
		fail "umnet argv is missing '$1'"
}

require_count() {
	count=$(wc -l <"$argv_file" | tr -d ' ')
	[ "$count" -eq "$1" ] || fail "umnet argv has $count entries, expected $1"
}

# --net-ipv6 is one option to umnet, and only what the caller named follows it:
# the address and gateway stay umnet's defaults instead of being restated here,
# and so does the resolver.
require_ipv6_flag_only() {
	expected="--passt
$temporary_directory/passt
--addr
10.0.2.15
--mask
24
--gw
10.0.2.2
--ipv6
--"
	actual=$(head -n 10 "$argv_file")
	[ "$actual" = "$expected" ] || fail "umnet options are malformed with --net-ipv6"
	[ "$(sed -n '11p' "$argv_file")" = "$temporary_directory/kernel" ] ||
		fail "umnet argv does not start with the kernel path after --net-ipv6"
}

require_ipv6_options() {
	expected="--passt
$temporary_directory/passt
--addr
10.0.2.15
--mask
24
--gw
10.0.2.2
--ipv6
--ipv6-addr
fd00::2/64
--ipv6-gw
fe80::1
--ipv6-dns
2001:db8::53
--"
	actual=$(head -n 16 "$argv_file")
	[ "$actual" = "$expected" ] || fail "umnet IPv6 options are malformed"
	[ "$(sed -n '17p' "$argv_file")" = "$temporary_directory/kernel" ] ||
		fail "umnet argv does not start with the kernel path after IPv6 options"
}

# The options only make sense with a network; saying so is the whole check.
require_ipv6_needs_net() {
	if TMPDIR="$temporary_directory" "$um_supervisor" \
		--kernel="$temporary_directory/kernel" \
		--stub="$temporary_directory/kernel" \
		--rootfs="$rootfs" "$@" -- /bin/true >"$temporary_directory/out" 2>&1; then
		fail "the supervisor accepted $* without --net"
	fi
	grep -q -F -- "--net-ipv6 options require --net" "$temporary_directory/out" ||
		fail "the supervisor did not explain that $* requires --net"
}

# hostfs: 9 options + 10 kernel arguments.
run_with_net --rootfs="$rootfs" --hostfs --net
require_options
require_count 19
require_argument "init="
require_argument "con=null"
require_argument "con0=fd:0,fd:1"
require_argument "rootfstype=hostfs"
require_argument "rootflags=$rootfs"
require_tail "panic=1"

# ext4 read-write: the longest vector, and the mode where dropping the session
# parameters silently discards the guest command.  9 options + 15 arguments.
run_with_net --rootfs="$image" --net
require_options
require_count 24
require_argument "init=/um-init"
require_argument "ubd0="
require_argument "root=/dev/ubda"
require_argument "rootfstype=ext4"
require_argument "hostfs="
require_argument "neoproot_protocol=session-v1"
require_argument "neoproot_session="
require_argument "neoproot_cwd=/"
require_tail "panic=1"

# --net-dns= is the only thing that may add `--dns`: 11 options + 10 arguments.
run_with_net --rootfs="$rootfs" --hostfs --net --net-dns=9.9.9.9
require_dns_option 9.9.9.9
require_count 21
require_tail "panic=1"

# ext4 read-only carries one extra argument (rootflags=noload).
run_with_net --rootfs="$image" --readonly --net
require_options
require_count 25
require_argument "ubd0r="
require_argument "neoproot_protocol=session-v1"
require_argument "neoproot_session="
require_argument "rootflags=noload"
require_tail "panic=1"

# --net-ipv6 alone: one extra option, and the kernel vector is untouched.
run_with_net --rootfs="$rootfs" --hostfs --net --net-ipv6
require_ipv6_flag_only
require_count 20
require_argument "rootfstype=hostfs"
require_tail "panic=1"

# The three values are passed only when named, in umnet's own order.
run_with_net --rootfs="$rootfs" --hostfs --net --net-ipv6 \
	--net-ipv6-addr=fd00::2/64 --net-ipv6-gw=fe80::1 \
	--net-ipv6-dns=2001:db8::53
require_ipv6_options
require_count 26
require_tail "panic=1"

# A named value implies the switch: "--net-ipv6-addr=" on its own still turns
# IPv6 on, which is what umnet does with the same argument.
run_with_net --rootfs="$rootfs" --hostfs --net --net-ipv6-addr=fd00::9/64
require_argument "--ipv6"
require_argument "--ipv6-addr"
require_count 22
require_tail "panic=1"

# --net-ipv6-dns=none is a value like any other: umnet decides what it means.
run_with_net --rootfs="$rootfs" --hostfs --net --net-ipv6-dns=none
require_argument "--ipv6-dns"
require_argument "none"

# ext4 with IPv6: the session parameters still arrive.
run_with_net --rootfs="$image" --net --net-ipv6
require_argument "neoproot_session="
require_argument "--ipv6"
require_count 25
require_tail "panic=1"

# IPv6 without a network is a mistake, not a silent no-op.
require_ipv6_needs_net --net-ipv6
require_ipv6_needs_net --net-ipv6-addr=fd00::2/64
require_ipv6_needs_net --net-ipv6-gw=fe80::1
require_ipv6_needs_net --net-ipv6-dns=none

# --net must not change the non-network path: without it the kernel is exec'd
# directly and umnet is never started.
rm -f "$argv_file"
TMPDIR="$temporary_directory" "$um_supervisor" \
	--kernel="$temporary_directory/kernel" \
	--stub="$temporary_directory/kernel" \
	--rootfs="$image" --timeout=5 -- /bin/true >/dev/null 2>&1 || true
[ ! -f "$argv_file" ] || fail "umnet ran without --net"

echo "UM supervisor --net and --net-ipv6 argv tests passed"
