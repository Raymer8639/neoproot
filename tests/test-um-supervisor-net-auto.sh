#!/bin/sh
# Execute the generated network wrapper with stateful mocks, without UML/root.
# A successful DHCP exchange with a missing hook must not skip static setup.
set -eu
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/neoproot-um-net-auto.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
mkdir "$temporary_directory/bin"
export NET_TEST_DIR="$temporary_directory"
cat >"$temporary_directory/bin/udhcpc" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$NET_TEST_DIR/dhcp-log"
case "$NET_TEST_MODE" in
    ready|ready-error) touch "$NET_TEST_DIR/address" "$NET_TEST_DIR/route" ;;
    address-only) touch "$NET_TEST_DIR/address" ;;
    route-only) touch "$NET_TEST_DIR/route" ;;
esac
case "$NET_TEST_MODE" in
    dhcp-error|ready-error) exit 1 ;;
esac
exit 0
MOCK
cat >"$temporary_directory/bin/ip" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$NET_TEST_DIR/ip-log"
case "$*" in
    'link set vec0 up') exit 0 ;;
    '-4 addr show dev vec0 scope global')
        if [ -f "$NET_TEST_DIR/address" ]; then
            echo '    inet 10.0.2.15/24 brd 10.0.2.255 scope global vec0'
        fi
        exit 0 ;;
    '-4 route show default dev vec0')
        if [ -f "$NET_TEST_DIR/route" ]; then
            echo 'default via 10.0.2.2 dev vec0'
        fi
        exit 0 ;;
    'addr add '*| 'route replace default via '*| 'route add default via '*)
        [ "$NET_TEST_MODE" != fallback-error ] || exit 1
        case "$1" in
            addr)
                # Model EEXIST from a partially successful DHCP hook.
                [ ! -f "$NET_TEST_DIR/address" ] || exit 2
                touch "$NET_TEST_DIR/address" ;;
            route) touch "$NET_TEST_DIR/route" ;;
        esac
        exit 0 ;;
esac
echo "unexpected ip invocation: $*" >&2
exit 99
MOCK
chmod 755 "$temporary_directory/bin/ip" "$temporary_directory/bin/udhcpc"
# Exercise only the real one-shot wrapper generator (hostfs and ext4).
# The C fixture rejects session-loop generation; do not link um_session.c or
# depend on its generated um_session_loop.h. Dead startup paths are discarded.
if ! command -v "${CC:-cc}" >/dev/null 2>&1; then
    echo 'skip: C compiler is not available' >&2
    exit 125
fi
"${CC:-cc}" -D_GNU_SOURCE -std=c11 -Wall -Wextra -Werror -O2 \
    -ffunction-sections -fdata-sections -I"$script_directory/../src" \
    "$script_directory/test-um-supervisor-net-auto.c" \
    -Wl,--gc-sections -lm -o "$temporary_directory/generator"
"$temporary_directory/generator" "$temporary_directory/wrapper" hostfs
"$temporary_directory/generator" "$temporary_directory/wrapper-ext4" ext4
sh -n "$temporary_directory/wrapper-ext4"
# Extract generated code, never a second hand-written copy of the algorithm.
# Match the old implementation too, so the no-hook case demonstrates the bug.
sed -n '/^um_net_.*() {$/,/^um_net_auto$/p' \
    "$temporary_directory/wrapper" >"$temporary_directory/network.sh"
[ -s "$temporary_directory/network.sh" ] || exit 1
sh -n "$temporary_directory/wrapper"
sed -n '/^um_net_.*() {$/,/^um_net_auto$/p' \
    "$temporary_directory/wrapper-ext4" >"$temporary_directory/network-ext4.sh"
cmp "$temporary_directory/network.sh" "$temporary_directory/network-ext4.sh"
cat >"$temporary_directory/run.sh" <<'RUN'
#!/bin/sh
# The managed container may hide /proc/net/dev. Mock only its existence and
# vec0 presence; address/route predicates use real grep over stateful ip output.
[() {
    if test "$#" -eq 3 && test "$1" = -e && test "$2" = /proc/net/dev; then
        return 0
    fi
    command [ "$@"
}
grep() {
    case "$*" in
        *'/proc/net/dev') [ "$NET_TEST_MODE" != no-vec0 ] ;;
        *) command grep "$@" ;;
    esac
}
. "$NET_TEST_DIR/network.sh"
printf '%s\n' guest-command-ran
RUN
fail() {
    echo "FAIL: $NET_TEST_MODE: $*" >&2
    cat "$temporary_directory/ip-log" "$temporary_directory/output" >&2
    exit 1
}
for NET_TEST_MODE in no-hook address-only route-only ready ready-error dhcp-error fallback-error no-vec0; do
    export NET_TEST_MODE
    # All removed paths are fixed children of this test's mktemp directory.
    rm -f "$temporary_directory/address" "$temporary_directory/route"
    : >"$temporary_directory/ip-log"
    : >"$temporary_directory/dhcp-log"
    PATH="$temporary_directory/bin:/usr/bin:/bin" sh "$temporary_directory/run.sh" \
        >"$temporary_directory/output" 2>&1 || fail 'network setup aborted guest'
    grep -q '^guest-command-ran$' "$temporary_directory/output" || fail 'guest not reached'
    case "$NET_TEST_MODE" in
        ready|ready-error|no-vec0)
            if grep -Eq '^addr add|^route .*default via' "$temporary_directory/ip-log"; then
                fail 'static configuration unexpectedly replaced working DHCP/no interface'
            fi ;;
        *)
            grep -q '^addr add 10.44.0.9/24 dev vec0$' "$temporary_directory/ip-log" ||
                fail 'missing static address after incomplete DHCP'
            grep -q '^route replace default via 10.44.0.1 dev vec0$' "$temporary_directory/ip-log" ||
                fail 'missing idempotent default route repair' ;;
    esac
    case "$NET_TEST_MODE" in
        fallback-error)
            grep -q 'no global IPv4 address or default route after configuration' \
                "$temporary_directory/output" || fail 'no warning after failed fallback' ;;
        no-vec0)
            [ ! -s "$temporary_directory/dhcp-log" ] || fail 'DHCP ran without vec0'
            grep -q 'guest has no vec0' "$temporary_directory/output" || fail 'no missing-interface warning' ;;
        *)
            [ -f "$temporary_directory/address" ] && [ -f "$temporary_directory/route" ] ||
                fail 'network state remains incomplete'
            if grep -q 'after configuration' "$temporary_directory/output"; then
                fail 'false failure warning after successful configuration'
            fi ;;
    esac
    echo "PASS: --net-auto $NET_TEST_MODE"
done
