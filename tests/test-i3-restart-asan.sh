#!/bin/sh

# This diagnostic integration test needs the user's real PRoot-Distro rootfs,
# X display, and an ASAN-instrumented neoproot.  It remains skipped elsewhere.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
set -euo pipefail

LOG=
report_error() {
    local status=$?
    printf 'i3 restart test failed at line %s (status %s): %s\n' \
        "$1" "$status" "$2" >&2
    if [[ -n "$LOG" && -f "$LOG" ]]; then
        cat "$LOG" >&2
    fi
    exit "$status"
}
trap 'report_error "$LINENO" "$BASH_COMMAND"' ERR

if [[ -z "${PROOT_ASAN:-}" || ! -x "$PROOT_ASAN" ||
      -z "${NEOPROOT_START_SCRIPT:-}" || ! -r "$NEOPROOT_START_SCRIPT" ||
      -z "${DISPLAY:-}" ]]; then
    echo "SKIP: require PROOT_ASAN, NEOPROOT_START_SCRIPT, and DISPLAY"
    exit 125
fi

if grep -q '^TracerPid:[[:space:]]*[1-9]' /proc/self/status 2>/dev/null; then
    echo "SKIP: i3 restart test must run from the Termux host, not a nested PRoot"
    exit 125
fi

# Load the environment and argument array without executing the launcher's
# final exec branch, then replace its binary with the ASAN build.  The
# launcher sets TMPDIR for the guest, so preserve the host's writable value.
HOST_TMPDIR=${TMPDIR:-}
source <(sed '/^if \[ \$# -eq 0 \]; then/,$d' "$NEOPROOT_START_SCRIPT")
if [[ -n "$HOST_TMPDIR" ]]; then
    TMPDIR="$HOST_TMPDIR"
fi
U="$PROOT_ASAN"
LOG=$(mktemp)
PREFLIGHT_LOG=$(mktemp)
trap 'rm -f "$LOG" "$PREFLIGHT_LOG"' EXIT INT TERM

if timeout -k 3 10 "$U" --verbose=1 "${ARGS[@]}" /usr/bin/zsh -lc \
    'printf "neoproot guest preflight\n"' >"$PREFLIGHT_LOG" 2>&1; then
    preflight_status=0
else
    preflight_status=$?
fi

if [ "$preflight_status" -ne 0 ] || \
   ! grep -qx 'neoproot guest preflight' "$PREFLIGHT_LOG"; then
    printf 'i3 restart guest preflight exited with status %s\n' \
        "$preflight_status" >&2
    cat "$PREFLIGHT_LOG" >&2
    exit 1
fi

guest_cmd='for round in 1 2; do
    echo "i3 ASAN round $round"
    setsid /usr/bin/i3 & i3pid=$!
    sleep 2
    kill -INT -- -"$i3pid"
    for attempt in 1 2 3 4 5; do
        kill -0 "$i3pid" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$i3pid" 2>/dev/null; then
        echo "i3 did not exit after SIGINT" >&2
        exit 1
    fi
    if wait "$i3pid"; then rc=0; else rc=$?; fi
    case "$rc" in 0|130) ;; *) exit "$rc";; esac
done'

if ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:handle_segv=2}" \
    timeout -k 3 25 "$U" "${ARGS[@]}" /usr/bin/zsh -lc "$guest_cmd" \
        >"$LOG" 2>&1; then
    status=0
else
    status=$?
fi

if grep -q 'ERROR: AddressSanitizer' "$LOG" || [ "$status" -ne 0 ]; then
    printf 'i3 restart command exited with status %s\n' "$status" >&2
    if [ -s "$LOG" ]; then
        cat "$LOG" >&2
    else
        echo 'i3 restart command produced no output' >&2
    fi
    exit 1
fi

echo "i3 restart ASAN regression passed"
