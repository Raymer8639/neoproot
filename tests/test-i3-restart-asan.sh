#!/bin/sh

# This diagnostic integration test needs the user's real PRoot-Distro rootfs,
# X display, and an ASAN-instrumented neoproot.  It remains skipped elsewhere.
if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi
set -euo pipefail

if [[ -z "${PROOT_ASAN:-}" || ! -x "$PROOT_ASAN" ||
      -z "${NEOPROOT_START_SCRIPT:-}" || ! -r "$NEOPROOT_START_SCRIPT" ||
      -z "${DISPLAY:-}" ]]; then
    echo "SKIP: require PROOT_ASAN, NEOPROOT_START_SCRIPT, and DISPLAY"
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
trap 'rm -f "$LOG"' EXIT INT TERM

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
    cat "$LOG" >&2
    exit 1
fi

echo "i3 restart ASAN regression passed"
