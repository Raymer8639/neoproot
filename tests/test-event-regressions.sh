#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EVENT_SOURCE="$SCRIPT_DIR/../src/tracee/event.c"
SECCOMP_SOURCE="$SCRIPT_DIR/../src/tracee/seccomp.c"
TRACEE_SOURCE="$SCRIPT_DIR/../src/tracee/tracee.c"

# SIGSYS extensions use return 1 for "handled, return zero" and return 2
# when they already populated the result register.
if ! awk '
    /if \(status >= 1\)/ { in_block = 1 }
    in_block && /if \(status == 1\)/ { saw_status_one = 1 }
    in_block && /set_result_after_seccomp\(tracee, 0\)/ { saw_zero = 1 }
    in_block && /return 0;/ { exit(saw_status_one && saw_zero ? 0 : 1) }
    END { if (!saw_status_one || !saw_zero) exit 1 }
' "$SECCOMP_SOURCE"; then
    echo "SIGSYS handled-without-result must return zero" >&2
    exit 1
fi

# remove_tracee() is the talloc destructor and owns the LIST_REMOVE.  Removing
# the node in free_terminated_tracees() first makes the destructor unlink it a
# second time when a process-heavy workload (such as i3) exits children.
if ! awk '
    /void free_terminated_tracees/ { in_free = 1 }
    in_free && /LIST_REMOVE\(t, link\)/ { found = 1 }
    in_free && /^}/ { exit(found ? 1 : 0) }
    END { if (found) exit 1 }
' "$TRACEE_SOURCE"; then
    echo "terminated tracees must be unlinked by their destructor only" >&2
    exit 1
fi

# PTRACE options are process state, so this guard must survive event calls.
if ! awk '
    /case SIGTRAP:/ { in_case = 1 }
    in_case && /static bool deliver_sigtrap = false;/ { found = 1 }
    in_case && /^            case SIGTRAP \| 0x80:/ { exit(found ? 0 : 1) }
    END { if (!found) exit 1 }
' "$EVENT_SOURCE"; then
    echo "SIGTRAP option guard must persist across events" >&2
    exit 1
fi

echo "event state regression source checks passed"
