/* Exercise the existing event flow with deterministic ptrace responses. */
#include <stdarg.h>
#include <sys/ptrace.h>
long tracee_test_ptrace(enum __ptrace_request request, ...);
#define ptrace tracee_test_ptrace
#include "../src/tracee/event.c"
#undef ptrace

static unsigned long message;
static int expected_flags, fetches, translations, resolved, adopted;
static int fetch_error, message_error;

long tracee_test_ptrace(enum __ptrace_request request, ...)
{
    va_list ap;
    va_start(ap, request);
    (void)va_arg(ap, pid_t);
    (void)va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (request == PTRACE_GETEVENTMSG) {
        *(unsigned long *)data = message;
        errno = message_error;
        return message_error ? -1 : 0;
    }
    if (request == PTRACE_GETREGSET) {
        fetches++;
        errno = fetch_error;
        return fetch_error ? -1 : 0;
    }
    assert(request == PTRACE_SETREGSET);
    return 0;
}

void note(const Tracee *t, Severity s, Origin o, const char *fmt, ...)
{ (void)t; (void)s; (void)o; (void)fmt; }
int filtered_sysnum_flags(const Tracee *t, Sysnum sn)
{ (void)t; assert(sn == PR_readlinkat); return expected_flags; }
void translate_syscall(Tracee *t) { translations++; t->status = !t->status; }
void resolve_pending_child(Tracee *t) { resolved++; t->pending_child = false; }
void adopt_held_children(void) { adopted++; }
int new_child(Tracee *t, word_t flags) { (void)t; (void)flags; abort(); }
void terminate_tracee(Tracee *t) { (void)t; abort(); }
int handle_seccomp_event(Tracee *t) { (void)t; abort(); }
int translate_path(Tracee *t, char path[PATH_MAX], int fd, const char *name, bool follow)
{ (void)t; (void)path; (void)fd; (void)name; (void)follow; abort(); }
int open_elf(const char *path, ElfHeader *header) { (void)path; (void)header; abort(); }

static int stop(int event) { return ((SIGTRAP | event << 8) << 8) | 0x7f; }
static Tracee fresh(void)
{
    Tracee t = { .pid = 100, .seccomp = ENABLED, .exe = "/guest" };
    set_sysnum(&t, PR_readlinkat);
    atomic_store(&seccomp_detected, true);
    atomic_store(&seccomp_after_ptrace_enter, false);
    atomic_store(&seccomp_after_ptrace_enter_checked, true);
    atomic_store(&eventmsg_state, EVENTMSG_UNKNOWN);
    message = expected_flags = fetches = translations = resolved = adopted = 0;
    fetch_error = message_error = 0;
    return t;
}

int main(void)
{
    Tracee t = fresh();
    /* Unknown zero-only entries do not establish reliability. */
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(atomic_load(&eventmsg_state) == EVENTMSG_UNKNOWN && fetches == 1);
    assert(translations == 1 && t.restart_how == PTRACE_CONT);
    t.status = 0; t.restart_how = 0;
    expected_flags = FILTER_SYSEXIT;
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(atomic_load(&eventmsg_state) == EVENTMSG_LOST && fetches == 2);
    assert(translations == 1 && t.restart_how == PTRACE_SYSCALL);
    /* Recovery must continue to query the lists after loss is detected. */
    expected_flags = 0; t.status = 0; t.restart_how = 0;
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(fetches == 3 && translations == 2 && t.restart_how == PTRACE_CONT);

    t = fresh(); message = expected_flags = FILTER_SYSEXIT;
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(atomic_load(&eventmsg_state) == EVENTMSG_RELIABLE && fetches == 1);
    message = 0; t.status = 0; t.restart_how = 0;
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(fetches == 1 && translations == 1 && t.restart_how == PTRACE_CONT);

    t = fresh(); expected_flags = FILTER_SYSEXIT; fetch_error = ESRCH;
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(atomic_load(&eventmsg_state) == EVENTMSG_UNKNOWN);

    /* Detect the first event in either kernel ordering without changing
     * the original sysexit path or translating an entry twice. */
    t = fresh(); expected_flags = FILTER_SYSEXIT;
    atomic_store(&seccomp_detected, false);
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(atomic_load(&seccomp_detected) && !atomic_load(&seccomp_after_ptrace_enter));
    assert(t.restart_how == PTRACE_SYSCALL && translations == 0);
    t = fresh(); expected_flags = FILTER_SYSEXIT; t.status = 1;
    t.last_restart_how = PTRACE_SYSCALL;
    atomic_store(&seccomp_detected, false);
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(atomic_load(&seccomp_detected) && atomic_load(&seccomp_after_ptrace_enter));
    assert(t.restart_how == PTRACE_SYSCALL && translations == 0);

    /* Keep the existing order: newer kernels already handled sysenter. */
    t = fresh(); expected_flags = FILTER_SYSEXIT; t.status = 1;
    t.last_restart_how = PTRACE_SYSCALL;
    atomic_store(&seccomp_after_ptrace_enter, true);
    assert(handle_tracee_event(&t, stop(PTRACE_EVENT_SECCOMP)) == 0);
    assert(translations == 0 && t.restart_how == PTRACE_SYSCALL);

    t = fresh(); t.status = 1; t.pending_child = true;
    assert(handle_tracee_event(&t, (SIGTRAP | 0x80) << 8 | 0x7f) == 0);
    assert(translations == 1 && resolved == 1 && !t.pending_child);
    t = fresh(); t.exe = NULL;
    assert(handle_tracee_event(&t, SIGSTOP << 8 | 0x7f) == -1);
    assert(t.sigstop == SIGSTOP_PENDING && adopted == 1);
    puts("upstream tracee events: PASS");
    return 0;
}
