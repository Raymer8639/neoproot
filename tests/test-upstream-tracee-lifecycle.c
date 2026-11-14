/* Deterministic kernel-boundary tests of the actual tracer implementation. */
#include <stdarg.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

long tracee_test_ptrace(enum __ptrace_request request, ...);
static int test_waitid(idtype_t type, id_t pid, siginfo_t *info, int options);
static FILE *test_fopen(const char *path, const char *mode);
#define ptrace tracee_test_ptrace
#define waitid test_waitid
#define fopen test_fopen
#include "../src/tracee/tracee.c"
#undef ptrace
#undef waitid
#undef fopen

static int context_destroyed;
static int count_context_free(int *marker) { (void)marker; context_destroyed++; return 0; }
static unsigned long event_pid;
static int event_error, wait_error, wait_calls, restarts, inherited;
static int register_error, word_error;
struct proc_ids { pid_t pid, tgid, ppid, tracer; };
static struct proc_ids proc[8];
static size_t proc_count;

long tracee_test_ptrace(enum __ptrace_request request, ...)
{
    va_list ap;
    va_start(ap, request);
    (void)va_arg(ap, pid_t);
    (void)va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    if (request == PTRACE_GETEVENTMSG) {
        *(unsigned long *)data = event_pid;
        errno = event_error;
        return event_error ? -1 : 0;
    }
    if (request == PTRACE_GETREGSET) {
        errno = register_error;
        return register_error ? -1 : 0;
    }
    assert(request == PTRACE_SETREGSET);
    return 0;
}

static int test_waitid(idtype_t type, id_t pid, siginfo_t *info, int options)
{
    assert(type == P_PID && pid > 0);
    assert(options == (WEXITED | WSTOPPED | WNOHANG | WNOWAIT | __WALL));
    memset(info, 0, sizeof(*info));
    wait_calls++;
    errno = wait_error;
    return wait_error ? -1 : 0;
}

static FILE *test_fopen(const char *path, const char *mode)
{
    int pid;
    char text[160];
    assert(strcmp(mode, "r") == 0);
    assert(sscanf(path, "/proc/%d/status", &pid) == 1);
    for (size_t i = 0; i < proc_count; i++) {
        if (proc[i].pid != pid) continue;
        int size = snprintf(text, sizeof(text), "Tgid:\t%d\nPPid:\t%d\nTracerPid:\t%d\n",
                            proc[i].tgid, proc[i].ppid, proc[i].tracer);
        FILE *file = tmpfile();
        assert(file != NULL && fwrite(text, 1, size, file) == (size_t)size);
        rewind(file);
        return file;
    }
    errno = ENOENT;
    return NULL;
}

void note(const Tracee *t, Severity s, Origin o, const char *fmt, ...)
{ (void)t; (void)s; (void)o; (void)fmt; }
void clear_proc_fd_paths(pid_t pid) { (void)pid; }
void inherit_proc_fd_paths(pid_t a, pid_t b) { (void)a; (void)b; inherited++; }
void remove_binding_from_all_lists(const Tracee *t, Binding *b) { (void)t; (void)b; }
Binding *copy_binding(const Tracee *t, const TALLOC_CTX *ctx, const Binding *b, const char *p)
{ (void)t; (void)ctx; (void)b; (void)p; abort(); }
void inherit_extensions(Tracee *child, Tracee *parent, word_t flags)
{ (void)child; (void)parent; (void)flags; }
void attach_to_ptracer(Tracee *child, Tracee *parent) { (void)child; (void)parent; abort(); }
void detach_from_ptracer(Tracee *t) { (void)t; }
bool handle_ptracee_event(Tracee *t, int status) { (void)t; (void)status; abort(); }
int handle_tracee_event(Tracee *t, int status) { (void)t; (void)status; abort(); }
bool restart_tracee(Tracee *t, int signal)
{ assert(signal == 0 && !t->running); restarts++; t->running = true; t->restart_how = 0; return true; }
word_t peek_word(const Tracee *t, word_t addr)
{ (void)t; errno = word_error; return word_error ? 0 : *(word_t *)addr; }

static Tracee *configured(pid_t pid)
{
    Tracee *t = get_tracee(NULL, pid, true);
    assert(t);
    t->exe = talloc_strdup(t, "/guest");
    t->fs->cwd = talloc_strdup(t->fs, "/");
    return t;
}

static void reset(void)
{
    Tracee *t;
    while ((t = LIST_FIRST(&tracees)) != NULL) {
        t->killall_on_exit = false;
        TALLOC_FREE(t);
    }
    event_pid = event_error = wait_error = wait_calls = restarts = inherited = 0;
    register_error = word_error = 0;
    proc_count = 0;
    atomic_store(&has_terminated_tracees, false);
}

static void test_stack(void)
{
    Tracee t = {0};
    word_t args[11] = {0};
    poke_reg(&t, STACK_POINTER, 0x1000);
    set_sysnum(&t, PR_clone);
    assert(new_child_stack(&t) == 0x1000);
    poke_reg(&t, SYSARG_2, 0x2000);
    assert(new_child_stack(&t) == 0x2000);
    set_sysnum(&t, PR_clone3);
    poke_reg(&t, SYSARG_1, (word_t)args);
    args[5] = 0x3000; args[6] = 0x4000;
    assert(new_child_stack(&t) == 0x7000);
    word_error = EFAULT;
    assert(new_child_stack(&t) == 0x1000);
    word_error = 0;
}

static void test_lost_pid(void)
{
    Tracee *p = configured(100);
    set_sysnum(p, PR_clone);
    poke_reg(p, SYSARG_1, SIGCHLD);
    poke_reg(p, STACK_POINTER, 0x1000);
    assert(new_child(p, 0) == 0 && p->pending_child);
    assert(p->pending_clone_flags == SIGCHLD && p->pending_child_sp == 0x1000);
    /* An unrelated syscall result must never become a tracked PID. */
    set_sysnum(p, PR_read);
    save_current_regs(p, ORIGINAL);
    poke_reg(p, SYSARG_RESULT, 200);
    resolve_pending_child(p);
    assert(p->pending_child && !get_tracee(p, 200, false));
    set_sysnum(p, PR_clone);
    save_current_regs(p, ORIGINAL);
    proc[proc_count++] = (struct proc_ids){200, 200, 100, getpid() + 1};
    resolve_pending_child(p);
    assert(!p->pending_child && !get_tracee(p, 200, false));
    p->pending_child = true;
    proc[0].tracer = getpid();
    resolve_pending_child(p);
    Tracee *c = get_tracee(p, 200, false);
    assert(c && c->parent == p && c->exe && inherited == 1);
    reset();
}

static void test_vfork(void)
{
    Tracee *p = configured(100), *c = get_tracee(NULL, 200, true);
    c->sigstop = SIGSTOP_PENDING;
    poke_reg(c, STACK_POINTER, 0x9000);
    proc[proc_count++] = (struct proc_ids){100, 100, 50, getpid()};
    proc[proc_count++] = (struct proc_ids){200, 200, 100, getpid()};
    set_sysnum(p, PR_clone);
    poke_reg(p, SYSARG_1, CLONE_VFORK | CLONE_VM | SIGCHLD);
    poke_reg(p, STACK_POINTER, 0x8000);
    assert(new_child(p, 0) == 0 && p->pending_child && !c->exe);
    /* Matching process ancestry alone does not select a concurrent fork. */
    poke_reg(c, STACK_POINTER, 0x8000);
    adopt_held_children();
    assert(!p->pending_child && c->exe && c->parent == p && restarts == 1);
    reset();
}

static void test_child_relationships(void)
{
    Tracee *p = configured(100), *c = get_tracee(NULL, 200, true);
    proc[proc_count++] = (struct proc_ids){100, 100, 50, getpid()};
    proc[proc_count++] = (struct proc_ids){200, 100, 50, getpid()};
    p->pending_child_sp = 0x8000;
    poke_reg(c, STACK_POINTER, 0x8000);
    p->pending_clone_flags = CLONE_THREAD;
    assert(is_pending_child_of(p, c));
    proc[1].tgid = 200;
    assert(!is_pending_child_of(p, c));
    p->pending_clone_flags = CLONE_PARENT;
    assert(is_pending_child_of(p, c));
    proc[1].ppid = 100;
    assert(!is_pending_child_of(p, c));
    p->pending_clone_flags = 0;
    assert(is_pending_child_of(p, c));
    register_error = ESRCH;
    assert(!is_pending_child_of(p, c));
    reset();
}

static void test_death_and_reuse(void)
{
    Tracee *p = configured(100);
    p->clone_stripped_newns = p->clone_stripped_newnet = true;
    wait_error = ECHILD;
    assert(attach_child(p, SIGCHLD, 200) == 0);
    assert(!get_tracee(p, 200, false) && wait_calls == 1);
    assert(!p->clone_stripped_newns && !p->clone_stripped_newnet);
    wait_error = EINTR;
    assert(is_still_traced(200)); /* Other waitid errors don't prove death. */
    wait_error = 0;
    Tracee *c = get_tracee(NULL, 200, true);
    c->sigstop = SIGSTOP_PENDING;
    c->running = true; /* EXIT already resumed this held child. */
    assert(attach_child(p, SIGCHLD, 200) == 0 && restarts == 0);
    Tracee *old = c;
    assert(attach_child(p, SIGCHLD, 200) == 0);
    c = get_tracee(NULL, 200, false);
    assert(c != old && old->terminated && c->parent == p && !c->terminated);
    reset();
}

static void test_exec_handoff(void)
{
    Tracee *p = configured(50), *leader = configured(100), *thread = configured(101);
    Tracee *child = configured(200);
    leader->parent = p; leader->vpid = 1; leader->killall_on_exit = true;
    thread->parent = leader; thread->status = 1; thread->sysexit_pending = true;
    thread->seccomp_notify = true;
    child->parent = leader;
    set_sysnum(thread, PR_execve);
    save_current_regs(thread, ORIGINAL);
    event_pid = 0;
    assert(get_execve_tracee(leader) == leader);
    event_pid = 999;
    assert(get_execve_tracee(leader) == leader);
    int *marker = talloc_zero(thread->ctx, int);
    assert(marker); talloc_set_destructor(marker, count_context_free);
    int destroyed_before = context_destroyed;
    event_pid = 101;
    assert(get_execve_tracee(leader) == thread);
    assert(context_destroyed == destroyed_before);
    assert(thread->pid == 100 && thread->vpid == 1 && thread->parent == p);
    assert(child->parent == thread && thread->killall_on_exit && !thread->terminated);
    assert(thread->status == 1 && thread->sysexit_pending && thread->seccomp_notify);
    assert(get_sysnum(thread, ORIGINAL) == PR_execve && !get_tracee(NULL, 101, false));
    assert(!atomic_load(&has_terminated_tracees));
    reset();
}

int main(void)
{
    assert(detranslate_sysnum(ABI_DEFAULT, PR_fork) == SYSCALL_AVOIDER);
    test_stack(); test_lost_pid(); test_vfork(); test_child_relationships();
    test_death_and_reuse(); test_exec_handoff();
    puts("upstream tracee lifecycle: PASS");
    return 0;
}
