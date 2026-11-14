/* Actual SIGSYS dispatcher/statx code with an in-process tracee memory model. */
#include <stdarg.h>
#include <sys/ptrace.h>
long tracee_test_ptrace(enum __ptrace_request request, ...);
#define ptrace tracee_test_ptrace
#include "../src/tracee/seccomp.c"
#undef ptrace

static Sysnum wanted_sysnum;
static int translated, statx_events, pushes;
static Tracee *active;

long tracee_test_ptrace(enum __ptrace_request request, ...)
{
    va_list ap;
    va_start(ap, request);
    (void)va_arg(ap, pid_t);
    (void)va_arg(ap, void *);
    (void)va_arg(ap, void *);
    va_end(ap);
    assert(request == PTRACE_GETREGSET || request == PTRACE_SETREGSET);
    if (request == PTRACE_SETREGSET) pushes++;
    return 0;
}
void note(const Tracee *t, Severity s, Origin o, const char *fmt, ...)
{ (void)t; (void)s; (void)o; (void)fmt; }
int read_string(const Tracee *t, char *dst, word_t addr, word_t size)
{ (void)t; size_t n = strlen((char *)addr) + 1; assert(n < size); memcpy(dst, (void *)addr, n); return n; }
int read_data(const Tracee *t, void *dst, word_t addr, word_t size)
{ (void)t; memcpy(dst, (void *)addr, size); return 0; }
int write_data(Tracee *t, word_t addr, const void *src, word_t size)
{ (void)t; memcpy((void *)addr, src, size); return 0; }
word_t peek_word(const Tracee *t, word_t addr) { (void)t; return *(word_t *)addr; }
void poke_word(const Tracee *t, word_t addr, word_t value) { (void)t; *(word_t *)addr = value; }
word_t alloc_mem(Tracee *t, ssize_t size) { (void)t; (void)size; abort(); }
int set_sysarg_data(Tracee *t, const void *data, word_t size, Reg reg)
{ (void)t; (void)data; (void)size; (void)reg; abort(); }
int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX])
{ (void)pid; (void)fd; (void)path; abort(); }
int lower_openat2_to_openat(Tracee *t) { (void)t; abort(); }
int unshare_file_system_namespace(Tracee *t) { (void)t; abort(); }
void apply_emulated_mount(Tracee *t) { (void)t; abort(); }
int apply_emulated_mount_setattr(Tracee *t) { (void)t; abort(); }
void apply_emulated_pivot_root(Tracee *t) { (void)t; abort(); }
void apply_emulated_umount(Tracee *t) { (void)t; abort(); }
Comparison compare_paths(const char *a, const char *b) { (void)a; (void)b; return PATHS_ARE_NOT_COMPARABLE; }

static int observer(Extension *ext, ExtensionEvent event, intptr_t d1, intptr_t d2)
{
    (void)ext; (void)d1; (void)d2;
    if (event == GUEST_PATH || event == STATX_SYSCALL) {
        assert(get_sysnum(active, ORIGINAL) == wanted_sysnum);
        /* Snapshotting must not discard an earlier ARM x0 correction. */
        assert(active->_regs_were_changed);
        if (event == STATX_SYSCALL) statx_events++;
    }
    return 0;
}

int translate_path(Tracee *t, char path[PATH_MAX], int fd, const char *name, bool follow)
{
    (void)fd; (void)follow;
    translated++;
    assert(get_sysnum(t, ORIGINAL) == wanted_sysnum);
    assert(peek_reg(t, ORIGINAL, SYSARG_1) == peek_reg(t, CURRENT, SYSARG_1));
    assert(notify_extensions(t, GUEST_PATH, (intptr_t)name, 0) == 0);
    strcpy(path, name);
    return 0;
}

int main(void)
{
    Tracee t = { .pid = 100 };
    struct statx sx = {0};
    Extensions extensions;
    Extension ext = { .callback = observer };
    LIST_INIT(&extensions); LIST_INSERT_HEAD(&extensions, &ext, link);
    t.extensions = &extensions; active = &t;
    /* This stale chmod snapshot reproduced the permissions corruption. */
    set_sysnum(&t, PR_chmod); save_current_regs(&t, ORIGINAL);
    set_sysnum(&t, PR_statx);
    poke_reg(&t, SYSARG_1, AT_FDCWD);
    poke_reg(&t, SYSARG_2, (word_t)"/dev/null");
    poke_reg(&t, SYSARG_3, 0);
    poke_reg(&t, SYSARG_4, STATX_BASIC_STATS);
    poke_reg(&t, SYSARG_5, (word_t)&sx);
    wanted_sysnum = PR_statx;
    assert(handle_seccomp_event(&t) == 0);
    assert(translated == 1 && statx_events == 1 && pushes == 1);
    assert((long)peek_reg(&t, CURRENT, SYSARG_RESULT) == 0 && S_ISCHR(sx.stx_mode));
    assert(get_sysnum(&t, ORIGINAL) == PR_statx);

    set_sysnum(&t, PR_chmod); save_current_regs(&t, ORIGINAL);
    set_sysnum(&t, PR_statfs);
    poke_reg(&t, SYSARG_1, (word_t)"/nonexistent-upstream-tracee-path");
    wanted_sysnum = PR_statfs;
    assert(handle_seccomp_event(&t) == 0);
    assert(translated == 2 && pushes == 2);
    assert((long)peek_reg(&t, CURRENT, SYSARG_RESULT) == -ENOENT);
    assert(get_sysnum(&t, ORIGINAL) == PR_statfs);
    puts("upstream tracee SIGSYS snapshots: PASS");
    return 0;
}
