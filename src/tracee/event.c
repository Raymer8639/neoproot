#include <sched.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <talloc.h>
#include <inttypes.h>

#include "tracee/tracee.h"
#include "tracee/event.h"
#include "tracee/seccomp.h"
#include "tracee/mem.h"
#include "cli/note.h"
#include "path/path.h"
#include "path/binding.h"
#include "syscall/syscall.h"
#include "syscall/seccomp.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "execve/elf.h"
#include "attribute.h"
#include "compat.h"

static bool seccomp_after_ptrace_enter = false;
static bool seccomp_detected = false;
static bool seccomp_after_ptrace_enter_checked = false;
static int last_exit_status = -1;

// 只在这里加了一个安全的忽略信号函数
static void sig_ign(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    (void)uc;
}

int launch_process(Tracee *tracee, char *const argv[])
{
    char *const default_argv[] = { "-sh", NULL };
    long status;
    pid_t pid;

    mem_prepare_before_first_execve(tracee);

    if (tracee->verbose > 0)
        list_open_fd(tracee);

    pid = fork();
    switch(pid) {
        case -1:
            note(tracee, ERROR, SYSTEM, "fork()");
            return -errno;
        case 0: /* child */
            status = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            if (status < 0) {
                note(tracee, ERROR, SYSTEM, "ptrace(TRACEME)");
                return -errno;
            }

            kill(getpid(), SIGSTOP);

            if (getenv("PROOT_NO_SECCOMP") == NULL)
                (void) enable_syscall_filtering(tracee);

            execvp(tracee->exe, argv[0] != NULL ? argv : default_argv);
            return -errno;
        default: /* parent */
            tracee->pid = pid;
            return 0;
    }
    return -ENOSYS;
}

static void kill_all_tracees2(int signum, siginfo_t *siginfo, void *ucontext)
{
    (void)ucontext;
    note(NULL, WARNING, INTERNAL, "signal %d received from process %d",
         signum, siginfo->si_pid);
    kill_all_tracees();
    if (signum != SIGQUIT)
        _exit(EXIT_FAILURE);
}

static void print_talloc_chunk(const void *ptr, int depth, int max_depth, int is_ref, void *data)
{
    (void)max_depth;
    (void)data;
    const char *name;
    size_t count;
    size_t size;
    name = talloc_get_name(ptr);
    size = talloc_get_size(ptr);
    count = talloc_reference_count(ptr);

    if (depth == 0)
        return;
    while (--depth > 0)
        fprintf(stderr, "\t");
    fprintf(stderr, "%-16s ", name);

    if (is_ref)
        fprintf(stderr, "-> %-8p", ptr);
    else {
        fprintf(stderr, "%-8p  %zd bytes  %zd ref'", ptr, size, count);
        if (name[0] == '$') {
            fprintf(stderr, "\t(\"%s\")", (char *)ptr);
        } else if (name[0] == '@') {
            char **argv = (char **)ptr;
            int i;
            fprintf(stderr, "\t(");
            for (i = 0; argv[i] != NULL; i++)
                fprintf(stderr, "\"%s\", ", argv[i]);
            fprintf(stderr, ")");
        } else if (!strcmp(name, "Tracee")) {
            fprintf(stderr, "\t(pid = %d, parent = %p)",
                    ((Tracee *)ptr)->pid, ((Tracee *)ptr)->parent);
        } else if (!strcmp(name, "Bindings")) {
            Tracee *tracee = TRACEE(ptr);
            if (ptr == tracee->fs->bindings.pending)
                fprintf(stderr, "\t(pending)");
            else if (ptr == tracee->fs->bindings.guest)
                fprintf(stderr, "\t(guest)");
            else if (ptr == tracee->fs->bindings.host)
                fprintf(stderr, "\t(host)");
        } else if (!strcmp(name, "Binding")) {
            Binding *binding = (Binding *)ptr;
            fprintf(stderr, "\t(%s:%s)", binding->host.path, binding->guest.path);
        }
    }
    fprintf(stderr, "\n");
}

static void print_talloc_hierarchy(int signum, siginfo_t *siginfo, void *ucontext)
{
    (void)siginfo;
    (void)ucontext;
    switch (signum) {
        case SIGUSR1:
            talloc_report_depth_cb(NULL, 0, 100, print_talloc_chunk, NULL);
            break;
        case SIGUSR2:
            talloc_report_depth_file(NULL, 0, 100, stderr);
            break;
        default:
            break;
    }
}

static void check_architecture(Tracee *tracee)
{
    struct utsname utsname;
    ElfHeader elf_header;
    char path[PATH_MAX];
    int status;

    if (tracee->exe == NULL)
        return;
    status = translate_path(tracee, path, AT_FDCWD, tracee->exe, false);
    if (status < 0)
        return;
    status = open_elf(path, &elf_header);
    if (status < 0)
        return;
    close(status);

    if (!IS_CLASS64(elf_header) || sizeof(word_t) == sizeof(uint64_t))
        return;

    note(tracee, ERROR, USER,
         "'%s' is a 64-bit AArch64 program, but this version of %s only supports 32-bit ARM programs",
         path, tracee->tool_name);
    status = uname(&utsname);
    if (status < 0)
        return;
    if (strcmp(utsname.machine, "aarch64") != 0 && strcmp(utsname.machine, "arm64") != 0)
        return;
    note(tracee, INFO, USER,
         "Please use the 64-bit ARM64 build of %s to run this program", tracee->tool_name);
}

int event_loop(void)
{
    struct sigaction signal_action;
    long status;

    status = atexit(kill_all_tracees);
    if (status != 0)
        note(NULL, WARNING, INTERNAL, "atexit() failed");

    memset(&signal_action, 0, sizeof(signal_action));
    signal_action.sa_flags = SA_SIGINFO | SA_RESTART;
    status = sigfillset(&signal_action.sa_mask);
    if (status < 0)
        note(NULL, WARNING, SYSTEM, "sigfillset()");

    int signum;
    for (signum = 0; signum < NSIG; signum++) {
        switch (signum) {
            case SIGQUIT: case SIGILL: case SIGABRT: case SIGFPE: case SIGSEGV:
                signal_action.sa_sigaction = kill_all_tracees2;
                (void) sigaction(signum, &signal_action, NULL);
                break;
            case SIGUSR1: case SIGUSR2:
                signal_action.sa_sigaction = print_talloc_hierarchy;
                (void) sigaction(signum, &signal_action, NULL);
                break;
            case SIGCHLD: case SIGCONT: case SIGSTOP: case SIGTSTP: case SIGTTIN: case SIGTTOU:
                continue;
            default:
                if (signum < SIGRTMIN) {
                    signal_action.sa_sigaction = sig_ign;
                    (void) sigaction(signum, &signal_action, NULL);
                }
                break;
        }
    }

    for (;;) {
        int tracee_status;
        Tracee *tracee;
        int signal;
        pid_t pid;

        free_terminated_tracees();
        pid = waitpid(-1, &tracee_status, __WALL);
        if (pid < 0) {
            if (errno != ECHILD) {
                note(NULL, ERROR, SYSTEM, "waitpid()");
                return EXIT_FAILURE;
            }
            break;
        }

        tracee = get_tracee(NULL, pid, true);
        assert(tracee != NULL);
        tracee->running = false;

        if (notify_extensions(tracee, NEW_STATUS, tracee_status, 0) != 0)
            continue;

        if (tracee->as_ptracee.ptracer != NULL) {
            bool keep_stopped = handle_ptracee_event(tracee, tracee_status);
            if (keep_stopped)
                continue;
        }

        signal = handle_tracee_event(tracee, tracee_status);
        (void) restart_tracee(tracee, signal);
    }
    return last_exit_status;
}

int handle_tracee_event(Tracee *tracee, int tracee_status)
{
    long status;
    int signal;
    bool sysexit_necessary;
    bool deliver_sigtrap = false;

    if (!seccomp_after_ptrace_enter_checked) {
        seccomp_after_ptrace_enter = getenv("PROOT_ASSUME_NEW_SECCOMP") != NULL;
        seccomp_after_ptrace_enter_checked = true;
    }

    sysexit_necessary = tracee->sysexit_pending
                        || tracee->chain.syscalls != NULL
                        || tracee->restore_original_regs_after_seccomp_event;

    if (tracee->restart_how == 0) {
        if (tracee->seccomp == ENABLED && !sysexit_necessary)
            tracee->restart_how = PTRACE_CONT;
        else
            tracee->restart_how = PTRACE_SYSCALL;
    }

    signal = 0;
    if (WIFEXITED(tracee_status)) {
        last_exit_status = WEXITSTATUS(tracee_status);
        VERBOSE(tracee, 1,
                "vpid %" PRIu64 ": exited with status %d",
                tracee->vpid, last_exit_status);
        terminate_tracee(tracee);
    }
    else if (WIFSIGNALED(tracee_status)) {
        if (tracee->verbose > 1) {
            check_architecture(tracee);
        }
        VERBOSE(tracee, (int) (tracee->vpid != 1),
                "vpid %" PRIu64 ": terminated with signal %d",
                tracee->vpid, WTERMSIG(tracee_status));
        terminate_tracee(tracee);
    }
    else if (WIFSTOPPED(tracee_status)) {
        signal = (tracee_status & 0xfff00) >> 8;
        switch (signal) {
            case SIGTRAP: {
                const unsigned long default_ptrace_options = (
                    PTRACE_O_TRACESYSGOOD	|
                    PTRACE_O_TRACEFORK	|
                    PTRACE_O_TRACEVFORK	|
                    PTRACE_O_TRACEVFORKDONE	|
                    PTRACE_O_TRACEEXEC	|
                    PTRACE_O_TRACECLONE	|
                    PTRACE_O_TRACEEXIT);
                if (deliver_sigtrap)
                    break;
                deliver_sigtrap = true;

                status = ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL,
                                default_ptrace_options | PTRACE_O_TRACESECCOMP);
                if (status < 0) {
                    status = ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL,
                                    default_ptrace_options);
                    if (status < 0) {
                        note(tracee, ERROR, SYSTEM, "ptrace(PTRACE_SETOPTIONS)");
                        exit(EXIT_FAILURE);
                    }
                }
            }
                /* FALLTHROUGH */
            case SIGTRAP | 0x80:
                signal = 0;
                if (tracee->exe == NULL) {
                    tracee->restart_how = PTRACE_CONT;
                    return 0;
                }
                switch (tracee->seccomp) {
                    case ENABLED:
                        if (IS_IN_SYSENTER(tracee)) {
                            tracee->restart_how = PTRACE_SYSCALL;
                            tracee->sysexit_pending = true;
                        }
                        else {
                            tracee->restart_how = PTRACE_CONT;
                            tracee->sysexit_pending = false;
                        }
                        /* FALLTHROUGH */
                    case DISABLED:
                        if (!tracee->seccomp_already_handled_enter)
                        {
                            bool was_sysenter = IS_IN_SYSENTER(tracee);
                            translate_syscall(tracee);
                            if (was_sysenter) {
                                tracee->skip_next_seccomp_signal = (
                                        seccomp_after_ptrace_enter &&
                                        get_sysnum(tracee, CURRENT) == PR_void);
                            }
                            if (tracee->chain.suppressed_signal && tracee->chain.syscalls == NULL && !tracee->restore_original_regs_after_seccomp_event) {
                                signal = tracee->chain.suppressed_signal;
                                tracee->chain.suppressed_signal = 0;
                                VERBOSE(tracee, 6, "vpid %" PRIu64 ": redelivering suppressed signal %d", tracee->vpid, signal);
                            }
                        }
                        else {
                            VERBOSE(tracee, 6, "skipping SIGTRAP for already handled sysenter");
                            assert(!IS_IN_SYSENTER(tracee));
                            assert(!seccomp_after_ptrace_enter);
                            tracee->seccomp_already_handled_enter = false;
                            tracee->restart_how = PTRACE_SYSCALL;
                        }
                        if (tracee->seccomp == DISABLING) {
                            tracee->restart_how = PTRACE_SYSCALL;
                            tracee->seccomp = DISABLED;
                        }
                        break;
                    case DISABLING:
                        tracee->seccomp = DISABLED;
                        if (IS_IN_SYSENTER(tracee))
                            tracee->status = 1;
                        break;
                }
                break;
            case SIGTRAP | PTRACE_EVENT_SECCOMP2 << 8:
            case SIGTRAP | PTRACE_EVENT_SECCOMP << 8: {
                unsigned long flags = 0;
                signal = 0;
                if (!seccomp_detected) {
                    tracee->seccomp = ENABLED;
                    seccomp_detected = true;
                    seccomp_after_ptrace_enter = !IS_IN_SYSENTER(tracee);
                    VERBOSE(tracee, 1, "ptrace acceleration (seccomp mode 2, %s syscall order) enabled",
                            seccomp_after_ptrace_enter ? "new" : "old");
                }
                tracee->skip_next_seccomp_signal = false;

                if (seccomp_after_ptrace_enter && !IS_IN_SYSENTER(tracee))
                {
                    tracee->restart_how = tracee->last_restart_how;
                    VERBOSE(tracee, 6, "skipping PTRACE_EVENT_SECCOMP for already handled sysenter");
                    assert(tracee->restart_how != PTRACE_CONT);
                    break;
                }
                assert(IS_IN_SYSENTER(tracee));
                if (tracee->seccomp != ENABLED)
                    break;

                status = ptrace(PTRACE_GETEVENTMSG, tracee->pid, NULL, &flags);
                if (status < 0)
                    break;

                if ((flags & FILTER_SYSEXIT) != 0 || sysexit_necessary) {
                    if (seccomp_after_ptrace_enter) {
                        tracee->restart_how = PTRACE_SYSCALL;
                        translate_syscall(tracee);
                    }
                    tracee->restart_how = PTRACE_SYSCALL;
                    break;
                }

                tracee->restart_how = PTRACE_CONT;
                translate_syscall(tracee);
                if (tracee->seccomp == DISABLING)
                    tracee->restart_how = PTRACE_SYSCALL;
                if (!seccomp_after_ptrace_enter && tracee->restart_how == PTRACE_SYSCALL)
                    tracee->seccomp_already_handled_enter = true;
                break;
            }
            case SIGTRAP | PTRACE_EVENT_VFORK << 8:
                signal = 0;
                (void) new_child(tracee, CLONE_VFORK);
                break;
            case SIGTRAP | PTRACE_EVENT_FORK  << 8:
            case SIGTRAP | PTRACE_EVENT_CLONE << 8:
                signal = 0;
                (void) new_child(tracee, 0);
                break;
            case SIGTRAP | PTRACE_EVENT_VFORK_DONE << 8:
            case SIGTRAP | PTRACE_EVENT_EXEC  << 8:
            case SIGTRAP | PTRACE_EVENT_EXIT  << 8:
                signal = 0;
                if (tracee->last_restart_how) {
                    tracee->restart_how = tracee->last_restart_how;
                }
                break;
            case SIGSTOP:
                if (tracee->exe == NULL) {
                    tracee->sigstop = SIGSTOP_PENDING;
                    signal = -1;
                }
                if (tracee->sigstop == SIGSTOP_IGNORED) {
                    tracee->sigstop = SIGSTOP_ALLOWED;
                    signal = 0;
                }
                break;
            case SIGSYS: {
                siginfo_t siginfo = {};
                ptrace(PTRACE_GETSIGINFO, tracee->pid, NULL, &siginfo);
                if (siginfo.si_code == SYS_SECCOMP) {
                    if (!IS_IN_SYSENTER(tracee)) {
                        VERBOSE(tracee, 1, "Handling syscall exit from SIGSYS");
                        translate_syscall(tracee);
                    }
                    if (tracee->skip_next_seccomp_signal || (seccomp_after_ptrace_enter && (word_t)siginfo.si_syscall == SYSCALL_AVOIDER)) {
                        VERBOSE(tracee, 4, "suppressed SIGSYS after void syscall");
                        tracee->skip_next_seccomp_signal = false;
                        signal = 0;
                    } else {
                        signal = handle_seccomp_event(tracee);
                    }
                } else {
                    VERBOSE(tracee, 1, "non-seccomp SIGSYS");
                }
                break;
            }
            default:
                if (tracee->chain.syscalls != NULL || tracee->restore_original_regs_after_seccomp_event) {
                    VERBOSE(tracee, 5,
                            "vpid %" PRIu64 ": suppressing signal during chain signal=%d, prev suppressed_signal=%d",
                            tracee->vpid, signal, tracee->chain.suppressed_signal);
                    tracee->chain.suppressed_signal = signal;
                    signal = 0;
                }
                break;
        }
    }
    tracee->as_ptracee.event4.proot.pending = false;
    return signal;
}

bool seccomp_event_happens_after_enter_sigtrap(void)
{
    return !seccomp_after_ptrace_enter;
}

bool restart_tracee(Tracee *tracee, int signal)
{
    int status;
    if (tracee->as_ptracer.wait_pid != 0 || signal == -1)
        return false;

    assert(tracee->restart_how != 0);
    status = ptrace(tracee->restart_how, tracee->pid, NULL, signal);
    if (status < 0)
        return false;

    tracee->last_restart_how = tracee->restart_how;
    tracee->restart_how = 0;
    tracee->running = true;
    return true;
}
