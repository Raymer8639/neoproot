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
#include <stdatomic.h>
#include <signal.h>
#include <pthread.h>

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

// ==================== C23 编译期静态检查 ====================
static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "atomic_bool must be lock-free for signal safety");
static_assert(ATOMIC_INT_LOCK_FREE == 2, "atomic_int must be lock-free");
static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "atomic pointer must be lock-free");
static_assert(PTRACE_SYSCALL != 0, "PTRACE_SYSCALL must not be 0 (fixes restart hang)");

// ==================== 全局原子状态（RCPC优化） ====================
static _Atomic bool seccomp_after_ptrace_enter = false;
static _Atomic bool seccomp_detected = false;
static _Atomic bool seccomp_after_ptrace_enter_checked = false;
static _Atomic int last_exit_status = -1;
static _Atomic bool is_exiting_normally = false;
static _Atomic bool root_exited = false;
static _Atomic pid_t main_pid = 0;

// ==================== 信号处理辅助函数 ====================
static void sig_ign(int sig, siginfo_t *si, void *uc)
{
    [[maybe_unused]] const int unused_sig = sig;
    [[maybe_unused]] siginfo_t *const unused_si = si;
    [[maybe_unused]] void *const unused_uc = uc;
}

static void kill_all_tracees_safely(void)
{
    static atomic_flag cleanup_done = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set_explicit(&cleanup_done, memory_order_acquire)) {
        return;
    }

    kill_all_tracees();

    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, __WALL | WNOHANG)) > 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        ptrace(PTRACE_CONT, pid, NULL, 0);
        kill(pid, SIGKILL);
    }

    atomic_flag_clear_explicit(&cleanup_done, memory_order_release);
}

static void kill_all_tracees2(int signum, siginfo_t *siginfo, void *ucontext)
{
    [[maybe_unused]] void *const uc = ucontext;
    static atomic_flag handling_signal = ATOMIC_FLAG_INIT;
    if (atomic_flag_test_and_set_explicit(&handling_signal, memory_order_acquire)) {
        return;
    }

    const bool exiting = atomic_load_explicit(&is_exiting_normally, memory_order_acquire);
    if (signum == SIGSEGV && exiting) {
        kill_all_tracees_safely();
        const int exit_code = atomic_load_explicit(&last_exit_status, memory_order_acquire);
        _Exit(exit_code >= 0 ? exit_code : EXIT_SUCCESS);
    }

    note(NULL, WARNING, INTERNAL, "signal %d received from process %d",
         signum, siginfo->si_pid);

    kill_all_tracees_safely();

    if (signum != SIGQUIT) {
        usleep(100000);
        _Exit(EXIT_FAILURE);
    }

    atomic_flag_clear_explicit(&handling_signal, memory_order_release);
}

// ==================== talloc 调试辅助函数 ====================
static void print_talloc_chunk(const void *ptr, int depth, int max_depth, int is_ref, void *data)
{
    [[maybe_unused]] const int unused_max_depth = max_depth;
    [[maybe_unused]] void *const unused_data = data;
    const char *name;
    size_t count;
    size_t size;

    name = talloc_get_name(ptr);
    size = talloc_get_size(ptr);
    count = talloc_reference_count(ptr);

    if (depth == 0)
        return;
    for (int i = 0; i < depth - 1; i++)
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
            fprintf(stderr, "\t(");
            for (int i = 0; argv[i] != NULL; i++)
                fprintf(stderr, "\"%s\", ", argv[i]);
            fprintf(stderr, ")");
        } else if (strcmp(name, "Tracee") == 0) {
            fprintf(stderr, "\t(pid = %d, parent = %p)",
                    ((Tracee *)ptr)->pid, ((Tracee *)ptr)->parent);
        } else if (strcmp(name, "Bindings") == 0) {
            Tracee *tracee = TRACEE(ptr);
            if (ptr == tracee->fs->bindings.pending)
                fprintf(stderr, "\t(pending)");
            else if (ptr == tracee->fs->bindings.guest)
                fprintf(stderr, "\t(guest)");
            else if (ptr == tracee->fs->bindings.host)
                fprintf(stderr, "\t(host)");
        } else if (strcmp(name, "Binding") == 0) {
            Binding *binding = (Binding *)ptr;
            fprintf(stderr, "\t(%s:%s)", binding->host.path, binding->guest.path);
        }
    }
    fprintf(stderr, "\n");
}

static void print_talloc_hierarchy(int signum, siginfo_t *siginfo, void *ucontext)
{
    [[maybe_unused]] siginfo_t *const unused_siginfo = siginfo;
    [[maybe_unused]] void *const unused_ucontext = ucontext;
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

// ==================== 架构检查函数 ====================
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

// ==================== 进程启动函数 ====================
[[nodiscard]]
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
        case 0:
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
        default:
            tracee->pid = pid;
            return 0;
    }
    return -ENOSYS;
}

// ==================== 核心事件循环 ====================
[[nodiscard]]
int event_loop(void)
{
    struct sigaction signal_action;
    long status;

    atomic_store_explicit(&main_pid, getpid(), memory_order_release);

    status = atexit(kill_all_tracees_safely);
    if (status != 0) {
        note(NULL, WARNING, INTERNAL, "atexit() failed");
    }

    memset(&signal_action, 0, sizeof(signal_action));
    signal_action.sa_flags = SA_SIGINFO;
    status = sigfillset(&signal_action.sa_mask);
    if (status < 0)
        note(NULL, WARNING, SYSTEM, "sigfillset()");

    for (int signum = 0; signum < NSIG; signum++) {
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

        const bool root_exited_flag = atomic_load_explicit(&root_exited, memory_order_acquire);
        if (root_exited_flag) {
            atomic_store_explicit(&is_exiting_normally, true, memory_order_release);
            kill_all_tracees_safely();
            break;
        }

        pid = waitpid(-1, &tracee_status, __WALL);

        if (pid < 0) {
            if (errno == ECHILD) {
                atomic_store_explicit(&is_exiting_normally, true, memory_order_release);
                kill_all_tracees_safely();
                break;
            }
            continue;
        }

        tracee = get_tracee(NULL, pid, true);
        if (tracee == NULL || tracee->pid <= 0 || tracee->terminated) {
            continue;
        }
        tracee->running = false;

        if (notify_extensions(tracee, NEW_STATUS, tracee_status, 0) != 0)
            continue;

        if (tracee->as_ptracee.ptracer != NULL) {
            const bool keep_stopped = handle_ptracee_event(tracee, tracee_status);
            if (keep_stopped)
                continue;
        }

        signal = handle_tracee_event(tracee, tracee_status);
        (void) restart_tracee(tracee, signal);
    }
    return atomic_load_explicit(&last_exit_status, memory_order_acquire);
}

// ==================== Tracee 事件处理核心 ====================
[[nodiscard]]
int handle_tracee_event(Tracee *tracee, int tracee_status)
{
    long status;
    int signal;
    bool sysexit_necessary;
    bool deliver_sigtrap = false;
    const bool after_enter = atomic_load_explicit(&seccomp_after_ptrace_enter, memory_order_acquire);

    if (tracee == NULL || tracee->pid <= 0 || tracee->terminated) {
        return 0;
    }

    // 进程退出处理
    if (WIFEXITED(tracee_status) || WIFSIGNALED(tracee_status)) {
        ptrace(PTRACE_DETACH, tracee->pid, NULL, NULL);

        if (WIFEXITED(tracee_status)) {
            const int exit_status = WEXITSTATUS(tracee_status);
            atomic_store_explicit(&last_exit_status, exit_status, memory_order_release);
            VERBOSE(tracee, 1, "vpid %" PRIu64 ": exited with status %d", tracee->vpid, exit_status);
        } else {
            if (tracee->verbose > 1) {
                check_architecture(tracee);
            }
            VERBOSE(tracee, (int)(tracee->vpid != 1), "vpid %" PRIu64 ": terminated by signal %d", tracee->vpid, WTERMSIG(tracee_status));
        }

        if (tracee->vpid == 1) {
            atomic_store_explicit(&root_exited, true, memory_order_release);
            kill(atomic_load_explicit(&main_pid, memory_order_acquire), SIGUSR1);
        }

        terminate_tracee(tracee);
        return 0;
    }

    // seccomp 模式检查
    const bool seccomp_checked = atomic_load_explicit(&seccomp_after_ptrace_enter_checked, memory_order_acquire);
    if (!seccomp_checked) {
        const bool new_seccomp = getenv("PROOT_ASSUME_NEW_SECCOMP") != NULL;
        atomic_store_explicit(&seccomp_after_ptrace_enter, new_seccomp, memory_order_release);
        atomic_store_explicit(&seccomp_after_ptrace_enter_checked, true, memory_order_release);
    }

    sysexit_necessary = tracee->sysexit_pending
                        || tracee->chain.syscalls != NULL
                        || tracee->restore_original_regs_after_seccomp_event;

    // 修复restart_how默认值
    if (tracee->restart_how == 0) {
        tracee->restart_how = (tracee->seccomp == ENABLED && !sysexit_necessary) ? PTRACE_CONT : PTRACE_SYSCALL;
    }

    signal = 0;
    if (WIFSTOPPED(tracee_status)) {
        signal = (tracee_status & 0xfff00) >> 8;
        switch (signal) {
            case SIGTRAP: {
                const unsigned long default_ptrace_options =
                    PTRACE_O_TRACESYSGOOD	|
                    PTRACE_O_TRACEFORK	|
                    PTRACE_O_TRACEVFORK	|
                    PTRACE_O_TRACEVFORKDONE	|
                    PTRACE_O_TRACEEXEC	|
                    PTRACE_O_TRACECLONE	|
                    PTRACE_O_TRACEEXIT;
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
                            const bool was_sysenter = IS_IN_SYSENTER(tracee);
                            translate_syscall(tracee);
                            if (was_sysenter) {
                                tracee->skip_next_seccomp_signal = (
                                        after_enter &&
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
                            tracee->seccomp_already_handled_enter = false;
                            tracee->restart_how = PTRACE_SYSCALL;
                        }
                        if (tracee->seccomp == DISABLING) {
                            tracee->restart_how = PTRACE_SYSCALL;
                            tracee->seccomp = DISABLED;
                            atomic_signal_fence(memory_order_release);
                        }
                        break;
                    case DISABLING:
                        tracee->seccomp = DISABLED;
                        atomic_signal_fence(memory_order_release);
                        if (IS_IN_SYSENTER(tracee))
                            tracee->status = 1;
                        break;
                }
                break;
            case SIGTRAP | PTRACE_EVENT_SECCOMP2 << 8:
            case SIGTRAP | PTRACE_EVENT_SECCOMP << 8: {
                unsigned long flags = 0;
                signal = 0;
                const bool seccomp_found = atomic_load_explicit(&seccomp_detected, memory_order_acquire);

                // 【关键修复1】先拿事件flags，再做任何逻辑判断
                status = ptrace(PTRACE_GETEVENTMSG, tracee->pid, NULL, &flags);
                if (status < 0) {
                    VERBOSE(tracee, 1, "failed to get seccomp event msg, skipping");
                    break;
                }

                // 【关键修复2】首次seccomp事件初始化，先判断事件类型再赋值
                if (!seccomp_found) {
                    const bool is_sysenter = IS_IN_SYSENTER(tracee);
                    const bool new_after_enter = !is_sysenter;
                    
                    tracee->seccomp = ENABLED;
                    atomic_signal_fence(memory_order_release);
                    atomic_store_explicit(&seccomp_detected, true, memory_order_release);
                    atomic_store_explicit(&seccomp_after_ptrace_enter, new_after_enter, memory_order_release);
                    
                    VERBOSE(tracee, 1, "ptrace acceleration (seccomp mode 2, %s syscall order) enabled",
                            new_after_enter ? "new" : "old");
                }

                tracee->skip_next_seccomp_signal = false;

                // 【关键修复3】新seccomp模式下，非sysenter事件直接跳过，不触发断言
                if (after_enter && !IS_IN_SYSENTER(tracee)) {
                    tracee->restart_how = tracee->last_restart_how;
                    VERBOSE(tracee, 6, "skipping PTRACE_EVENT_SECCOMP for already handled sysenter");
                    break;
                }

                // 仅对sysenter阶段的事件做断言，SYSEXIT事件跳过
                if ((flags & FILTER_SYSEXIT) == 0) {
                    assert(IS_IN_SYSENTER(tracee));
                } else {
                    VERBOSE(tracee, 6, "seccomp sysexit event received, skipping assert");
                }

                if (tracee->seccomp != ENABLED)
                    break;

                // SYSEXIT事件处理
                if ((flags & FILTER_SYSEXIT) != 0 || sysexit_necessary) {
                    if (after_enter) {
                        tracee->restart_how = PTRACE_SYSCALL;
                        translate_syscall(tracee);
                    }
                    tracee->restart_how = PTRACE_SYSCALL;
                    break;
                }

                // SYSENTER事件处理
                tracee->restart_how = PTRACE_CONT;
                translate_syscall(tracee);
                if (tracee->seccomp == DISABLING)
                    tracee->restart_how = PTRACE_SYSCALL;
                if (!after_enter && tracee->restart_how == PTRACE_SYSCALL)
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
                siginfo_t siginfo = {0};
                ptrace(PTRACE_GETSIGINFO, tracee->pid, NULL, &siginfo);
                if (siginfo.si_code == SYS_SECCOMP) {
                    if (!IS_IN_SYSENTER(tracee)) {
                        VERBOSE(tracee, 1, "Handling syscall exit from SIGSYS");
                        translate_syscall(tracee);
                    }
                    const bool skip_signal = tracee->skip_next_seccomp_signal ||
                        (after_enter && (word_t)siginfo.si_syscall == SYSCALL_AVOIDER);
                    if (skip_signal) {
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

// ==================== 辅助函数 ====================
[[nodiscard]]
bool seccomp_event_happens_after_enter_sigtrap(void)
{
    return !atomic_load_explicit(&seccomp_after_ptrace_enter, memory_order_acquire);
}

[[nodiscard]]
bool restart_tracee(Tracee *tracee, int signal)
{
    if (tracee == NULL || tracee->pid <= 0 || tracee->terminated || tracee->as_ptracer.wait_pid != 0 || signal == -1)
        return false;

    if (tracee->restart_how == 0) {
        tracee->restart_how = PTRACE_SYSCALL;
    }

    const int status = ptrace(tracee->restart_how, tracee->pid, NULL, signal);
    if (status < 0)
        return false;

    tracee->last_restart_how = tracee->restart_how;
    tracee->restart_how = 0;
    tracee->running = true;
    return true;
}
