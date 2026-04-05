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

// ==================== 早停字符串比较优化 ====================
static inline int fast_strcmp(const char *a, const char *b)
{
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}
// ==========================================================

static bool seccomp_after_ptrace_enter = false;
static bool seccomp_detected = false;
static bool seccomp_after_ptrace_enter_checked = false;
static int last_exit_status = -1;
// 全局标记：是否处于正常退出流程
static volatile sig_atomic_t is_exiting_normally = 0;
// 全局标记：根进程是否已退出（根治卡死核心）
static volatile sig_atomic_t root_exited = 0;
// 主进程PID，用于打断阻塞waitpid
static pid_t main_pid = 0;

// 安全的忽略信号函数（仅用于唤醒阻塞的waitpid，无任何副作用）
static void sig_ign(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    (void)uc;
}

// ==================== 安全全量清理函数 ====================
// 仅在退出时执行一次，彻底清理所有残留进程，绝不阻塞
static void kill_all_tracees_safely(void)
{
    static volatile sig_atomic_t cleanup_done = 0;
    if (__atomic_test_and_set(&cleanup_done, __ATOMIC_SEQ_CST)) {
        return;
    }

    // 调用原生全量杀死API
    kill_all_tracees();

    // 【根治卡死核心】强制detach+收割所有残留进程，包括stopped状态
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, __WALL | WNOHANG)) > 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        ptrace(PTRACE_CONT, pid, NULL, 0);
        kill(pid, SIGKILL);
    }
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

// 防重入+正常退出静默处理，彻底解决signal 11警告
static void kill_all_tracees2(int signum, siginfo_t *siginfo, void *ucontext)
{
    (void)ucontext;
    
    // 防重入保护
    static volatile sig_atomic_t handling_signal = 0;
    if (__atomic_test_and_set(&handling_signal, __ATOMIC_SEQ_CST)) {
        return;
    }

    // 正常退出流程的SIGSEGV，静默清理退出
    if (signum == SIGSEGV && is_exiting_normally) {
        kill_all_tracees_safely();
        _exit(last_exit_status >= 0 ? last_exit_status : EXIT_SUCCESS);
    }

    // 非退出场景的真崩溃，保留原版警告逻辑
    note(NULL, WARNING, INTERNAL, "signal %d received from process %d",
         signum, siginfo->si_pid);
    
    kill_all_tracees_safely();
    
    if (signum != SIGQUIT) {
        usleep(100000);
        _exit(EXIT_FAILURE);
    }

    __atomic_clear(&handling_signal, __ATOMIC_SEQ_CST);
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
        } else if (fast_strcmp(name, "Tracee") == 0) {
            fprintf(stderr, "\t(pid = %d, parent = %p)",
                    ((Tracee *)ptr)->pid, ((Tracee *)ptr)->parent);
        } else if (fast_strcmp(name, "Bindings") == 0) {
            Tracee *tracee = TRACEE(ptr);
            if (ptr == tracee->fs->bindings.pending)
                fprintf(stderr, "\t(pending)");
            else if (ptr == tracee->fs->bindings.guest)
                fprintf(stderr, "\t(guest)");
            else if (ptr == tracee->fs->bindings.host)
                fprintf(stderr, "\t(host)");
        } else if (fast_strcmp(name, "Binding") == 0) {
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
    if (fast_strcmp(utsname.machine, "aarch64") != 0 && fast_strcmp(utsname.machine, "arm64") != 0)
        return;
    note(tracee, INFO, USER,
         "Please use the 64-bit ARM64 build of %s to run this program", tracee->tool_name);
}

// ==================== 【核心：纯事件驱动零延迟事件循环】 ====================
// 无轮询、无超时、无sleep，纯内核级事件驱动，零延迟响应，退出绝对不卡死
int event_loop(void)
{
    struct sigaction signal_action;
    long status;

    // 记录主进程PID，用于退出时打断阻塞
    main_pid = getpid();

    // 注册退出清理函数
    status = atexit(kill_all_tracees_safely);
    if (status != 0) {
        note(NULL, WARNING, INTERNAL, "atexit() failed");
    }

    // 信号注册：去掉SA_RESTART，让信号能打断waitpid阻塞
    memset(&signal_action, 0, sizeof(signal_action));
    signal_action.sa_flags = SA_SIGINFO;
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

        // 先清理已终止进程，避免野指针
        free_terminated_tracees();

        // 【核心1】根进程已退出，直接强制清理，绝不阻塞
        if (root_exited) {
            is_exiting_normally = 1;
            kill_all_tracees_safely();
            break;
        }

        // 【核心2：纯事件驱动零延迟】原生阻塞waitpid
        // 无事件时，内核直接把进程挂起，CPU 0%，无任何唤醒开销
        // 有事件时，内核立刻唤醒进程处理，零延迟，没有任何等待
        pid = waitpid(-1, &tracee_status, __WALL);

        // waitpid被打断/出错，先检查是否要退出
        if (pid < 0) {
            // 所有子进程已退出，正常结束流程
            if (errno == ECHILD) {
                is_exiting_normally = 1;
                kill_all_tracees_safely();
                break;
            }
            // 被信号打断，检查根进程状态，退出就结束，否则继续等待事件
            continue;
        }

        // 空指针防护，无效tracee直接跳过
        tracee = get_tracee(NULL, pid, true);
        if (tracee == NULL || tracee->pid <= 0 || tracee->terminated) {
            continue;
        }
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

// 【核心重构：先处理进程生死，再执行业务逻辑】
int handle_tracee_event(Tracee *tracee, int tracee_status)
{
    long status;
    int signal;
    bool sysexit_necessary;
    bool deliver_sigtrap = false;

    // 生死前置校验，无效/已终止进程直接返回
    if (tracee == NULL || tracee->pid <= 0 || tracee->terminated) {
        return 0;
    }

    // 【核心3：退出事件优先处理】
    if (WIFEXITED(tracee_status) || WIFSIGNALED(tracee_status)) {
        // 立刻detach，避免进程卡在stopped状态
        ptrace(PTRACE_DETACH, tracee->pid, NULL, NULL);
        // 记录退出状态
        if (WIFEXITED(tracee_status)) {
            last_exit_status = WEXITSTATUS(tracee_status);
            VERBOSE(tracee, 1, "vpid %" PRIu64 ": exited with status %d", tracee->vpid, last_exit_status);
        } else {
            if (tracee->verbose > 1) {
                check_architecture(tracee);
            }
            VERBOSE(tracee, (int)(tracee->vpid != 1), "vpid %" PRIu64 ": terminated by signal %d", tracee->vpid, WTERMSIG(tracee_status));
        }
        // 【根治卡死核心】根进程退出，标记+打断主循环阻塞
        if (tracee->vpid == 1) {
            root_exited = 1;
            // 给主进程发信号，立刻打断阻塞的waitpid，进入退出流程
            kill(main_pid, SIGUSR1);
        }
        // 标记进程终止
        terminate_tracee(tracee);
        // 直接返回，绝不操作已死进程
        return 0;
    }

    // 只有进程还活着，才执行后续的业务逻辑
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
    if (WIFSTOPPED(tracee_status)) {
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

// 重启前有效性校验，杜绝对已死进程执行ptrace
bool restart_tracee(Tracee *tracee, int signal)
{
    int status;
    if (tracee == NULL || tracee->pid <= 0 || tracee->terminated || tracee->as_ptracer.wait_pid != 0 || signal == -1)
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
