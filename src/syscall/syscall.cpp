#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

#include <algorithm>

#ifdef __cplusplus
extern "C" {
#endif

#include "syscall/syscall.h"
#include "syscall/chain.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "cli/note.h"

#ifdef __cplusplus
}
#endif

#define PATH_BUF_SAFE_LEN (PATH_MAX - 1)

static const char *BIONIC_LINKER_PATTERNS[] = {
    "/apex/com.android.runtime/bin/linker",
    "/apex/com.android.runtime/bin/linker64",
    "/system/bin/linker",
    "/system/bin/linker64",
    NULL
};

static inline bool bionic_intercept_syscall(word_t sysnum) {
    switch (sysnum) {
        case PR_open:
        case PR_openat:
        case PR_creat:
        case PR_read:
        case PR_write:
        case PR_pread64:
        case PR_pwrite64:
        case PR_close:
        case PR_stat:
        case PR_lstat:
        case PR_fstat:
        case PR_newfstatat:
        case PR_getcwd:
        case PR_chdir:
        case PR_fchdir:
        case PR_readlink:
        case PR_readlinkat:
        case PR_mmap:
        case PR_mprotect:
        case PR_munmap:
        case PR_brk:
            return true;
        default:
            return false;
    }
}

static inline bool is_mandatory_intercept(word_t sysnum)
{
    switch (sysnum) {
        case PR_getuid:
        case PR_getgid:
        case PR_geteuid:
        case PR_getegid:
        case PR_getresuid:
        case PR_getresgid:
        case PR_setuid:
        case PR_setgid:
        case PR_setresuid:
        case PR_setresgid:
        case PR_capget:
        case PR_capset:

        case PR_execve:
        case PR_execveat:
        case PR_fork:
        case PR_vfork:
        case PR_clone:
        case PR_exit:
        case PR_exit_group:
        case PR_wait4:
        case PR_waitid:
        case PR_ptrace:

        case PR_prctl:
        case PR_seccomp:
        case PR_setdomainname:
        case PR_sethostname:
            return true;
        default:
            return false;
    }
}

static inline bool is_safe_passthrough(word_t sysnum)
{
    switch (sysnum) {
        case PR_gettimeofday:
        case PR_clock_gettime:
        case PR_clock_getres:
        case PR_time:
        case PR_times:
        case PR_nanosleep:
        case PR_clock_nanosleep:

        case PR_getpid:
        case PR_getppid:
        case PR_gettid:

        case PR_uname:
        case PR_sysinfo:

        case PR_sched_yield:
        case PR_sched_get_priority_max:
        case PR_sched_get_priority_min:

        case PR_getrandom:
        case PR_sigpending:
            return true;

    default:
        return false;
    }
}

static inline bool is_gpu_passthrough(word_t sysnum)
{
    switch (sysnum) {
        case PR_mbind:
        case PR_get_mempolicy:
        case PR_set_mempolicy:
        case PR_migrate_pages:
        case PR_move_pages:
        case PR_msync:
        case PR_madvise:
        case PR_mlock:
        case PR_munlock:
            return true;
        default:
            return false;
    }
}

int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg)
{
    if (tracee == NULL || path == NULL) {
        note(tracee, ERROR, INTERNAL, "get_sysarg_path: invalid input (tracee=%p, path=%p)", tracee, path);
        return -EINVAL;
    }

    const word_t src = peek_reg(tracee, CURRENT, reg);
    if (src == 0) {
        path[0] = '\0';
        return 0;
    }

    int size = read_path(tracee, path, src);
    if (size < 0) {
        note(tracee, WARNING, SYSTEM, "get_sysarg_path: read_path failed (reg=%d, src=0x%lx, err=%d)", reg, src, size);
        path[0] = '\0';
        return size;
    }

    size = std::min(size, (int)PATH_BUF_SAFE_LEN);
    path[size] = '\0';
    return size;
}

int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg)
{
    if (tracee == NULL || tracer_ptr == NULL || size == 0 || size > PATH_MAX) {
        note(tracee, ERROR, INTERNAL, "set_sysarg_data: invalid input (tracee=%p, ptr=%p, size=%lu)", tracee, tracer_ptr, size);
        return -EINVAL;
    }

    word_t tracee_ptr = alloc_mem(tracee, size);
    if (tracee_ptr == 0) {
        note(tracee, WARNING, SYSTEM, "set_sysarg_data: alloc failed (size=%lu)", size);
        return -EFAULT;
    }

    int status = write_data(tracee, tracee_ptr, tracer_ptr, size);
    if (status < 0) {
        note(tracee, WARNING, SYSTEM, "set_sysarg_data: write failed (ptr=0x%lx, size=%lu, err=%d)", tracee_ptr, size, status);
        return status;
    }

    poke_reg(tracee, reg, tracee_ptr);
    return 0;
}

int set_sysarg_path(Tracee *tracee, const char path[PATH_MAX], Reg reg)
{
    if (tracee == NULL || path == NULL) {
        note(tracee, ERROR, INTERNAL, "set_sysarg_path: invalid input (tracee=%p, path=%p)", tracee, path);
        return -EINVAL;
    }

    const size_t path_len = strlen(path);
    const size_t new_len = std::min(path_len + 1, (size_t)PATH_BUF_SAFE_LEN);
    const word_t old_ptr = peek_reg(tracee, CURRENT, reg);

    if (old_ptr != 0 && new_len > 1) {
        char old_path[PATH_MAX];
        const ssize_t old_len = get_sysarg_path(tracee, old_path, reg);

        if (old_len >= 0) {
            bool is_bionic_linker = false;
            for (int i = 0; BIONIC_LINKER_PATTERNS[i] != NULL; i++) {
                if (strstr(old_path, BIONIC_LINKER_PATTERNS[i]) != NULL) {
                    is_bionic_linker = true;
                    break;
                }
            }

            if (!is_bionic_linker && (size_t)old_len >= new_len && path[0] != '\0') {
                if (write_data(tracee, old_ptr, path, new_len) == 0) {
                    return 0;
                }
            }
        }
    }

    return set_sysarg_data(tracee, path, new_len, reg);
}

void translate_syscall(Tracee *tracee)
{
    if (tracee == NULL) {
        note(NULL, ERROR, INTERNAL, "translate_syscall: invalid tracee");
        return;
    }

    const bool is_enter_stage = IS_IN_SYSENTER(tracee);
    int suppressed_syscall_status = 0;

    if (fetch_regs(tracee) < 0) {
        note(tracee, WARNING, SYSTEM, "translate_syscall: fetch_regs failed");
        return;
    }

    if (is_enter_stage) {
        tracee->restore_original_regs = false;

        if (!tracee->chain.syscalls) {
            const word_t sysnum = get_sysnum(tracee, CURRENT);

            if (is_mandatory_intercept(sysnum)) {
                save_current_regs(tracee, ORIGINAL);
                const int status = translate_syscall_enter(tracee);
                save_current_regs(tracee, MODIFIED);

                if (status < 0) {
                    set_sysnum(tracee, PR_void);
                    poke_reg(tracee, SYSARG_RESULT, (word_t)status);
                    tracee->status = status;
                } else {
                    tracee->status = 1;
                }
            } else if (bionic_intercept_syscall(sysnum)) {
                save_current_regs(tracee, ORIGINAL);
                const int status = translate_syscall_enter(tracee);
                save_current_regs(tracee, MODIFIED);

                if (status < 0) {
                    set_sysnum(tracee, PR_void);
                    poke_reg(tracee, SYSARG_RESULT, (word_t)status);
                    tracee->status = status;
                } else {
                    tracee->status = 1;
                }
            } else if (is_safe_passthrough(sysnum)) {
                tracee->restart_how = PTRACE_SYSCALL;
                return;
            } else if (is_gpu_passthrough(sysnum)) {
                tracee->restart_how = PTRACE_SYSCALL;
                return;
            } else {
                save_current_regs(tracee, ORIGINAL);
                const int status = translate_syscall_enter(tracee);
                save_current_regs(tracee, MODIFIED);

                if (status < 0) {
                    set_sysnum(tracee, PR_void);
                    poke_reg(tracee, SYSARG_RESULT, (word_t)status);
                    tracee->status = status;
                } else {
                    tracee->status = 1;
                }
            }
        } else {
            tracee->restart_how = PTRACE_SYSCALL;
        }

        if (tracee->restart_how == PTRACE_CONT) {
            suppressed_syscall_status = tracee->status;
            tracee->status = 0;
            poke_reg(tracee, STACK_POINTER, peek_reg(tracee, ORIGINAL, STACK_POINTER));
        }
    } else {
        tracee->restore_original_regs = true;
        if (!tracee->chain.syscalls) {
            translate_syscall_exit(tracee);
        }
        tracee->status = 0;
        if (tracee->chain.syscalls) {
            chain_next_syscall(tracee);
        }
    }

    const bool override_sysnum = is_enter_stage && !tracee->chain.syscalls;
    const int push_status = push_specific_regs(tracee, override_sysnum);

    if (push_status < 0 && override_sysnum) {
        const word_t orig_sysnum = peek_reg(tracee, ORIGINAL, SYSARG_NUM);
        const word_t curr_sysnum = peek_reg(tracee, CURRENT, SYSARG_NUM);

        if (orig_sysnum != curr_sysnum) {
            if (curr_sysnum != SYSCALL_AVOIDER) {
                restart_current_syscall_as_chained(tracee);
            } else if (suppressed_syscall_status != 0) {
                tracee->status = suppressed_syscall_status;
                tracee->restart_how = PTRACE_SYSCALL;
            }

            const Reg sysargs[] = {SYSARG_1, SYSARG_2, SYSARG_3, SYSARG_4, SYSARG_5, SYSARG_6};
            for (Reg r : sysargs) {
                poke_reg(tracee, r, (word_t)-1);
            }

            if (get_sysnum(tracee, ORIGINAL) == PR_brk) {
                poke_reg(tracee, SYSARG_1, 0);
            }

            push_specific_regs(tracee, false);
        }
    }
}
