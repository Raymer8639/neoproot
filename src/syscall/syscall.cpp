#include <cassert>
#include <cstring>
#include <cerrno>
#include <climits>
#include <cstddef>
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
#define TRIVIAL_SYSCALL_WHITELIST_SIZE 10

// ==============================
// 优先处理名单（必须拦截，禁止透传）
// ==============================
static bool is_priority_syscall(word_t sysnum)
{
    switch (sysnum) {
        case PR_read:
        case PR_write:
        case PR_open:
        case PR_close:
        case PR_execve:
        case PR_prctl:
        case PR_fork:
        case PR_vfork:
        case PR_clone:
        case PR_getuid:
        case PR_getgid:
        case PR_geteuid:
        case PR_getegid:
        case PR_chdir:
        case PR_fchdir:
        case PR_getcwd:
        case PR_mmap:
        case PR_mprotect:
        case PR_munmap:
        case PR_brk:
        case PR_fstat:
        case PR_lstat:
        case PR_stat:
            return true;
        default:
            return false;
    }
}

int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg)
{
    if (tracee == nullptr || path == nullptr) {
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
        return size;
    }

    size = std::min(size, PATH_BUF_SAFE_LEN);
    path[size] = '\0';
    return size;
}

int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg)
{
    if (tracee == nullptr || tracer_ptr == nullptr || size == 0 || size > PATH_MAX) {
        note(tracee, ERROR, INTERNAL, "set_sysarg_data: invalid input (tracee=%p, ptr=%p, size=%lu)", tracee, tracer_ptr, size);
        return -EINVAL;
    }

    // ==============================
    // 树扁平：直接挂 tracee 顶层，不再嵌套子上下文
    // ==============================
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
    if (tracee == nullptr || path == nullptr) {
        note(tracee, ERROR, INTERNAL, "set_sysarg_path: invalid input (tracee=%p, path=%p)", tracee, path);
        return -EINVAL;
    }

    const size_t new_len = std::min(strlen(path) + 1, (size_t)PATH_BUF_SAFE_LEN);
    const word_t old_ptr = peek_reg(tracee, CURRENT, reg);

    if (old_ptr != 0 && new_len > 1) {
        char old_path[PATH_MAX];
        const ssize_t old_len = get_sysarg_path(tracee, old_path, reg);

        if (old_len >= 0) {
            static const char *LINKER_PATTERNS[] = {
                "/ld-linux-", "/lib/ld-", "/system/bin/linker", "/ld.so.", nullptr
            };
            bool is_linker = false;
            for (int i = 0; LINKER_PATTERNS[i] != nullptr; i++) {
                if (strstr(old_path, LINKER_PATTERNS[i]) != nullptr) {
                    is_linker = true;
                    break;
                }
            }

            if (!is_linker && (size_t)old_len >= new_len && path[0] != '\0') {
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
    if (tracee == nullptr || tracee->exe == nullptr) {
        note(nullptr, ERROR, INTERNAL, "translate_syscall: invalid tracee (tracee=%p, exe=%p)", tracee, tracee ? tracee->exe : nullptr);
        return;
    }

    const bool is_enter_stage = IS_IN_SYSENTER(tracee);
    bool is_trivial_syscall = false;
    int suppressed_syscall_status = 0;

    if (fetch_regs(tracee) < 0) {
        note(tracee, WARNING, SYSTEM, "translate_syscall: fetch_regs failed");
        return;
    }

    if (is_enter_stage) {
        tracee->restore_original_regs = false;

        if (!tracee->chain.syscalls) {
            const word_t sysnum = get_sysnum(tracee, CURRENT);

            // ==============================
            // 优先处理：直接不走白名单
            // ==============================
            if (is_priority_syscall(sysnum)) {
                is_trivial_syscall = false;
            } else {
                static const word_t TRIVIAL_SYSCALLS[] = {
                    PR_gettimeofday, PR_clock_gettime, PR_clock_getres,
                    PR_time, PR_times, PR_uname, PR_sysinfo,
                    PR_getpid, PR_getppid, PR_gettid
                };

                for (size_t i = 0; i < TRIVIAL_SYSCALL_WHITELIST_SIZE && TRIVIAL_SYSCALLS[i] != 0; i++) {
                    if (sysnum == TRIVIAL_SYSCALLS[i]) {
                        is_trivial_syscall = true;
                        break;
                    }
                }
            }

            if (is_trivial_syscall) {
                tracee->status = 0;
                tracee->restart_how = PTRACE_SYSCALL;
                return;
            }

            // ==============================
            // 树扁平关键：所有临时内存统一挂 tracee 顶层，不再深层嵌套
            // ==============================
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
    if (!is_trivial_syscall) {
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

                if (push_specific_regs(tracee, false) != 0) {
                    note(tracee, ERROR, SYSTEM, "translate_syscall: failed to set tracee registers (orig=0x%lx, curr=0x%lx)", orig_sysnum, curr_sysnum);
                }
            }
        }
    }
}
