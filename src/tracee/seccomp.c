#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <utime.h>
#include <sys/vfs.h>
#include <string.h>
#include <linux/net.h>
#include <assert.h>
#include <time.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "syscall/chain.h"
#include "syscall/syscall.h"
#include "tracee/seccomp.h"
#include "tracee/mem.h"
#include "tracee/statx.h"
#include "path/path.h"
#include "compat.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10
#endif

#define TRANSFORM_TO_AT_SYS(new_sys, fd, path, ...) do { \
    set_sysnum(tracee, new_sys); \
    poke_reg(tracee, SYSARG_1, fd); \
    poke_reg(tracee, SYSARG_2, path); \
    __VA_ARGS__; \
    restart_syscall_after_seccomp(tracee); \
} while(0)

static ALWAYS_INLINE void transform_simple_syscall(Tracee* restrict tracee, Sysnum new_sys,
                                                   word_t arg4, word_t arg5, word_t arg6) {
    set_sysnum(tracee, new_sys);
    if (arg4 != (word_t)-1) poke_reg(tracee, SYSARG_4, arg4);
    if (arg5 != (word_t)-1) poke_reg(tracee, SYSARG_5, arg5);
    if (arg6 != (word_t)-1) poke_reg(tracee, SYSARG_6, arg6);
    restart_syscall_after_seccomp(tracee);
}

void restart_syscall_after_seccomp(Tracee* restrict tracee) {
    tracee->restore_original_regs_after_seccomp_event = true;
    tracee->restart_how = PTRACE_SYSCALL;
    poke_reg(tracee, INSTR_POINTER, peek_reg(tracee, CURRENT, INSTR_POINTER) - get_systrap_size(tracee));
    push_specific_regs(tracee, false);
}

void set_result_after_seccomp(Tracee *restrict tracee, word_t result) {
    poke_reg(tracee, SYSARG_RESULT, result);
    push_specific_regs(tracee, false);
}

static int handle_seccomp_event_common(Tracee *restrict tracee);

int handle_seccomp_event(Tracee* restrict tracee) {
    if (UNLIKELY(fetch_regs(tracee) < 0)) {
        tracee->restore_sysarg1_after_sigsys = false;
        return SIGSYS;
    }

#if defined(ARCH_ARM_EABI) || defined(ARCH_ARM64)
    /* 上游 cd02c79：本次 SIGSYS 前跑过合成 sysexit 并 poke 了
     * SYSARG_RESULT（ARM/ARM64 上即 SYSARG_1）。被拦截 syscall 的
     * 首参数（路径指针、setresgid 的 rgid 等）已被伪结果覆盖——从
     * 入口快照恢复，保证 SIGSYS 模拟与 *at 风格重启读到真参数。
     * sysnum 相等守卫防止无关旧 syscall 的 ORIGINAL 泄漏进来。 */
    if (tracee->restore_sysarg1_after_sigsys
        && get_sysnum(tracee, ORIGINAL) == get_sysnum(tracee, CURRENT))
        poke_reg(tracee, SYSARG_1, peek_reg(tracee, ORIGINAL, SYSARG_1));
#endif
    tracee->restore_sysarg1_after_sigsys = false;

    tracee->status = 0;
    tracee->restore_original_regs = false;
    save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);
    return handle_seccomp_event_common(tracee);
}

void fix_and_restart_enosys_syscall(Tracee* restrict tracee) {
    tracee->status = 0;
    tracee->restore_original_regs = false;
    memcpy(&tracee->_regs[CURRENT], &tracee->_regs[ORIGINAL], sizeof(tracee->_regs[CURRENT]));
    save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);
    handle_seccomp_event_common(tracee);
}

static int handle_seccomp_event_common(Tracee *restrict tracee) {
    int status = notify_extensions(tracee, SIGSYS_OCC, 0, 0);
    if (UNLIKELY(status < 0)) {
        set_result_after_seccomp(tracee, status);
        return 0;
    }
    if (status >= 1) {
        set_result_after_seccomp(tracee, peek_reg(tracee, CURRENT, SYSARG_RESULT));
        return 0;
    }

    const Sysnum sysnum = get_sysnum(tracee, CURRENT);
    switch (sysnum) {
        case PR_open:
            TRANSFORM_TO_AT_SYS(PR_openat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)),
                poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3)));
            break;
        case PR_symlink:
            TRANSFORM_TO_AT_SYS(PR_symlinkat, peek_reg(tracee, CURRENT, SYSARG_1), AT_FDCWD,
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)));
            break;
        case PR_link:
            TRANSFORM_TO_AT_SYS(PR_linkat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, AT_FDCWD),
                poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2)),
                poke_reg(tracee, SYSARG_5, 0));
            break;
        case PR_chmod:
            TRANSFORM_TO_AT_SYS(PR_fchmodat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)),
                poke_reg(tracee, SYSARG_4, 0));
            break;
        case PR_chown:
        case PR_lchown:
        case PR_chown32:
        case PR_lchown32: {
            const int flag = (sysnum == PR_lchown || sysnum == PR_lchown32) ? AT_SYMLINK_NOFOLLOW : 0;
            TRANSFORM_TO_AT_SYS(PR_fchownat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)),
                poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_3)),
                poke_reg(tracee, SYSARG_5, flag));
            break;
        }
        case PR_unlink:
        case PR_rmdir: {
            const int flag = (sysnum == PR_rmdir) ? AT_REMOVEDIR : 0;
            TRANSFORM_TO_AT_SYS(PR_unlinkat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, flag));
            break;
        }
        case PR_stat:
        case PR_lstat: {
            const int flag = (sysnum == PR_lstat) ? AT_SYMLINK_NOFOLLOW : 0;
            TRANSFORM_TO_AT_SYS(PR_newfstatat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)),
                poke_reg(tracee, SYSARG_4, flag));
            break;
        }
        case PR_access:
            TRANSFORM_TO_AT_SYS(PR_faccessat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)),
                poke_reg(tracee, SYSARG_4, 0));
            break;
        case PR_mkdir:
            TRANSFORM_TO_AT_SYS(PR_mkdirat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2)));
            break;
        case PR_rename:
            TRANSFORM_TO_AT_SYS(PR_renameat, AT_FDCWD, peek_reg(tracee, CURRENT, SYSARG_1),
                poke_reg(tracee, SYSARG_3, AT_FDCWD),
                poke_reg(tracee, SYSARG_4, peek_reg(tracee, CURRENT, SYSARG_2)));
            break;
        case PR_accept:
            transform_simple_syscall(tracee, PR_accept4, 0, -1, -1);
            break;
        case PR_openat2: {
            /* 外层 seccomp 拒绝 openat2 时转 openat（上游 114a7c6 移植）：
             * 这样调用能在外层策略下存活，且重启动后路径会被翻译。 */
            struct proot_open_how how = {};
            word_t how_size = peek_reg(tracee, CURRENT, SYSARG_4);
            if (how_size > sizeof(how))
                how_size = sizeof(how);
            status = read_data(tracee, &how, peek_reg(tracee, CURRENT, SYSARG_3), how_size);
            if (status < 0) {
                set_result_after_seccomp(tracee, status);
                break;
            }
            tracee->openat2_resolve_in_root =
                (how.resolve & RESOLVE_IN_ROOT) != 0;
            set_sysnum(tracee, PR_openat);
            poke_reg(tracee, SYSARG_3, how.flags);
            poke_reg(tracee, SYSARG_4, how.mode);
            restart_syscall_after_seccomp(tracee);
            break;
        }
        case PR_send:
            transform_simple_syscall(tracee, PR_sendto, -1, 0, 0);
            break;
        case PR_recv:
            transform_simple_syscall(tracee, PR_recvfrom, -1, 0, 0);
            break;
        case PR_waitpid:
            transform_simple_syscall(tracee, PR_wait4, 0, -1, -1);
            break;
        case PR_pipe:
            transform_simple_syscall(tracee, PR_pipe2, 0, -1, -1);
            break;
        case PR_dup2:
            transform_simple_syscall(tracee, PR_dup3, 0, -1, -1);
            break;
        case PR_epoll_wait:
            transform_simple_syscall(tracee, PR_epoll_pwait, -1, 0, 0);
            break;
        case PR_setgroups:
        case PR_setgroups32:
            set_result_after_seccomp(tracee, 0);
            break;

        /* 上游 e754452：Android 父进程 seccomp 常 trap mount/umount/
         * pivot_root/unshare/setns，这里镜像 enter.c 的模拟，让
         * bubblewrap 这类沙箱工具能继续。 */
        case PR_mount:
            apply_emulated_mount(tracee);
            set_result_after_seccomp(tracee, 0);
            break;
        case PR_pivot_root:
            apply_emulated_pivot_root(tracee);
            set_result_after_seccomp(tracee, 0);
            break;
        case PR_umount:
        case PR_umount2:
            apply_emulated_umount(tracee);
            set_result_after_seccomp(tracee, 0);
            break;
        case PR_unshare:
        case PR_setns:
            set_result_after_seccomp(tracee, 0);
            break;

        case PR_getpgrp:
            set_result_after_seccomp(tracee, getpgid(tracee->pid));
            break;
        case PR_time: {
            const time_t t = time(NULL);
            const word_t addr = peek_reg(tracee, CURRENT, SYSARG_1);
            if (addr != 0) poke_word(tracee, addr, t);
            set_result_after_seccomp(tracee, errno ? -EFAULT : t);
            break;
        }
        case PR_statx:
            set_result_after_seccomp(tracee, handle_statx_syscall(tracee, true));
            break;
        case PR_set_robust_list:
            set_result_after_seccomp(tracee, -ENOSYS);
            break;
        case PR_statfs: {
            char original[PATH_MAX], path[PATH_MAX], devshm_path[PATH_MAX];
            const int size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_1), PATH_MAX);
            if (UNLIKELY(size < 0 || size >= PATH_MAX)) {
                set_result_after_seccomp(tracee, size < 0 ? size : -ENAMETOOLONG);
                break;
            }
            translate_path(tracee, path, AT_FDCWD, original, true);
            struct statfs64 my_statfs64;
            if (UNLIKELY(statfs64(path, &my_statfs64) < 0)) {
                set_result_after_seccomp(tracee, -errno);
                break;
            }
            if (translate_path(tracee, devshm_path, AT_FDCWD, "/dev/shm", true) >= 0) {
                const Comparison cmp = compare_paths(devshm_path, path);
                if (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX)
                    my_statfs64.f_type = 0x01021994;
            }
            if (UNLIKELY((my_statfs64.f_blocks | my_statfs64.f_bfree | my_statfs64.f_bavail |
                          my_statfs64.f_bsize | my_statfs64.f_frsize | my_statfs64.f_files |
                          my_statfs64.f_ffree) & 0xffffffff00000000ULL)) {
                set_result_after_seccomp(tracee, -EOVERFLOW);
                break;
            }
            struct compat_statfs my_statfs;
            memcpy(&my_statfs, &my_statfs64, sizeof(struct compat_statfs));
            memset(my_statfs.f_spare, 0, sizeof(my_statfs.f_spare));
            const int ret = write_data(tracee, peek_reg(tracee, CURRENT, SYSARG_2), &my_statfs, sizeof(struct compat_statfs));
            set_result_after_seccomp(tracee, ret < 0 ? ret : 0);
            break;
        }
        case PR_utimes: {
            const word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            const word_t tp = peek_reg(tracee, CURRENT, SYSARG_2);
            struct timespec timens[2];
            if (tp != 0) {
                struct timeval times[2];
                if (UNLIKELY(read_data(tracee, times, tp, sizeof(times)) < 0)) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
                timens[0] = (struct timespec){.tv_sec = times[0].tv_sec, .tv_nsec = times[0].tv_usec * 1000};
                timens[1] = (struct timespec){.tv_sec = times[1].tv_sec, .tv_nsec = times[1].tv_usec * 1000};
                const int ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
                if (UNLIKELY(ret < 0)) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
            }
            TRANSFORM_TO_AT_SYS(PR_utimensat, AT_FDCWD, path,
                poke_reg(tracee, SYSARG_3, tp),
                poke_reg(tracee, SYSARG_4, 0));
            break;
        }
        case PR_utime: {
            const word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            const word_t buf = peek_reg(tracee, CURRENT, SYSARG_2);
            struct timespec timens[2];
            if (buf != 0) {
                struct utimbuf times;
                if (UNLIKELY(read_data(tracee, &times, buf, sizeof(times)) < 0)) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
                timens[0] = (struct timespec){.tv_sec = times.actime, .tv_nsec = 0};
                timens[1] = (struct timespec){.tv_sec = times.modtime, .tv_nsec = 0};
                const int ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
                if (UNLIKELY(ret < 0)) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
            }
            TRANSFORM_TO_AT_SYS(PR_utimensat, AT_FDCWD, path,
                poke_reg(tracee, SYSARG_3, buf),
                poke_reg(tracee, SYSARG_4, 0));
            break;
        }
        case PR_select: {
            const word_t timeval_arg = peek_reg(tracee, CURRENT, SYSARG_5);
            word_t timespec_arg = 0;
            if (timeval_arg != 0) {
                struct timeval tv;
                if (UNLIKELY(read_data(tracee, &tv, timeval_arg, sizeof(tv)) < 0 || tv.tv_usec >= 1000000 || tv.tv_usec < 0)) {
                    set_result_after_seccomp(tracee, tv.tv_usec < 0 ? -EINVAL : -EFAULT);
                    break;
                }
                struct timespec ts = {.tv_sec = tv.tv_sec, .tv_nsec = tv.tv_usec * 1000};
                timespec_arg = alloc_mem(tracee, sizeof(ts));
                if (UNLIKELY(write_data(tracee, timespec_arg, &ts, sizeof(ts)) < 0)) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
            }
            transform_simple_syscall(tracee, PR_pselect6, timespec_arg, 0, -1);
            break;
        }
        case PR_poll: {
            const int ms_arg = (int)peek_reg(tracee, CURRENT, SYSARG_3);
            word_t timespec_arg = 0;
            if (ms_arg >= 0) {
                struct timespec ts = {.tv_sec = ms_arg / 1000, .tv_nsec = (ms_arg % 1000) * 1000000};
                timespec_arg = alloc_mem(tracee, sizeof(ts));
                if (UNLIKELY(write_data(tracee, timespec_arg, &ts, sizeof(ts)) < 0)) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
            }
            transform_simple_syscall(tracee, PR_ppoll, timespec_arg, 0, 0);
            break;
        }
        case PR_ftruncate: {
            if (detranslate_sysnum(get_abi(tracee), PR_ftruncate64) == SYSCALL_AVOIDER) {
                set_result_after_seccomp(tracee, -ENOSYS);
                break;
            }
            set_sysnum(tracee, PR_ftruncate64);
            poke_reg(tracee, SYSARG_2, 0);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            restart_syscall_after_seccomp(tracee);
            break;
        }
        case PR_setresuid:
        case PR_setresgid: {
            uid_t r, e, s;
            int ret = (sysnum == PR_setresuid) ? getresuid(&r, &e, &s) : getresgid((gid_t*)&r, (gid_t*)&e, (gid_t*)&s);
            if (UNLIKELY(ret != 0)) {
                set_result_after_seccomp(tracee, -EPERM);
                break;
            }
            const uid_t arg_r = peek_reg(tracee, CURRENT, SYSARG_1);
            const uid_t arg_e = peek_reg(tracee, CURRENT, SYSARG_2);
            const uid_t arg_s = peek_reg(tracee, CURRENT, SYSARG_3);
            ret = ((arg_r != (uid_t)-1 && arg_r != r) ||
                   (arg_e != (uid_t)-1 && arg_e != e) ||
                   (arg_s != (uid_t)-1 && arg_s != s)) ? -EPERM : 0;
            set_result_after_seccomp(tracee, ret);
            break;
        }
        default:
            set_result_after_seccomp(tracee, -ENOSYS);
    }
    return 0;
}
