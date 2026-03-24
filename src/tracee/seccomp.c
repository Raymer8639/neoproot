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

// 直接在这里定义，不再跨文件
void restart_syscall_after_seccomp(Tracee* tracee) {
    word_t instr_pointer;
    tracee->restore_original_regs_after_seccomp_event = true;
    tracee->restart_how = PTRACE_SYSCALL;

    instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER) - get_systrap_size(tracee);
    poke_reg(tracee, INSTR_POINTER, instr_pointer);

    push_specific_regs(tracee, false);
}

void set_result_after_seccomp(Tracee *tracee, word_t result) {
    VERBOSE(tracee, 3, "Setting result after SIGSYS to 0x%lx", result);
    poke_reg(tracee, SYSARG_RESULT, result);
    push_specific_regs(tracee, false);
}

static int handle_seccomp_event_common(Tracee *tracee);

int handle_seccomp_event(Tracee* tracee)
{
    int ret;
    tracee->status = 0;
    tracee->restore_original_regs = false;

    ret = fetch_regs(tracee);
    if (ret != 0) {
        VERBOSE(tracee, 1, "Couldn't fetch regs on seccomp SIGSYS");
        return SIGSYS;
    }

    save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);
    print_current_regs(tracee, 3, "seccomp SIGSYS");

    return handle_seccomp_event_common(tracee);
}

void fix_and_restart_enosys_syscall(Tracee* tracee)
{
    tracee->status = 0;
    tracee->restore_original_regs = false;
    memcpy(&tracee->_regs[CURRENT], &tracee->_regs[ORIGINAL], sizeof(tracee->_regs[CURRENT]));
    save_current_regs(tracee, ORIGINAL_SECCOMP_REWRITE);
    handle_seccomp_event_common(tracee);
}

static int handle_seccomp_event_common(Tracee *tracee)
{
    int ret;
    int status;
    Sysnum sysnum = get_sysnum(tracee, CURRENT);

    status = notify_extensions(tracee, SIGSYS_OCC, 0, 0);
    if (status < 0) {
        set_result_after_seccomp(tracee, status);
        return 0;
    }
    if (status >= 1) {
        if (status == 1)
            set_result_after_seccomp(tracee, 0);
        return 0;
    }

    switch (sysnum) {
        case PR_open: {
            word_t path  = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t flags = peek_reg(tracee, CURRENT, SYSARG_2);
            word_t mode  = peek_reg(tracee, CURRENT, SYSARG_3);

            set_sysnum(tracee, PR_openat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, flags);
            poke_reg(tracee, SYSARG_4, mode);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_accept:
            set_sysnum(tracee, PR_accept4);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_setgroups:
        case PR_setgroups32:
            set_result_after_seccomp(tracee, 0);
            break;

        case PR_getpgrp:
            set_result_after_seccomp(tracee, getpgid(tracee->pid));
            break;

        case PR_symlink: {
            word_t target = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t linkpath = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_symlinkat);
            poke_reg(tracee, SYSARG_1, target);
            poke_reg(tracee, SYSARG_2, AT_FDCWD);
            poke_reg(tracee, SYSARG_3, linkpath);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_link: {
            word_t oldpath = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t newpath = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_linkat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, oldpath);
            poke_reg(tracee, SYSARG_3, AT_FDCWD);
            poke_reg(tracee, SYSARG_4, newpath);
            poke_reg(tracee, SYSARG_5, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_chmod: {
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t mode = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_fchmodat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, mode);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_chown:
        case PR_lchown:
        case PR_chown32:
        case PR_lchown32: {
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t uid  = peek_reg(tracee, CURRENT, SYSARG_2);
            word_t gid  = peek_reg(tracee, CURRENT, SYSARG_3);
            int flag = (sysnum == PR_lchown || sysnum == PR_lchown32) ? AT_SYMLINK_NOFOLLOW : 0;

            set_sysnum(tracee, PR_fchownat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, uid);
            poke_reg(tracee, SYSARG_4, gid);
            poke_reg(tracee, SYSARG_5, flag);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_unlink:
        case PR_rmdir: {
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            int flag = (sysnum == PR_rmdir) ? AT_REMOVEDIR : 0;

            set_sysnum(tracee, PR_unlinkat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, flag);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_send:
            set_sysnum(tracee, PR_sendto);
            poke_reg(tracee, SYSARG_5, 0);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_recv:
            set_sysnum(tracee, PR_recvfrom);
            poke_reg(tracee, SYSARG_5, 0);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_waitpid:
            set_sysnum(tracee, PR_wait4);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_statfs:
        {
            int size;
            char path[PATH_MAX];
            char original[PATH_MAX];
            char devshm_path[PATH_MAX];
            struct statfs64 my_statfs64;
            struct compat_statfs my_statfs;

            size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_1), PATH_MAX);
            if (size < 0 || size >= PATH_MAX) {
                set_result_after_seccomp(tracee, size < 0 ? size : -ENAMETOOLONG);
                break;
            }

            translate_path(tracee, path, AT_FDCWD, original, true);
            errno = 0;
            if (statfs64(path, &my_statfs64) < 0) {
                set_result_after_seccomp(tracee, -errno);
                break;
            }

            if (translate_path(tracee, devshm_path, AT_FDCWD, "/dev/shm", true) >= 0) {
                Comparison comparison = compare_paths(devshm_path, path);
                if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX)
                    my_statfs64.f_type = 0x01021994;
            }

            if ((my_statfs64.f_blocks | my_statfs64.f_bfree | my_statfs64.f_bavail |
                 my_statfs64.f_bsize | my_statfs64.f_frsize | my_statfs64.f_files |
                 my_statfs64.f_ffree) & 0xffffffff00000000ULL) {
                set_result_after_seccomp(tracee, -EOVERFLOW);
                break;
            }

            memcpy(&my_statfs, &my_statfs64, sizeof(struct compat_statfs));
            memset(my_statfs.f_spare, 0, sizeof(my_statfs.f_spare));

            ret = write_data(tracee, peek_reg(tracee, CURRENT, SYSARG_2), &my_statfs, sizeof(struct compat_statfs));
            set_result_after_seccomp(tracee, ret < 0 ? ret : 0);
            break;
        }

        case PR_utimes:
        {
            struct timeval times[2];
            struct timespec timens[2];
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t tp   = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_utimensat);

            if (tp != 0) {
                ret = read_data(tracee, times, tp, sizeof(times));
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
                timens[0].tv_sec = (time_t)times[0].tv_sec;
                timens[0].tv_nsec = (long)times[0].tv_usec * 1000;
                timens[1].tv_sec = (time_t)times[1].tv_sec;
                timens[1].tv_nsec = (long)times[1].tv_usec * 1000;

                ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
            }

            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, tp);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_utime:
        {
            struct utimbuf times;
            struct timespec timens[2];
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t buf  = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_utimensat);

            if (buf != 0) {
                ret = read_data(tracee, &times, buf, sizeof(times));
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
                timens[0].tv_sec = (time_t)times.actime;
                timens[0].tv_nsec = 0;
                timens[1].tv_sec = (time_t)times.modtime;
                timens[1].tv_nsec = 0;

                ret = set_sysarg_data(tracee, timens, sizeof(timens), SYSARG_2);
                if (ret < 0) {
                    set_result_after_seccomp(tracee, ret);
                    break;
                }
            }

            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, buf);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_stat:
        case PR_lstat: {
            word_t path    = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t statbuf = peek_reg(tracee, CURRENT, SYSARG_2);
            int flag = (sysnum == PR_lstat) ? AT_SYMLINK_NOFOLLOW : 0;

            set_sysnum(tracee, PR_newfstatat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, statbuf);
            poke_reg(tracee, SYSARG_4, flag);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_pipe:
            set_sysnum(tracee, PR_pipe2);
            poke_reg(tracee, SYSARG_2, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_dup2:
            set_sysnum(tracee, PR_dup3);
            poke_reg(tracee, SYSARG_3, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_access: {
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t mode = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_faccessat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, mode);
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_mkdir: {
            word_t path = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t mode = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_mkdirat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, path);
            poke_reg(tracee, SYSARG_3, mode);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_rename: {
            word_t oldpath = peek_reg(tracee, CURRENT, SYSARG_1);
            word_t newpath = peek_reg(tracee, CURRENT, SYSARG_2);

            set_sysnum(tracee, PR_renameat);
            poke_reg(tracee, SYSARG_1, AT_FDCWD);
            poke_reg(tracee, SYSARG_2, oldpath);
            poke_reg(tracee, SYSARG_3, AT_FDCWD);
            poke_reg(tracee, SYSARG_4, newpath);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_select:
        {
            word_t timeval_arg = peek_reg(tracee, CURRENT, SYSARG_5);
            word_t timespec_arg = 0;

            if (timeval_arg != 0) {
                struct timeval tv = {};
                if (read_data(tracee, &tv, timeval_arg, sizeof(tv))) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
                if (tv.tv_usec >= 1000000 || tv.tv_usec < 0) {
                    set_result_after_seccomp(tracee, -EINVAL);
                    break;
                }
                struct timespec ts = {
                    .tv_sec = tv.tv_sec,
                    .tv_nsec = tv.tv_usec * 1000
                };
                timespec_arg = alloc_mem(tracee, sizeof(ts));
                if (write_data(tracee, timespec_arg, &ts, sizeof(ts))) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
            }

            set_sysnum(tracee, PR_pselect6);
            poke_reg(tracee, SYSARG_5, timespec_arg);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_poll:
        {
            int ms_arg = (int)peek_reg(tracee, CURRENT, SYSARG_3);
            word_t timespec_arg = 0;

            if (ms_arg >= 0) {
                struct timespec ts = {
                    .tv_sec = ms_arg / 1000,
                    .tv_nsec = (ms_arg % 1000) * 1000000
                };
                timespec_arg = alloc_mem(tracee, sizeof(ts));
                if (write_data(tracee, timespec_arg, &ts, sizeof(ts))) {
                    set_result_after_seccomp(tracee, -EFAULT);
                    break;
                }
            }

            set_sysnum(tracee, PR_ppoll);
            poke_reg(tracee, SYSARG_3, timespec_arg);
            poke_reg(tracee, SYSARG_4, 0);
            poke_reg(tracee, SYSARG_5, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_epoll_wait:
            set_sysnum(tracee, PR_epoll_pwait);
            poke_reg(tracee, SYSARG_5, 0);
            poke_reg(tracee, SYSARG_6, 0);
            restart_syscall_after_seccomp(tracee);
            break;

        case PR_time:
        {
            time_t t = time(NULL);
            word_t addr = peek_reg(tracee, CURRENT, SYSARG_1);
            errno = 0;
            if (addr != 0)
                poke_word(tracee, addr, t);
            set_result_after_seccomp(tracee, errno ? -EFAULT : t);
            break;
        }

        case PR_statx:
            set_result_after_seccomp(tracee, handle_statx_syscall(tracee, true));
            break;

        case PR_ftruncate:
        {
            if (detranslate_sysnum(get_abi(tracee), PR_ftruncate64) == SYSCALL_AVOIDER) {
                set_result_after_seccomp(tracee, -ENOSYS);
                break;
            }
            set_sysnum(tracee, PR_ftruncate64);
            poke_reg(tracee, SYSARG_2, 0);
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_4, 0);
            restart_syscall_after_seccomp(tracee);
            break;
        }

        case PR_setresuid:
        case PR_setresgid:
        {
            uid_t ruid, euid, suid;
            if (sysnum == PR_setresuid) {
                if (getresuid(&ruid, &euid, &suid) != 0) {
                    set_result_after_seccomp(tracee, -EPERM);
                    break;
                }
            } else {
                if (getresgid((gid_t*)&ruid, (gid_t*)&euid, (gid_t*)&suid) != 0) {
                    set_result_after_seccomp(tracee, -EPERM);
                    break;
                }
            }

            uid_t arg_r = peek_reg(tracee, CURRENT, SYSARG_1);
            uid_t arg_e = peek_reg(tracee, CURRENT, SYSARG_2);
            uid_t arg_s = peek_reg(tracee, CURRENT, SYSARG_3);

            int ret = ((arg_r != (uid_t)-1 && arg_r != ruid) ||
                       (arg_e != (uid_t)-1 && arg_e != euid) ||
                       (arg_s != (uid_t)-1 && arg_s != suid)) ? -EPERM : 0;
            set_result_after_seccomp(tracee, ret);
            break;
        }

        case PR_set_robust_list:
        default:
            set_result_after_seccomp(tracee, -ENOSYS);
    }

    return 0;
}
