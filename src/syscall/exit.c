#include <errno.h>
#include <sys/utsname.h>
#include <linux/net.h>
#include <linux/ioctl.h>
#include <string.h>

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "syscall/chain.h"
#include "syscall/heap.h"
#include "syscall/rlimit.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/seccomp.h"
#include "tracee/statx.h"
#include "path/path.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "arch.h"

void translate_syscall_exit(Tracee *tracee)
{
    word_t syscall_number;
    word_t syscall_result;
    int status;

    status = notify_extensions(tracee, SYSCALL_EXIT_START, 0, 0);
    if (status < 0) {
        poke_reg(tracee, SYSARG_RESULT, (word_t)status);
        goto end;
    }
    if (status > 0)
        return;

    if (tracee->status < 0) {
        poke_reg(tracee, SYSARG_RESULT, (word_t)tracee->status);
        goto end;
    }

    /* 纯 ARM64：SYSCALL_AVOIDER 无需 32bit 兼容 */
    if (peek_reg(tracee, MODIFIED, SYSARG_NUM) == SYSCALL_AVOIDER &&
        peek_reg(tracee, ORIGINAL, SYSARG_NUM) != peek_reg(tracee, MODIFIED, SYSARG_NUM))
    {
        poke_reg(tracee, SYSARG_RESULT, peek_reg(tracee, MODIFIED, SYSARG_RESULT));
    }

    syscall_number = get_sysnum(tracee, ORIGINAL);
    syscall_result = peek_reg(tracee, CURRENT, SYSARG_RESULT);

    switch (syscall_number) {
    case PR_brk:
        translate_brk_exit(tracee);
        goto end;

    case PR_getcwd: {
        char path[PATH_MAX];
        size_t new_size;
        size_t size;
        word_t output;

        size = (size_t)peek_reg(tracee, ORIGINAL, SYSARG_2);
        if (size == 0) {
            status = -EINVAL;
            break;
        }

        status = translate_path(tracee, path, AT_FDCWD, ".", false);
        if (status < 0)
            break;

        new_size = strlen(tracee->fs->cwd) + 1;
        if (size < new_size) {
            status = -ERANGE;
            break;
        }

        output = peek_reg(tracee, ORIGINAL, SYSARG_1);
        status = write_data(tracee, output, tracee->fs->cwd, new_size);
        if (status < 0)
            break;

        status = new_size;
        break;
    }

    case PR_accept:
    case PR_accept4:
        if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0)
            goto end;
        /* fall through */
    case PR_getsockname:
    case PR_getpeername: {
        word_t sock_addr;
        word_t size_addr;
        word_t max_size;

        if ((int)syscall_result < 0)
            goto end;

        sock_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
        size_addr = peek_reg(tracee, MODIFIED, SYSARG_3);
        max_size  = peek_reg(tracee, MODIFIED, SYSARG_6);

        status = translate_socketcall_exit(tracee, sock_addr, size_addr, max_size);
        if (status < 0)
            break;

        goto end;
    }

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * sizeof_word(tracee))
#define POKE_WORD(addr, value)    \
    poke_word(tracee, addr, value); \
    if (errno != 0) {            \
        status = -errno;         \
        break;                  \
    }
#define PEEK_WORD(addr)           \
    peek_word(tracee, addr);     \
    if (errno != 0) {            \
        status = -errno;         \
        break;                  \
    }

    case PR_socketcall: {
        word_t args_addr;
        word_t sock_addr;
        word_t size_addr;
        word_t max_size;

        args_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);

        switch (peek_reg(tracee, ORIGINAL, SYSARG_1)) {
        case SYS_ACCEPT:
        case SYS_ACCEPT4:
            sock_addr = PEEK_WORD(SYSARG_ADDR(2));
            if (sock_addr == 0)
                goto end;
            /* fall through */
        case SYS_GETSOCKNAME:
        case SYS_GETPEERNAME:
            status = 1;
            break;

        case SYS_BIND:
        case SYS_CONNECT:
            POKE_WORD(SYSARG_ADDR(2), peek_reg(tracee, MODIFIED, SYSARG_5));
            POKE_WORD(SYSARG_ADDR(3), peek_reg(tracee, MODIFIED, SYSARG_6));
            status = 0;
            break;

        default:
            status = 0;
            break;
        }

        if ((int)syscall_result < 0 || status == 0)
            goto end;
        if (status < 0)
            break;

        sock_addr = PEEK_WORD(SYSARG_ADDR(2));
        size_addr = PEEK_WORD(SYSARG_ADDR(3));
        max_size  = peek_reg(tracee, MODIFIED, SYSARG_6);

        status = translate_socketcall_exit(tracee, sock_addr, size_addr, max_size);
        if (status < 0)
            break;

        goto end;
    }

#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

    case PR_fchdir:
    case PR_chdir:
        status = 0;
        break;

    case PR_rename:
    case PR_renameat: {
        char old_path[PATH_MAX];
        char new_path[PATH_MAX];
        ssize_t old_length;
        ssize_t new_length;
        Comparison comparison;
        Reg old_reg;
        Reg new_reg;
        char *tmp;

        if ((int)syscall_result < 0)
            goto end;

        if (syscall_number == PR_rename) {
            old_reg = SYSARG_1;
            new_reg = SYSARG_2;
        } else {
            old_reg = SYSARG_2;
            new_reg = SYSARG_4;
        }

        status = read_path(tracee, old_path, peek_reg(tracee, MODIFIED, old_reg));
        if (status < 0)
            break;

        status = detranslate_path(tracee, old_path, NULL);
        if (status < 0)
            break;
        old_length = (status > 0) ? status - 1 : (ssize_t)strlen(old_path);

        comparison = compare_paths(old_path, tracee->fs->cwd);
        if (comparison != PATH1_IS_PREFIX && comparison != PATHS_ARE_EQUAL) {
            status = 0;
            break;
        }

        status = read_path(tracee, new_path, peek_reg(tracee, MODIFIED, new_reg));
        if (status < 0)
            break;

        status = detranslate_path(tracee, new_path, NULL);
        if (status < 0)
            break;
        new_length = (status > 0) ? status - 1 : (ssize_t)strlen(new_path);

        if (strlen(tracee->fs->cwd) >= PATH_MAX) {
            status = 0;
            break;
        }
        strcpy(old_path, tracee->fs->cwd);

        substitute_path_prefix(old_path, old_length, new_path, new_length);

        tmp = talloc_strdup(tracee->fs, old_path);
        if (tmp == NULL) {
            status = -ENOMEM;
            break;
        }

        TALLOC_FREE(tracee->fs->cwd);
        tracee->fs->cwd = tmp;

        status = 0;
        break;
    }

    case PR_readlink:
    case PR_readlinkat: {
        char referee[PATH_MAX];
        char referer[PATH_MAX];
        size_t old_size;
        size_t new_size;
        size_t max_size;
        word_t input;
        word_t output;

        if ((int)syscall_result < 0)
            goto end;

        old_size = syscall_result;

        if (syscall_number == PR_readlink) {
            output   = peek_reg(tracee, ORIGINAL, SYSARG_2);
            max_size = peek_reg(tracee, ORIGINAL, SYSARG_3);
            input    = peek_reg(tracee, MODIFIED, SYSARG_1);
        } else {
            output   = peek_reg(tracee, ORIGINAL, SYSARG_3);
            max_size = peek_reg(tracee, ORIGINAL, SYSARG_4);
            input    = peek_reg(tracee, MODIFIED, SYSARG_2);
        }

        if (max_size > PATH_MAX)
            max_size = PATH_MAX;
        if (max_size == 0) {
            status = -EINVAL;
            break;
        }

        status = read_data(tracee, referee, output, old_size);
        if (status < 0)
            break;
        referee[old_size] = '\0';

        status = read_path(tracee, referer, input);
        if (status < 0)
            break;
        if (status >= PATH_MAX) {
            status = -ENAMETOOLONG;
            break;
        }

        if (status == 1) {
            word_t dirfd = peek_reg(tracee, ORIGINAL, SYSARG_1);
            if (syscall_number == PR_readlink || dirfd < 0) {
                status = -EBADF;
                break;
            }
            status = readlink_proc_pid_fd(tracee->pid, dirfd, referer);
            if (status < 0)
                break;
        }

        status = detranslate_path(tracee, referee, referer);
        if (status < 0)
            break;
        if (status == 0)
            goto end;

        if ((size_t)status < max_size) {
            new_size = status - 1;
            status = write_data(tracee, output, referee, status);
        } else {
            new_size = max_size;
            status = write_data(tracee, output, referee, max_size);
        }
        if (status < 0)
            break;

        status = new_size;
        break;
    }

    case PR_execve:
    case PR_execveat:
        translate_execve_exit(tracee);
        goto end;

    case PR_ptrace:
        status = translate_ptrace_exit(tracee);
        break;

    case PR_wait4:
    case PR_waitpid:
        if (tracee->as_ptracer.waits_in != WAITS_IN_PROOT)
            goto end;
        status = translate_wait_exit(tracee);
        break;

    case PR_setrlimit:
    case PR_prlimit64:
        if ((int)syscall_result < 0)
            goto end;
        status = translate_setrlimit_exit(tracee, syscall_number == PR_prlimit64);
        if (status < 0)
            break;
        goto end;

    case PR_utime:
        if ((int)syscall_result == -ENOSYS)
            fix_and_restart_enosys_syscall(tracee);
        goto end;

    case PR_statfs:
    case PR_statfs64: {
        char devshm_path[PATH_MAX];
        char statfs_path[PATH_MAX];

        if (syscall_result != 0)
            goto end;

        if (translate_path(tracee, devshm_path, AT_FDCWD, "/dev/shm", true) < 0)
            goto end;

        if (read_path(tracee, statfs_path, peek_reg(tracee, MODIFIED, SYSARG_1)) < 0)
            goto end;

        Comparison cmp = compare_paths(devshm_path, statfs_path);
        if (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX) {
            word_t stat_addr = peek_reg(tracee, ORIGINAL,
                (syscall_number == PR_statfs64) ? SYSARG_3 : SYSARG_2);
            (void)write_data(tracee, stat_addr, "\x94\x19\x02\x01", 4);
        }
        goto end;
    }

    case PR_statx:
        status = handle_statx_syscall(tracee, false);
        break;

    case PR_ioctl:
        if (peek_reg(tracee, ORIGINAL, SYSARG_2) == _IOW(0x94, 9, int) &&
            (int)peek_reg(tracee, CURRENT, SYSARG_RESULT) == -EACCES)
        {
            poke_reg(tracee, SYSARG_RESULT, -EOPNOTSUPP);
        }
        goto end;

    default:
        goto end;
    }

    poke_reg(tracee, SYSARG_RESULT, (word_t)status);

end:
    status = notify_extensions(tracee, SYSCALL_EXIT_END, 0, 0);
    if (status < 0)
        poke_reg(tracee, SYSARG_RESULT, (word_t)status);
}
