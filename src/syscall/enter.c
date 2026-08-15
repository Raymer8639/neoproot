#include <errno.h>
#include <talloc.h>
#include <sys/un.h>
#include <linux/net.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/prctl.h>
#include <termios.h>
#include <stddef.h>
#include <stdbool.h>

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "syscall/heap.h"
#include "extension/extension.h"
#include "compat.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "path/path.h"
#include "path/canon.h"
#include "path/binding.h"
#include "arch.h"
#include "attribute.h"

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static int translate_path2(Tracee *tracee, int dir_fd, char path[PATH_MAX], Reg reg, Type type);
static int translate_sysarg(Tracee *tracee, Reg reg, Type type);

/*
 * ro bind（--bind=host:guest:ro）只读检查：
 * 路径落在只读挂载下且是写操作 → 返回 -EROFS。
 * 必须在路径翻译（guest → host）之前检查，此时 sysarg 还是 guest 视角。
 */
static int check_bind_readonly(const Tracee *restrict tracee, const char *restrict guest_path)
{
    const Binding *b = get_binding(tracee, GUEST, guest_path);
    return (b != NULL && b->readonly) ? -EROFS : 0;
}

static int translate_path2(Tracee *tracee, int dir_fd, char path[PATH_MAX], Reg reg, Type type)
{
    char new_path[PATH_MAX];
    int status;

    if (path[0] == '\0')
        return 0;

    status = translate_path(tracee, new_path, dir_fd, path, type != SYMLINK);
    if (status < 0)
        return status;

    return set_sysarg_path(tracee, new_path, reg);
}

static int translate_sysarg(Tracee *tracee, Reg reg, Type type)
{
    char old_path[PATH_MAX];
    int status;

    status = get_sysarg_path(tracee, old_path, reg);
    if (status < 0)
        return status;

    return translate_path2(tracee, AT_FDCWD, old_path, reg, type);
}

int translate_syscall_enter(Tracee *tracee)
{
    int flags;
    int dirfd;
    int olddirfd;
    int newdirfd;
    int status;
    int status2;
    char path[PATH_MAX];
    char oldpath[PATH_MAX];
    char newpath[PATH_MAX];
    word_t syscall_number;
    bool special = false;

    status = notify_extensions(tracee, SYSCALL_ENTER_START, 0, 0);
    if (status < 0)
        goto end;
    if (status > 0)
        return 0;

    syscall_number = get_sysnum(tracee, ORIGINAL);

    switch (syscall_number) {
    default:
        status = 0;
        break;

    case PR_execve:
        status = translate_execve_enter(tracee);
        break;

    case PR_execveat:
        if ((int) peek_reg(tracee, CURRENT, SYSARG_1) == AT_FDCWD) {
            set_sysnum(tracee, PR_execve);
            poke_reg(tracee, SYSARG_1, peek_reg(tracee, CURRENT, SYSARG_2));
            poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_3));
            poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_4));
        } else {
            note(tracee, ERROR, SYSTEM, "execveat() with non-AT_FDCWD fd is not currently supported");
            status = -ENOSYS;
            break;
        }
        status = translate_execve_enter(tracee);
        break;

    case PR_ptrace:
        status = translate_ptrace_enter(tracee);
        break;

    case PR_wait4:
    case PR_waitpid:
        status = translate_wait_enter(tracee);
        break;

    case PR_brk:
        translate_brk_enter(tracee);
        status = 0;
        break;

    case PR_getcwd:
        set_sysnum(tracee, PR_void);
        status = 0;
        break;

    case PR_fchdir:
    case PR_chdir: {
        struct stat statl;
        char *tmp;

        if (syscall_number == PR_chdir) {
            status = get_sysarg_path(tracee, path, SYSARG_1);
            if (status < 0)
                break;

            status = join_paths(2, oldpath, path, ".");
            if (status < 0)
                break;

            dirfd = AT_FDCWD;
        }
        else {
            strcpy(oldpath, ".");
            dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
        }

        status = translate_path(tracee, path, dirfd, oldpath, true);
        if (status < 0)
            break;

        status = lstat(path, &statl);
        if (status < 0)
            break;

        if ((statl.st_mode & S_IXUSR) == 0) {
            status = -EACCES;
            break;
        }

        status = detranslate_path(tracee, path, NULL);
        if (status < 0)
            break;

        chop_finality(path);

        tmp = talloc_strdup(tracee->fs, path);
        if (tmp == NULL) {
            status = -ENOMEM;
            break;
        }
        TALLOC_FREE(tracee->fs->cwd);

        tracee->fs->cwd = tmp;
        talloc_set_name_const(tracee->fs->cwd, "$cwd");

        set_sysnum(tracee, PR_void);
        status = 0;
        break;
    }

    case PR_bind:
    case PR_connect: {
        word_t address;
        word_t size;

        address = peek_reg(tracee, CURRENT, SYSARG_2);
        size    = peek_reg(tracee, CURRENT, SYSARG_3);

        status = translate_socketcall_enter(tracee, &address, size);
        if (status <= 0)
            break;

        poke_reg(tracee, SYSARG_2, address);
        poke_reg(tracee, SYSARG_3, sizeof(struct sockaddr_un));

        status = 0;
        break;
    }

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * sizeof_word(tracee))

#define PEEK_WORD(addr, forced_errno)       \
    peek_word(tracee, addr);        \
    if (errno != 0) {           \
        status = forced_errno ?: -errno; \
        break;              \
    }

#define POKE_WORD(addr, value)          \
    poke_word(tracee, addr, value);     \
    if (errno != 0) {           \
        status = -errno;        \
        break;              \
    }

    case PR_accept:
    case PR_accept4:
        if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0) {
            status = 0;
            break;
        }
        special = true;
        /* fall through */
    case PR_getsockname:
    case PR_getpeername:{
        int size;

        size = (int) PEEK_WORD(peek_reg(tracee, ORIGINAL, SYSARG_3), special ? -EINVAL : 0);
        poke_reg(tracee, SYSARG_6, size);

        status = 0;
        break;
    }

    case PR_socketcall: {
        word_t args_addr;
        word_t sock_addr_saved;
        word_t sock_addr;
        word_t size_addr;
        word_t size;

        args_addr = peek_reg(tracee, CURRENT, SYSARG_2);

        switch (peek_reg(tracee, CURRENT, SYSARG_1)) {
        case SYS_BIND:
        case SYS_CONNECT:
            status = 1;
            break;

        case SYS_ACCEPT:
        case SYS_ACCEPT4:
            sock_addr = PEEK_WORD(SYSARG_ADDR(2), 0);
            if (sock_addr == 0) {
                status = 0;
                break;
            }
            special = true;
            /* fall through */
        case SYS_GETSOCKNAME:
        case SYS_GETPEERNAME:
            size_addr =  PEEK_WORD(SYSARG_ADDR(3), 0);
            size = (int) PEEK_WORD(size_addr, special ? -EINVAL : 0);

            poke_reg(tracee, SYSARG_6, size);
            status = 0;
            break;

        default:
            status = 0;
            break;
        }

        if (status <= 0)
            break;

        sock_addr = PEEK_WORD(SYSARG_ADDR(2), 0);
        size      = PEEK_WORD(SYSARG_ADDR(3), 0);

        sock_addr_saved = sock_addr;
        status = translate_socketcall_enter(tracee, &sock_addr, size);
        if (status <= 0)
            break;

        poke_reg(tracee, SYSARG_5, sock_addr_saved);
        poke_reg(tracee, SYSARG_6, size);

        POKE_WORD(SYSARG_ADDR(2), sock_addr);
        POKE_WORD(SYSARG_ADDR(3), sizeof(struct sockaddr_un));

        status = 0;
        break;
    }

#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

    case PR_access:
    case PR_acct:
    case PR_chroot:
    case PR_getxattr:
    case PR_listxattr:
    case PR_oldstat:
    case PR_stat:
    case PR_stat64:
    case PR_statfs:
    case PR_statfs64:
    case PR_swapoff:
    case PR_swapon:
    case PR_uselib:
        status = translate_sysarg(tracee, SYSARG_1, REGULAR);
        break;

    /* 写操作：先做 ro bind 只读检查 */
    case PR_chmod:
    case PR_chown:
    case PR_chown32:
    case PR_mknod:
    case PR_creat:
    case PR_removexattr:
    case PR_setxattr:
    case PR_truncate:
    case PR_truncate64:
    case PR_umount:
    case PR_umount2:
    case PR_utime:
    case PR_utimes:
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;
        status = translate_sysarg(tracee, SYSARG_1, REGULAR);
        break;

    case PR_open:
        flags = peek_reg(tracee, CURRENT, SYSARG_2);

        if ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0) {
            status = get_sysarg_path(tracee, path, SYSARG_1);
            if (status < 0)
                break;
            status = check_bind_readonly(tracee, path);
            if (status < 0)
                break;
        }

        if (((flags & O_NOFOLLOW) != 0) || ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0))
            status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
        else
            status = translate_sysarg(tracee, SYSARG_1, REGULAR);
        break;

    case PR_fstatat64:
    case PR_newfstatat:
    case PR_name_to_handle_at:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;

        flags = (syscall_number == PR_name_to_handle_at)
            ? peek_reg(tracee, CURRENT, SYSARG_5)
            : peek_reg(tracee, CURRENT, SYSARG_4);

        if ((flags & AT_SYMLINK_NOFOLLOW) != 0)
            status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
        else
            status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
        break;

    /* 写操作：先做 ro bind 只读检查 */
    case PR_fchownat:
    case PR_utimensat:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;

        flags = (syscall_number == PR_fchownat)
            ? peek_reg(tracee, CURRENT, SYSARG_5)
            : peek_reg(tracee, CURRENT, SYSARG_4);
        if ((flags & AT_SYMLINK_NOFOLLOW) != 0)
            status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
        else
            status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
        break;

    case PR_faccessat:
    case PR_faccessat2:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;

        status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
        break;

    /* 写操作：先做 ro bind 只读检查 */
    case PR_fchmodat:
    case PR_futimesat:
    case PR_mknodat:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;

        status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
        break;

    case PR_inotify_add_watch:
        flags = peek_reg(tracee, CURRENT, SYSARG_3);

        if ((flags & IN_DONT_FOLLOW) != 0)
            status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
        else
            status = translate_sysarg(tracee, SYSARG_2, REGULAR);
        break;

    case PR_readlink:
    case PR_lgetxattr:
    case PR_llistxattr:
    case PR_lstat:
    case PR_lstat64:
    case PR_oldlstat:
        status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
        break;

    /* 写操作：先做 ro bind 只读检查 */
    case PR_lchown:
    case PR_lchown32:
    case PR_lremovexattr:
    case PR_lsetxattr:
    case PR_unlink:
    case PR_rmdir:
    case PR_mkdir:
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;
        status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
        break;

    case PR_pivot_root:
        status = translate_sysarg(tracee, SYSARG_1, REGULAR);
        if (status < 0)
            break;

        status = translate_sysarg(tracee, SYSARG_2, REGULAR);
        break;

    case PR_linkat:
        olddirfd = peek_reg(tracee, CURRENT, SYSARG_1);
        newdirfd = peek_reg(tracee, CURRENT, SYSARG_3);
        flags    = peek_reg(tracee, CURRENT, SYSARG_5);

        status = get_sysarg_path(tracee, oldpath, SYSARG_2);
        if (status < 0)
            break;

        status = get_sysarg_path(tracee, newpath, SYSARG_4);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, newpath);
        if (status < 0)
            break;

        if ((flags & AT_SYMLINK_FOLLOW) != 0)
            status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, REGULAR);
        else
            status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, SYMLINK);
        if (status < 0)
            break;

        status = translate_path2(tracee, newdirfd, newpath, SYSARG_4, SYMLINK);
        break;

    case PR_mount:
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;

        if (path[0] == '/' || path[0] == '.') {
            status = translate_path2(tracee, AT_FDCWD, path, SYSARG_1, REGULAR);
            if (status < 0)
                break;
        }

        status = translate_sysarg(tracee, SYSARG_2, REGULAR);
        break;

    case PR_openat2: {
        /* openat2(dirfd, pathname, open_how*, size) → 改写为 openat 再翻译
         * （上游 114a7c6 移植）：路径在 SYSARG_2 同 openat，flags/mode 在
         * open_how 结构里 → 搬进 SYSARG_3/4。how.resolve 标志丢弃：
         * RESOLVE_BENEATH 等会拒绝 neoproot 生成的绝对 host 路径，且
         * 路径限制本就由 rootfs 翻译保证。 */
        struct proot_open_how how = {};
        word_t how_size = peek_reg(tracee, CURRENT, SYSARG_4);
        if (how_size > sizeof(how))
            how_size = sizeof(how);
        status = read_data(tracee, &how, peek_reg(tracee, CURRENT, SYSARG_3), how_size);
        if (status < 0)
            break;
        set_sysnum(tracee, PR_openat);
        poke_reg(tracee, SYSARG_3, how.flags);
        poke_reg(tracee, SYSARG_4, how.mode);
    }
        /* fall through */
    case PR_openat:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);
        flags = peek_reg(tracee, CURRENT, SYSARG_3);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;

        if ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0) {
            status = check_bind_readonly(tracee, path);
            if (status < 0)
                break;
        }

        if (((flags & O_NOFOLLOW) != 0) || ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0))
            status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
        else
            status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
        break;
    case PR_readlinkat:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;

        status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
        break;

    /* 写操作：先做 ro bind 只读检查 */
    case PR_unlinkat:
    case PR_mkdirat:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;

        status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
        break;

    case PR_link:
    case PR_rename:
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;

        status = get_sysarg_path(tracee, newpath, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, newpath);
        if (status < 0)
            break;

        status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
        if (status < 0)
            break;

        status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
        break;

    case PR_renameat:
    case PR_renameat2:
        olddirfd = peek_reg(tracee, CURRENT, SYSARG_1);
        newdirfd = peek_reg(tracee, CURRENT, SYSARG_3);

        status = get_sysarg_path(tracee, oldpath, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, oldpath);
        if (status < 0)
            break;

        status = get_sysarg_path(tracee, newpath, SYSARG_4);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, newpath);
        if (status < 0)
            break;

        status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, SYMLINK);
        if (status < 0)
            break;

        status = translate_path2(tracee, newdirfd, newpath, SYSARG_4, SYMLINK);
        break;

    case PR_symlink:
        status = get_sysarg_path(tracee, newpath, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, newpath);
        if (status < 0)
            break;
        status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
        break;

    case PR_symlinkat:
        newdirfd = peek_reg(tracee, CURRENT, SYSARG_2);

        status = get_sysarg_path(tracee, newpath, SYSARG_3);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, newpath);
        if (status < 0)
            break;

        status = translate_path2(tracee, newdirfd, newpath, SYSARG_3, SYMLINK);
        break;

    case PR_statx:
        newdirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, newpath, SYSARG_2);
        if (status < 0)
            break;

        status = translate_path2(
            tracee,
            newdirfd,
            newpath,
            SYSARG_2,
            (peek_reg(tracee, CURRENT, SYSARG_3) & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR
        );
        break;

    case PR_prctl:
        if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_SET_DUMPABLE) {
            set_sysnum(tracee, PR_void);
            status = 0;
        }
        /* 上游 571a6c0：neoproot 在 execve 前必设 PR_SET_NO_NEW_PRIVS
         * （seccomp 过滤器前提），真实标志恒为 1——按 guest 自身意图
         * 回答 PR_GET_NO_NEW_PRIVS，并观察 guest 自发的 SET。 */
        if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_GET_NO_NEW_PRIVS) {
            poke_reg(tracee, SYSARG_RESULT, tracee->no_new_privs ? 1 : 0);
            set_sysnum(tracee, PR_void);
            status = 0;
        }
        if (peek_reg(tracee, CURRENT, SYSARG_1) == PR_SET_NO_NEW_PRIVS) {
            tracee->sysexit_pending = true;
            tracee->restart_how = PTRACE_SYSCALL;
        }
        break;

#ifdef __ANDROID__
    case PR_ioctl:
        if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETS + 2) {
            poke_reg(tracee, SYSARG_2, TCSETS + TCSANOW);
        }

        if (peek_reg(tracee, CURRENT, SYSARG_2) == TCGETS2) {
            poke_reg(tracee, SYSARG_2, TCGETS);
        }

        if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETS2) {
            poke_reg(tracee, SYSARG_2, TCSETS);
        }

        if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETSW2) {
            poke_reg(tracee, SYSARG_2, TCSETSW);
        }

        if (peek_reg(tracee, CURRENT, SYSARG_2) == TCSETSF2) {
            poke_reg(tracee, SYSARG_2, TCSETSF);
        }
        break;
#endif

    case PR_memfd_create:
        {
            char memfd_name[20] = {};
            if (read_string(tracee, memfd_name, peek_reg(tracee, CURRENT, SYSARG_1), sizeof(memfd_name) - 1) < 0) {
                break;
            }
            if (strncmp(memfd_name, "JITCode:", 8) == 0) {
                status = -EACCES;
            }
            if (strcmp(memfd_name, "opcache_lock") == 0) {
                status = -EACCES;
            }
            if (strncmp(memfd_name, "lib/apk/exec/", 13) == 0) {
                status = -EACCES;
            }
            break;
        }
    }

end:
    status2 = notify_extensions(tracee, SYSCALL_ENTER_END, status, 0);
    if (status2 < 0)
        status = status2;

    return status;
}
