#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <climits>
#include <cstdlib>

#include <talloc.h>
#include <sys/un.h>
#include <linux/net.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <termios.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "syscall/heap.h"
#include "extension/extension.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "path/path.h"
#include "path/canon.h"
#include "arch.h"
#include "attribute.h"

#ifdef __cplusplus
}
#endif

using reg_val_t = word_t;
using sysnum_t = word_t;

static int translate_path2(Tracee* tracee, int dir_fd, char path[PATH_MAX], Reg reg, Type type);
static int translate_sysarg(Tracee* tracee, Reg reg, Type type);

typedef int (*syscall_handler_t)(Tracee* tracee);

typedef struct {
    sysnum_t num;
    syscall_handler_t handler;
} SyscallHandlerEntry;

static const SyscallHandlerEntry syscall_handlers[] = {
    { PR_accept,        [](Tracee* t) -> int { return 0; } },
    { PR_accept4,       [](Tracee* t) -> int { return 0; } },
    { PR_access,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_acct,          [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_bind,          [](Tracee* t) -> int {
        reg_val_t addr = peek_reg(t, CURRENT, SYSARG_2);
        reg_val_t sz   = peek_reg(t, CURRENT, SYSARG_3);
        int ret = translate_socketcall_enter(t, &addr, sz);
        if (ret > 0) {
            poke_reg(t, SYSARG_2, addr);
            poke_reg(t, SYSARG_3, (reg_val_t)sizeof(struct sockaddr_un));
        }
        return 0;
    }},
    { PR_brk,           [](Tracee* t) -> int { translate_brk_enter(t); return 0; } },
    { PR_chdir,         [](Tracee* t) -> int {
        char path[PATH_MAX] = {0};
        int status = get_sysarg_path(t, path, SYSARG_1);
        if (status < 0) return status;

        char oldpath[PATH_MAX] = {0};
        status = join_paths(2, oldpath, path, ".");
        if (status < 0) return status;

        struct stat statl = {};
        status = translate_path(t, path, AT_FDCWD, oldpath, true);
        if (status < 0) return status;
        if (lstat(path, &statl) < 0) return -errno;
        if ((statl.st_mode & S_IXUSR) == 0) return -EACCES;

        status = detranslate_path(t, path, nullptr);
        if (status < 0) return status;
        chop_finality(path);

        char* tmp = talloc_strdup(t, path);
        if (!tmp) return -ENOMEM;
        TALLOC_FREE(t->fs->cwd);
        t->fs->cwd = tmp;
        talloc_set_name_const(t->fs->cwd, "$cwd");
        set_sysnum(t, PR_void);
        return 0;
    }},
    { PR_chmod,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_chown,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_chown32,       [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_chroot,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_connect,       [](Tracee* t) -> int {
        reg_val_t addr = peek_reg(t, CURRENT, SYSARG_2);
        reg_val_t sz   = peek_reg(t, CURRENT, SYSARG_3);
        int ret = translate_socketcall_enter(t, &addr, sz);
        if (ret > 0) {
            poke_reg(t, SYSARG_2, addr);
            poke_reg(t, SYSARG_3, (reg_val_t)sizeof(struct sockaddr_un));
        }
        return 0;
    }},
    { PR_creat,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_execve,        [](Tracee* t) -> int { return translate_execve_enter(t); } },
    { PR_execveat,      [](Tracee* t) -> int {
        reg_val_t fd = peek_reg(t, CURRENT, SYSARG_1);
        if ((int)fd == AT_FDCWD) {
            set_sysnum(t, PR_execve);
            poke_reg(t, SYSARG_1, peek_reg(t, CURRENT, SYSARG_2));
            poke_reg(t, SYSARG_2, peek_reg(t, CURRENT, SYSARG_3));
            poke_reg(t, SYSARG_3, peek_reg(t, CURRENT, SYSARG_4));
            return translate_execve_enter(t);
        }
        note(t, ERROR, SYSTEM, "execveat() with non-AT_FDCWD fd not supported");
        return -ENOSYS;
    }},
    { PR_faccessat,     [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, REGULAR);
    }},
    { PR_faccessat2,    [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, REGULAR);
    }},
    { PR_fchdir,        [](Tracee* t) -> int {
        char oldpath[PATH_MAX] = ".";
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int status = translate_path(t, path, dirfd, oldpath, true);
        if (status < 0) return status;

        struct stat statl = {};
        if (lstat(path, &statl) < 0) return -errno;
        if ((statl.st_mode & S_IXUSR) == 0) return -EACCES;

        status = detranslate_path(t, path, nullptr);
        if (status < 0) return status;
        chop_finality(path);

        char* tmp = talloc_strdup(t, path);
        if (!tmp) return -ENOMEM;
        TALLOC_FREE(t->fs->cwd);
        t->fs->cwd = tmp;
        talloc_set_name_const(t->fs->cwd, "$cwd");
        set_sysnum(t, PR_void);
        return 0;
    }},
    { PR_fchmodat,      [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, REGULAR);
    }},
    { PR_fchownat,      [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        int flags = (int)peek_reg(t, CURRENT, SYSARG_5);
        return translate_path2(t, dirfd, path, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
    }},
    { PR_fstatat64,     [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        int flags = (int)peek_reg(t, CURRENT, SYSARG_4);
        return translate_path2(t, dirfd, path, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
    }},
    { PR_futimesat,     [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, REGULAR);
    }},
    { PR_getcwd,        [](Tracee* t) -> int { set_sysnum(t, PR_void); return 0; } },
    { PR_getpeername,   [](Tracee* t) -> int { return 0; } },
    { PR_getsockname,   [](Tracee* t) -> int { return 0; } },
    { PR_getxattr,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_inotify_add_watch, [](Tracee* t) -> int {
        int flags = (int)peek_reg(t, CURRENT, SYSARG_3);
        return translate_sysarg(t, SYSARG_2, (flags & IN_DONT_FOLLOW) ? SYMLINK : REGULAR);
    }},
    { PR_ioctl,         [](Tracee* t) -> int { return 0; } },
    { PR_lchown,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_lchown32,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_lgetxattr,     [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_link,          [](Tracee* t) -> int {
        int ret = translate_sysarg(t, SYSARG_1, SYMLINK);
        if (ret < 0) return ret;
        return translate_sysarg(t, SYSARG_2, SYMLINK);
    }},
    { PR_linkat,        [](Tracee* t) -> int {
        int oldfd  = (int)peek_reg(t, CURRENT, SYSARG_1);
        int newfd  = (int)peek_reg(t, CURRENT, SYSARG_3);
        int flags  = (int)peek_reg(t, CURRENT, SYSARG_5);
        char oldpath[PATH_MAX] = {0};
        char newpath[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, oldpath, SYSARG_2);
        if (ret < 0) return ret;
        ret = get_sysarg_path(t, newpath, SYSARG_4);
        if (ret < 0) return ret;
        ret = translate_path2(t, oldfd, oldpath, SYSARG_2, (flags & AT_SYMLINK_FOLLOW) ? REGULAR : SYMLINK);
        if (ret < 0) return ret;
        return translate_path2(t, newfd, newpath, SYSARG_4, SYMLINK);
    }},
    { PR_listxattr,     [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_llistxattr,    [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_lstat,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_lstat64,       [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_mkdir,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_mkdirat,       [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, SYMLINK);
    }},
    { PR_mknod,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_mknodat,       [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, REGULAR);
    }},
    { PR_mount,         [](Tracee* t) -> int {
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_1);
        if (ret < 0) return ret;
        if (path[0] == '/' || path[0] == '.') {
            ret = translate_path2(t, AT_FDCWD, path, SYSARG_1, REGULAR);
            if (ret < 0) return ret;
        }
        return translate_sysarg(t, SYSARG_2, REGULAR);
    }},
    { PR_newfstatat,    [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        int flags = (int)peek_reg(t, CURRENT, SYSARG_4);
        return translate_path2(t, dirfd, path, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
    }},
    { PR_oldlstat,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_oldstat,       [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_open,          [](Tracee* t) -> int {
        int flags = (int)peek_reg(t, CURRENT, SYSARG_2);
        if ((flags & O_NOFOLLOW) || ((flags & O_EXCL) && (flags & O_CREAT)))
            return translate_sysarg(t, SYSARG_1, SYMLINK);
        else
            return translate_sysarg(t, SYSARG_1, REGULAR);
    }},
    { PR_openat,        [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        int flags = (int)peek_reg(t, CURRENT, SYSARG_3);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        if ((flags & O_NOFOLLOW) || ((flags & O_EXCL) && (flags & O_CREAT)))
            return translate_path2(t, dirfd, path, SYSARG_2, SYMLINK);
        else
            return translate_path2(t, dirfd, path, SYSARG_2, REGULAR);
    }},
    { PR_pivot_root,    [](Tracee* t) -> int {
        int ret = translate_sysarg(t, SYSARG_1, REGULAR);
        if (ret < 0) return ret;
        return translate_sysarg(t, SYSARG_2, REGULAR);
    }},
    { PR_prctl,         [](Tracee* t) -> int {
        if (peek_reg(t, CURRENT, SYSARG_1) == (reg_val_t)PR_SET_DUMPABLE) {
            set_sysnum(t, PR_void);
            return 0;
        }
        return 0;
    }},
    { PR_ptrace,        [](Tracee* t) -> int { return translate_ptrace_enter(t); } },
    { PR_readlink,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_readlinkat,    [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, SYMLINK);
    }},
    { PR_removexattr,   [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_rename,        [](Tracee* t) -> int {
        int ret = translate_sysarg(t, SYSARG_1, SYMLINK);
        if (ret < 0) return ret;
        return translate_sysarg(t, SYSARG_2, SYMLINK);
    }},
    { PR_renameat,      [](Tracee* t) -> int {
        int oldfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        int newfd = (int)peek_reg(t, CURRENT, SYSARG_3);
        char oldpath[PATH_MAX] = {0};
        char newpath[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, oldpath, SYSARG_2);
        if (ret < 0) return ret;
        ret = get_sysarg_path(t, newpath, SYSARG_4);
        if (ret < 0) return ret;
        ret = translate_path2(t, oldfd, oldpath, SYSARG_2, SYMLINK);
        if (ret < 0) return ret;
        return translate_path2(t, newfd, newpath, SYSARG_4, SYMLINK);
    }},
    { PR_renameat2,     [](Tracee* t) -> int {
        int oldfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        int newfd = (int)peek_reg(t, CURRENT, SYSARG_3);
        char oldpath[PATH_MAX] = {0};
        char newpath[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, oldpath, SYSARG_2);
        if (ret < 0) return ret;
        ret = get_sysarg_path(t, newpath, SYSARG_4);
        if (ret < 0) return ret;
        ret = translate_path2(t, oldfd, oldpath, SYSARG_2, SYMLINK);
        if (ret < 0) return ret;
        return translate_path2(t, newfd, newpath, SYSARG_4, SYMLINK);
    }},
    { PR_rmdir,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_setxattr,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_socketcall,    [](Tracee* t) -> int { return 0; } },
    { PR_stat,          [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_stat64,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_statfs,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_statfs64,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_statx,         [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        int flags = (int)peek_reg(t, CURRENT, SYSARG_3);
        return translate_path2(t, dirfd, path, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
    }},
    { PR_symlink,       [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_2, SYMLINK); } },
    { PR_symlinkat,     [](Tracee* t) -> int {
        int newfd = (int)peek_reg(t, CURRENT, SYSARG_2);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_3);
        if (ret < 0) return ret;
        return translate_path2(t, newfd, path, SYSARG_3, SYMLINK);
    }},
    { PR_swapoff,       [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_swapon,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_truncate,      [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_truncate64,    [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_umount,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_umount2,       [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_unlink,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, SYMLINK); } },
    { PR_unlinkat,      [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        return translate_path2(t, dirfd, path, SYSARG_2, SYMLINK);
    }},
    { PR_uselib,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_utime,         [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_utimensat,     [](Tracee* t) -> int {
        int dirfd = (int)peek_reg(t, CURRENT, SYSARG_1);
        char path[PATH_MAX] = {0};
        int ret = get_sysarg_path(t, path, SYSARG_2);
        if (ret < 0) return ret;
        int flags = (int)peek_reg(t, CURRENT, SYSARG_4);
        return translate_path2(t, dirfd, path, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
    }},
    { PR_utimes,        [](Tracee* t) -> int { return translate_sysarg(t, SYSARG_1, REGULAR); } },
    { PR_wait4,         [](Tracee* t) -> int { return translate_wait_enter(t); } },
    { PR_waitpid,       [](Tracee* t) -> int { return translate_wait_enter(t); } },
};

static const size_t handler_count = sizeof(syscall_handlers) / sizeof(SyscallHandlerEntry);

static int syscall_handler_cmp(const void *a, const void *b) {
    sysnum_t n1 = *(const sysnum_t*)a;
    const SyscallHandlerEntry* e2 = (const SyscallHandlerEntry*)b;
    if (n1 < e2->num) return -1;
    if (n1 > e2->num) return 1;
    return 0;
}

static syscall_handler_t find_syscall_handler(sysnum_t num) {
    const auto* e = (const SyscallHandlerEntry*)bsearch(
        &num, syscall_handlers, handler_count, sizeof(SyscallHandlerEntry), syscall_handler_cmp
    );
    return e ? e->handler : nullptr;
}

static int translate_path2(Tracee* tracee, int dir_fd, char path[PATH_MAX], Reg reg, Type type) {
    if (!*path) return 0;
    char new_path[PATH_MAX] = {0};
    int ret = translate_path(tracee, new_path, dir_fd, path, type != SYMLINK);
    if (ret < 0) return ret;
    return set_sysarg_path(tracee, new_path, reg);
}

static int translate_sysarg(Tracee* tracee, Reg reg, Type type) {
    char old_path[PATH_MAX] = {0};
    int ret = get_sysarg_path(tracee, old_path, reg);
    if (ret < 0) return ret;
    return translate_path2(tracee, AT_FDCWD, old_path, reg, type);
}

extern "C" int translate_syscall_enter(Tracee* tracee)
{
    if (!tracee)
        return -EINVAL;

    int status = notify_extensions(tracee, SYSCALL_ENTER_START, 0, 0);
    if (status != 0)
        return status;

    sysnum_t num = get_sysnum(tracee, ORIGINAL);
    syscall_handler_t handler = find_syscall_handler(num);
    if (handler)
        status = handler(tracee);

    int status2 = notify_extensions(tracee, SYSCALL_ENTER_END, status, 0);
    if (status2 < 0)
        status = status2;

    return status;
}
