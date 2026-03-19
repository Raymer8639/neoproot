/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
  *
  * This file is part of PRoot.
  *
  * Copyright (C) 2026 scicat
  *
  * This program is free software; you can redistribute it and/or
  * modify it under the terms of the GNU General Public License
  * as published by the Free Software Foundation; either version 2 of the
  * License, or (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  * 02110-1301 USA.
  */
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

#ifdef __cplusplus
}
#endif

/**
 * 类型别名：简化word_t相关操作，提升代码可读性
 */
using reg_val_t = word_t;
using sysnum_t = word_t;

/**
 * Translate @path and put the result in the @tracee's memory address
 * space pointed to by the @reg argument of the current syscall.
 */
static int translate_path2(Tracee* tracee, int dir_fd, char path[PATH_MAX], Reg reg, Type type)
{
    if (path[0] == '\0')
        return 0;

    char new_path[PATH_MAX] = {0};
    const int status = translate_path(tracee, new_path, dir_fd, path, type != SYMLINK);
    if (status < 0)
        return status;

    return set_sysarg_path(tracee, new_path, reg);
}

/**
 * A helper for translate_path2, extract and translate sysarg path
 */
static int translate_sysarg(Tracee* tracee, Reg reg, Type type)
{
    char old_path[PATH_MAX] = {0};
    const int status = get_sysarg_path(tracee, old_path, reg);
    if (status < 0)
        return status;

    return translate_path2(tracee, AT_FDCWD, old_path, reg, type);
}

/**
 * 内联工具函数：获取sizeof_word，避免重复计算，编译器可优化
 */
static inline size_t get_sizeof_word(const Tracee* tracee)
{
    return sizeof_word(tracee);
}

/**
 * Translate the input arguments of the current @tracee's syscall
 * 核心重构：解决goto跳变量初始化问题，强化类型检查、提前return减少嵌套
 */
extern "C" int translate_syscall_enter(Tracee* tracee)
{
    // 1. 所有变量移到函数开头定义，避免goto跳过初始化
    int status = 0;
    int status2 = 0;
    bool special = false;
    sysnum_t syscall_number = 0;
    reg_val_t reg_val = 0;
    int flags = 0, dirfd = 0, olddirfd = 0, newdirfd = 0;
    char path[PATH_MAX] = {0};
    char oldpath[PATH_MAX] = {0};
    char newpath[PATH_MAX] = {0};

    // 入口判空，无goto直接return
    if (tracee == nullptr)
        return -EINVAL;

    // 扩展通知，异常直接后续处理，不再goto
    status = notify_extensions(tracee, SYSCALL_ENTER_START, 0, 0);
    if (status > 0)
        return 0;
    if (status < 0)
        goto notify_end; // 此时所有变量已初始化，可安全goto

    syscall_number = get_sysnum(tracee, ORIGINAL);

    switch (syscall_number)
    {
        case PR_execve:
            status = translate_execve_enter(tracee);
            break;

        case PR_execveat:
            reg_val = peek_reg(tracee, CURRENT, SYSARG_1);
            if (static_cast<int>(reg_val) == AT_FDCWD)
            {
                set_sysnum(tracee, PR_execve);
                poke_reg(tracee, SYSARG_1, peek_reg(tracee, CURRENT, SYSARG_2));
                poke_reg(tracee, SYSARG_2, peek_reg(tracee, CURRENT, SYSARG_3));
                poke_reg(tracee, SYSARG_3, peek_reg(tracee, CURRENT, SYSARG_4));
                status = translate_execve_enter(tracee);
            }
            else
            {
                note(tracee, ERROR, SYSTEM, "execveat() with non-AT_FDCWD fd is not currently supported");
                status = -ENOSYS;
            }
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
            struct stat statl = {0};
            if (syscall_number == PR_chdir)
            {
                status = get_sysarg_path(tracee, path, SYSARG_1);
                if (status < 0) break;
                status = join_paths(2, oldpath, path, ".");
                if (status < 0) break;
                dirfd = AT_FDCWD;
            }
            else
            {
                std::strcpy(oldpath, ".");
                dirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            }

            status = translate_path(tracee, path, dirfd, oldpath, true);
            if (status < 0) break;
            if (lstat(path, &statl) < 0)
            {
                status = -errno;
                break;
            }
            if ((statl.st_mode & S_IXUSR) == 0)
                return -EACCES;

            status = detranslate_path(tracee, path, nullptr);
            if (status < 0) break;
            chop_finality(path);

            char* tmp = talloc_strdup(tracee->fs, path);
            if (tmp == nullptr)
            {
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
            const reg_val_t address = peek_reg(tracee, CURRENT, SYSARG_2);
            const reg_val_t size = peek_reg(tracee, CURRENT, SYSARG_3);
            status = translate_socketcall_enter(tracee, &const_cast<reg_val_t&>(address), size);
            if (status <= 0) break;
            poke_reg(tracee, SYSARG_2, address);
            poke_reg(tracee, SYSARG_3, static_cast<reg_val_t>(sizeof(struct sockaddr_un)));
            status = 0;
            break;
        }

#define SYSARG_ADDR(n) (args_addr + ((n) - 1) * get_sizeof_word(tracee))
#define PEEK_WORD(addr, forced_errno)    \
    ([&]() -> reg_val_t {                \
        reg_val_t val = peek_word(tracee, addr); \
        if (errno != 0) {                \
            status = forced_errno ?: -errno; \
        }                                \
        return val;                      \
    }())

#define POKE_WORD(addr, value)           \
    do {                                 \
        poke_word(tracee, addr, value);  \
        if (errno != 0) {                \
            status = -errno;             \
        }                                \
    } while (0)

        case PR_accept:
        case PR_accept4:
            if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0)
            {
                status = 0;
                break;
            }
            special = true;
            [[fallthrough]];

        case PR_getsockname:
        case PR_getpeername: {
            reg_val_t size_val = PEEK_WORD(peek_reg(tracee, ORIGINAL, SYSARG_3), special ? -EINVAL : 0);
            if (status != 0) break;
            poke_reg(tracee, SYSARG_6, size_val);
            status = 0;
            break;
        }

        case PR_socketcall: {
            const reg_val_t args_addr = peek_reg(tracee, CURRENT, SYSARG_2);
            reg_val_t sock_addr_saved = 0, sock_addr = 0, size_addr = 0, size = 0;
            const reg_val_t sock_cmd = peek_reg(tracee, CURRENT, SYSARG_1);

            switch (sock_cmd)
            {
                case SYS_BIND:
                case SYS_CONNECT:
                    status = 1;
                    break;

                case SYS_ACCEPT:
                case SYS_ACCEPT4:
                    sock_addr = PEEK_WORD(SYSARG_ADDR(2), 0);
                    if (status != 0) break;
                    if (sock_addr == 0)
                    {
                        status = 0;
                        break;
                    }
                    special = true;
                    [[fallthrough]];

                case SYS_GETSOCKNAME:
                case SYS_GETPEERNAME:
                    size_addr = PEEK_WORD(SYSARG_ADDR(3), 0);
                    if (status != 0) break;
                    size = PEEK_WORD(size_addr, special ? -EINVAL : 0);
                    if (status != 0) break;
                    poke_reg(tracee, SYSARG_6, size);
                    status = 0;
                    break;

                default:
                    status = 0;
                    break;
            }

            if (status <= 0) break;
            sock_addr = PEEK_WORD(SYSARG_ADDR(2), 0);
            if (status != 0) break;
            size = PEEK_WORD(SYSARG_ADDR(3), 0);
            if (status != 0) break;

            sock_addr_saved = sock_addr;
            status = translate_socketcall_enter(tracee, &sock_addr, size);
            if (status <= 0) break;

            poke_reg(tracee, SYSARG_5, sock_addr_saved);
            poke_reg(tracee, SYSARG_6, size);
            POKE_WORD(SYSARG_ADDR(2), sock_addr);
            if (status != 0) break;
            POKE_WORD(SYSARG_ADDR(3), static_cast<reg_val_t>(sizeof(struct sockaddr_un)));
            status = 0;
            break;
        }
#undef SYSARG_ADDR
#undef PEEK_WORD
#undef POKE_WORD

        case PR_access: case PR_acct: case PR_chmod: case PR_chown: case PR_chown32:
        case PR_chroot: case PR_getxattr: case PR_listxattr: case PR_mknod: case PR_oldstat:
        case PR_creat: case PR_removexattr: case PR_setxattr: case PR_stat: case PR_stat64:
        case PR_statfs: case PR_statfs64: case PR_swapoff: case PR_swapon: case PR_truncate:
        case PR_truncate64: case PR_umount: case PR_umount2: case PR_uselib: case PR_utime:
        case PR_utimes:
            status = translate_sysarg(tracee, SYSARG_1, REGULAR);
            break;

        case PR_open:
            flags = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_2));
            if ((flags & O_NOFOLLOW) != 0 || ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0))
                status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
            else
                status = translate_sysarg(tracee, SYSARG_1, REGULAR);
            break;

        case PR_fchownat: case PR_fstatat64: case PR_newfstatat:
        case PR_utimensat: case PR_name_to_handle_at:
            dirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0) break;
            flags = (syscall_number == PR_fchownat || syscall_number == PR_name_to_handle_at)
                    ? static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_5))
                    : static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_4));
            status = translate_path2(tracee, dirfd, path, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
            break;

        case PR_fchmodat: case PR_faccessat: case PR_faccessat2:
        case PR_futimesat: case PR_mknodat:
            dirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0) break;
            status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
            break;

        case PR_inotify_add_watch:
            flags = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_3));
            status = translate_sysarg(tracee, SYSARG_2, (flags & IN_DONT_FOLLOW) ? SYMLINK : REGULAR);
            break;

        case PR_readlink: case PR_lchown: case PR_lchown32: case PR_lgetxattr:
        case PR_llistxattr: case PR_lremovexattr: case PR_lsetxattr: case PR_lstat:
        case PR_lstat64: case PR_oldlstat: case PR_unlink: case PR_rmdir: case PR_mkdir:
            status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
            break;

        case PR_pivot_root:
            status = translate_sysarg(tracee, SYSARG_1, REGULAR);
            if (status < 0) break;
            status = translate_sysarg(tracee, SYSARG_2, REGULAR);
            break;

        case PR_linkat:
            olddirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            newdirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_3));
            flags    = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_5));
            status = get_sysarg_path(tracee, oldpath, SYSARG_2);
            if (status < 0) break;
            status = get_sysarg_path(tracee, newpath, SYSARG_4);
            if (status < 0) break;
            status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, (flags & AT_SYMLINK_FOLLOW) ? REGULAR : SYMLINK);
            if (status < 0) break;
            status = translate_path2(tracee, newdirfd, newpath, SYSARG_4, SYMLINK);
            break;

        case PR_mount:
            status = get_sysarg_path(tracee, path, SYSARG_1);
            if (status < 0) break;
            if (path[0] == '/' || path[0] == '.')
            {
                status = translate_path2(tracee, AT_FDCWD, path, SYSARG_1, REGULAR);
                if (status < 0) break;
            }
            status = translate_sysarg(tracee, SYSARG_2, REGULAR);
            break;

        case PR_openat:
            dirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            flags = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_3));
            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0) break;
            if ((flags & O_NOFOLLOW) != 0 || ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0))
                status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
            else
                status = translate_path2(tracee, dirfd, path, SYSARG_2, REGULAR);
            break;

        case PR_readlinkat: case PR_unlinkat: case PR_mkdirat:
            dirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            status = get_sysarg_path(tracee, path, SYSARG_2);
            if (status < 0) break;
            status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
            break;

        case PR_link: case PR_rename:
            status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
            if (status < 0) break;
            status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
            break;

        case PR_renameat: case PR_renameat2:
            olddirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            newdirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_3));
            status = get_sysarg_path(tracee, oldpath, SYSARG_2);
            if (status < 0) break;
            status = get_sysarg_path(tracee, newpath, SYSARG_4);
            if (status < 0) break;
            status = translate_path2(tracee, olddirfd, oldpath, SYSARG_2, SYMLINK);
            if (status < 0) break;
            status = translate_path2(tracee, newdirfd, newpath, SYSARG_4, SYMLINK);
            break;

        case PR_symlink:
            status = translate_sysarg(tracee, SYSARG_2, SYMLINK);
            break;

        case PR_symlinkat:
            newdirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_2));
            status = get_sysarg_path(tracee, newpath, SYSARG_3);
            if (status < 0) break;
            status = translate_path2(tracee, newdirfd, newpath, SYSARG_3, SYMLINK);
            break;

        case PR_statx:
            newdirfd = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_1));
            status = get_sysarg_path(tracee, newpath, SYSARG_2);
            if (status < 0) break;
            flags = static_cast<int>(peek_reg(tracee, CURRENT, SYSARG_3));
            status = translate_path2(tracee, newdirfd, newpath, SYSARG_2, (flags & AT_SYMLINK_NOFOLLOW) ? SYMLINK : REGULAR);
            break;

        case PR_prctl:
            if (peek_reg(tracee, CURRENT, SYSARG_1) == static_cast<reg_val_t>(PR_SET_DUMPABLE))
            {
                set_sysnum(tracee, PR_void);
                status = 0;
            }
            break;

#ifdef __ANDROID__
        case PR_ioctl:
            reg_val = peek_reg(tracee, CURRENT, SYSARG_2);
            if (reg_val == static_cast<reg_val_t>(TCSETS + 2))        // TCSAFLUSH
                poke_reg(tracee, SYSARG_2, static_cast<reg_val_t>(TCSETS + TCSANOW));
            else if (reg_val == static_cast<reg_val_t>(TCGETS2))
                poke_reg(tracee, SYSARG_2, static_cast<reg_val_t>(TCGETS));
            else if (reg_val == static_cast<reg_val_t>(TCSETS2))
                poke_reg(tracee, SYSARG_2, static_cast<reg_val_t>(TCSETS));
            else if (reg_val == static_cast<reg_val_t>(TCSETSW2))
                poke_reg(tracee, SYSARG_2, static_cast<reg_val_t>(TCSETSW));
            else if (reg_val == static_cast<reg_val_t>(TCSETSF2))
                poke_reg(tracee, SYSARG_2, static_cast<reg_val_t>(TCSETSF));
            break;
#endif

        case PR_memfd_create: {
            char memfd_name[20] = {0};
            const int read_status = read_string(tracee, memfd_name, peek_reg(tracee, CURRENT, SYSARG_1), sizeof(memfd_name) - 1);
            if (read_status >= 0)
            {
                if (std::strncmp(memfd_name, "JITCode:", 8) == 0)
                    status = -EACCES;
                else if (std::strcmp(memfd_name, "opcache_lock") == 0)
                    status = -EACCES;
                else if (std::strncmp(memfd_name, "lib/apk/exec/", 13) == 0)
                    status = -EACCES;
            }
            break;
        }

        default:
            status = 0;
            break;
    }

notify_end:
    // 扩展结束通知，所有分支最终都会走到这里
    status2 = notify_extensions(tracee, SYSCALL_ENTER_END, status, 0);
    if (status2 < 0)
        status = status2;

    return status;
}
