#include <errno.h>
#include <sys/utsname.h>
#include <linux/net.h>
#include <linux/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

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
#include <stdio.h>      /* sscanf(3), */

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
    /* 上游 f2c5744：这些 syscall 在 enter.c 被 PR_void，确保
     * 即使 AVOIDER 泄漏 -ENOSYS，tracee 也看到 0 返回值。 */
    case PR_unshare:
    case PR_setns:
    case PR_mount:
    case PR_umount:
    case PR_umount2:
    case PR_pivot_root:
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
        /* 上游 7ff389a1：tracee 读 /proc/<pid>/fd/<fd> 时，让扩展
         * （link2symlink）有机会把内核上报的 .l2s 内部名替换为
         * tracee 打开该描述符时用的名字。 */
        struct readlink_proc_fd_state proc_fd = {
            .pid = 0, .fd = -1, .host_path = referee, .substituted = false,
        };
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
            proc_fd.pid = tracee->pid;
            proc_fd.fd  = (int) dirfd;
        } else {
            /* referer 形如 /proc/<pid>/fd/<fd>（"/proc/self" 已在
             * enter 阶段 canonicalize 成真实 pid）→ 记下描述符编号。 */
            int fd_pid;
            int fd_number;
            char extra;

            /* fork 的 canon 不把 /proc/self 解析成数字 pid（实测 referer
             * 原样 = /proc/self/fd/N）——self 形式按本进程处理 */
            if (sscanf(referer, "/proc/self/fd/%d%c", &fd_number, &extra) == 1
                && fd_number >= 0) {
                proc_fd.pid = tracee->pid;
                proc_fd.fd  = fd_number;
            }
            else if (sscanf(referer, "/proc/%d/fd/%d%c", &fd_pid, &fd_number, &extra) == 2
                && fd_number >= 0) {
                proc_fd.pid = (pid_t) fd_pid;
                proc_fd.fd  = fd_number;
            }
        }

        /* /proc/self/exe（及当前 tracee 的 /proc/<pid>/exe）：内核返回的是
         * 内部 loader 的临时路径（/tmp/proot-loader-*），必须替换为真实
         * 二进制路径，否则 tsgo（typescript-go）等按自身路径找 lib.d.ts
         * 的程序会 panic（"bundled: ... does not exist"）。 */
        if (tracee->exe != NULL) {
            bool is_exe_link = (strcmp(referer, "/proc/self/exe") == 0);
            if (!is_exe_link) {
                char proc_exe[PATH_MAX];
                int n = snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", tracee->pid);
                if (n > 0 && (size_t) n < sizeof(proc_exe))
                    is_exe_link = (strcmp(referer, proc_exe) == 0);
            }
            if (is_exe_link) {
                size_t len = strlen(tracee->exe);
                if (len + 1 > PATH_MAX) {
                    status = -ENAMETOOLONG;
                    break;
                }
                memcpy(referee, tracee->exe, len + 1);
                status = len + 1;
                goto write_back;
            }
        }

        /* Linux readlink 在用户缓冲不足时静默截断并返回 bufsiz（"缓冲满"
         * 语义，调用方凭返回值扩大缓冲重试，如 tsgo realpath 的 O_PATH +
         * readlink(/proc/self/fd/N) 技巧）。截断内容经 detranslate 缩短后
         * 返回值 < bufsiz，会破坏该语义（调用方误以为结果完整拿到截断
         * 路径）。此时从宿主侧重读完整内容再 detranslate。 */
        if (old_size == max_size) {
            char full[PATH_MAX];
            bool reread = false;

            if (strncmp(referer, "/proc/", 6) == 0) {
                /* /proc/self/fd/N 或 /proc/<pid>/fd/N：内核结果无法从
                 * tracee 内存恢复（已截断），从宿主侧 /proc/<pid>/fd/N
                 * 重读（PATH_MAX 缓冲不截断）。 */
                pid_t rpid = tracee->pid;
                const char *fdpart = NULL;

                if (strncmp(referer, "/proc/self/fd/", 14) == 0)
                    fdpart = referer + 14;
                else {
                    const char *p = referer + 6;
                    char *end = NULL;
                    long v = strtol(p, &end, 10);
                    if (end != p && *end == '/' && strncmp(end + 1, "fd/", 3) == 0) {
                        rpid = (pid_t)v;
                        fdpart = end + 4;
                    }
                }
                if (fdpart != NULL) {
                    char *end = NULL;
                    long v = strtol(fdpart, &end, 10);
                    if (end != fdpart && *end == '\0' && v >= 0 && v <= 0x7fffffff
                        && readlink_proc_pid_fd(rpid, (int)v, full) == 0)
                        reread = true;
                }
            }
            else if (referer[0] == '/') {
                /* 普通路径（enter 阶段已翻译为 host 路径）：宿主侧直接重读。 */
                ssize_t n = readlink(referer, full, sizeof(full) - 1);
                if (n >= 0) {
                    full[n] = '\0';
                    reread = true;
                }
            }

            if (reread) {
                int st = detranslate_path(tracee, full, referer);
                if (st > 0) {
                    size_t full_len = st - 1; /* detranslate 返回含 \0 的长度 */
                    if (full_len + 1 <= max_size) {
                        status = write_data(tracee, output, full, full_len + 1);
                        if (status < 0)
                            break;
                        status = full_len; /* 完整返回 */
                    } else {
                        /* guest 路径仍超用户缓冲：保持"缓冲满"语义，
                         * 返回 max_size 让调用方扩大缓冲重试。 */
                        status = write_data(tracee, output, full, max_size);
                        if (status < 0)
                            break;
                        status = max_size;
                    }
                    break;
                }
                /* detranslate 失败（bind 外路径等）→ 沿用内核原结果 */
            }
        }

        /* 让扩展替换内核上报的路径（link2symlink：fd 打开时
         * 用的名字）；替换后必须写回 tracee。 */
        if (proc_fd.fd >= 0) {
            status = notify_extensions(tracee, READLINK_PROC_FD, (intptr_t) &proc_fd, 0);
            if (status < 0)
                break;
        }

        status = detranslate_path(tracee, referee, referer);
        if (status < 0)
            break;
        if (status == 0) {
            /* 路径无需转换……除非上面刚被替换，此时要告知 tracee。 */
            if (!proc_fd.substituted)
                goto end;
            status = strlen(referee) + 1;
        }

write_back:
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

    case PR_prctl: {
        word_t option = peek_reg(tracee, ORIGINAL, SYSARG_1);
#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
        /* PR_GET_AUXV（内核 6.4+）：内核返回的 auxv 里 AT_EXECFN 仍指向
         * loader 临时路径（loader BRANCH 不进内核，补不了）——出口侧
         * 扫描返回缓冲区，把 AT_EXECFN 的值改成 execfn_addr（= guest
         * 栈上 argv[0] 指针，execve 出口已捕获）。本机 GKI 5.15 无此
         * syscall，属远期兼容死代码；纯缓冲区后处理，无寄存器 poke。 */
        if (option == PR_GET_AUXV) {
            word_t buf_addr, buf_max, offset, entry_size, type;
            if ((int) syscall_result < 0)
                goto end;
            if (tracee->execfn_addr == 0)
                goto end;
            buf_max = peek_reg(tracee, ORIGINAL, SYSARG_3);
            if (syscall_result > buf_max)
                goto end;
            buf_addr   = peek_reg(tracee, ORIGINAL, SYSARG_2);
            entry_size = 2 * sizeof_word(tracee);
            for (offset = 0; offset + entry_size <= syscall_result; offset += entry_size) {
                errno = 0;
                type = peek_word(tracee, buf_addr + offset);
                if (errno != 0)
                    break;
                if (type == AT_NULL)
                    break;
                if (type == AT_EXECFN) {
                    poke_word(tracee, buf_addr + offset + sizeof_word(tracee),
                              tracee->execfn_addr);
                    break;
                }
            }
            goto end;
        }
        break;
    }

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

    case PR_socket:
        /* 上游 4abc88b：记录被替换成 AF_UNIX 的假 netlink fd。 */
        if (tracee->pending_fake_netlink_socket) {
            int fd = (int) peek_reg(tracee, CURRENT, SYSARG_RESULT);
            if (fd >= 0) {
                int i;
                if (tracee->fake_netlink_fds_count < MAX_FAKE_NETLINK_FDS) {
                    bool present = false;
                    for (i = 0; i < tracee->fake_netlink_fds_count; i++) {
                        if (tracee->fake_netlink_fds[i] == fd) {
                            present = true;
                            break;
                        }
                    }
                    if (!present)
                        tracee->fake_netlink_fds[tracee->fake_netlink_fds_count++] = fd;
                }
            }
            tracee->pending_fake_netlink_socket = false;
        }

        /* 上游 87af48f：记录宿主直接给的真实 NETLINK_ROUTE socket。 */
        if (tracee->pending_real_netlink_socket) {
            int fd = (int) peek_reg(tracee, CURRENT, SYSARG_RESULT);
            if (fd >= 0) {
                int i;
                if (tracee->netlink_route_fds_count < MAX_NETLINK_ROUTE_FDS) {
                    bool present = false;
                    for (i = 0; i < tracee->netlink_route_fds_count; i++) {
                        if (tracee->netlink_route_fds[i] == fd) {
                            present = true;
                            break;
                        }
                    }
                    if (!present)
                        tracee->netlink_route_fds[tracee->netlink_route_fds_count++] = fd;
                }
            }
            tracee->pending_real_netlink_socket = false;
        }
        goto end;

    case PR_recvfrom:
    case PR_recvmsg:
        /* 上游 87af48f：把内核拒绝的 netns 配置请求改成 ACK。 */
        handle_netlink_reply_exit(tracee, syscall_number);
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
