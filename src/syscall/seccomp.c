#include "build.h"
#include "arch.h"

#if defined(HAVE_SECCOMP_FILTER)

#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <talloc.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>

#include "syscall/seccomp.h"
#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "compat.h"
#include "attribute.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

static_assert(sizeof(struct sock_filter) == 8, "sock_filter size mismatch");
static_assert(offsetof(struct seccomp_data, nr) < UINT32_MAX, "nr offset too large");

#define DEBUG_FILTER(...)

/* ioctl args1 过滤版指令数（1 JEQ nr + 1 LD args1 + 6 对 JEQ+RET = 14） */
#define IOCTL_ARGS1_STMTS 16

static ALWAYS_INLINE int new_program_filter(struct sock_fprog *restrict program) {
    program->filter = talloc_array(NULL, struct sock_filter, 0);
    if (UNLIKELY(!program->filter))
        return -ENOMEM;
    program->len = 0;
    return 0;
}

static ALWAYS_INLINE int add_statements(struct sock_fprog *restrict program,
                                        size_t nb_statements,
                                        const struct sock_filter statements[restrict]) {
    size_t old_len = talloc_array_length(program->filter);
    struct sock_filter *new_filter = talloc_realloc(NULL, program->filter,
                                                    struct sock_filter,
                                                    old_len + nb_statements);
    if (UNLIKELY(!new_filter))
        return -ENOMEM;
    program->filter = new_filter;
    for (size_t i = 0; i < nb_statements; ++i)
        program->filter[old_len + i] = statements[i];
    return 0;
}

static ALWAYS_INLINE int add_syscall_ret(struct sock_fprog *restrict program,
                                         word_t syscall, uint32_t seccomp_ret) {
    if (UNLIKELY(syscall > UINT32_MAX))
        return -ERANGE;
    const struct sock_filter stmts[] = {
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)syscall, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, seccomp_ret),
    };
    return add_statements(program, sizeof(stmts)/sizeof(*stmts), stmts);
}

static ALWAYS_INLINE int add_trace_syscall(struct sock_fprog *restrict program,
                                           word_t syscall, int flag) {
    return add_syscall_ret(program, syscall, SECCOMP_RET_TRACE + flag);
}

static ALWAYS_INLINE bool is_user_notif_sysnum(Sysnum value) {
    return value == PR_newfstatat || value == PR_fstatat64;
}

/* ioctl 等按参数条件过滤的变体：只有 args[1] 匹配特定值才停靠，
 * 其余直通（nvim 等高频 ioctl 全部停靠会拖慢终端操作）。
 * 指令布局：JEQ nr 不匹配跳 SKIP；匹配则 LD args[1] 后逐个 JEQ+RET。
 * SKIP = 1(LD) + 2*n(JEQ+RET) */
static ALWAYS_INLINE int add_trace_syscall_args1(struct sock_fprog *restrict program,
                                                 word_t syscall, int flag,
                                                 const uint32_t *args1, size_t n_args1) {
    if (UNLIKELY(syscall > UINT32_MAX))
        return -ERANGE;
    size_t skip = 1 + 2 * n_args1;
    struct sock_filter *stmts = talloc_array(NULL, struct sock_filter, 2 + skip);
    if (UNLIKELY(!stmts))
        return -ENOMEM;
    size_t idx = 0;
    stmts[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                               (uint32_t)syscall, 0, (uint8_t)skip);
    stmts[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                               offsetof(struct seccomp_data, args[1]));
    for (size_t i = 0; i < n_args1; i++) {
        stmts[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                   args1[i], 0, 1);
        stmts[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE + flag);
    }
    int ret = add_statements(program, idx, stmts);
    talloc_free(stmts);
    return ret;
}

static ALWAYS_INLINE int end_arch_section(struct sock_fprog *restrict program,
                                          size_t nb_traced, size_t extra_stmts) {
    const struct sock_filter stmt = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    int ret = add_statements(program, 1, &stmt);
    if (UNLIKELY(ret < 0))
        return ret;
    size_t used = talloc_array_length(program->filter) - program->len;
    size_t expected = 1 + nb_traced * 2 + extra_stmts;
    if (UNLIKELY(used != expected))
        return -ERANGE;
    return 0;
}

static ALWAYS_INLINE int start_arch_section(struct sock_fprog *restrict program,
                                            uint32_t arch, size_t nb_traced, size_t extra_stmts) {
    size_t arch_off = offsetof(struct seccomp_data, arch);
    size_t nr_off   = offsetof(struct seccomp_data, nr);
    size_t sec_len  = 1 + nb_traced * 2 + extra_stmts;
    if (UNLIKELY(arch_off > UINT32_MAX || nr_off > UINT32_MAX || sec_len > UINT32_MAX - 1))
        return -ERANGE;
    const struct sock_filter stmts[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)arch_off),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_JMP | BPF_JA | BPF_K, (uint32_t)(sec_len + 1)),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t)nr_off),
    };
    int ret = add_statements(program, sizeof(stmts)/sizeof(*stmts), stmts);
    if (UNLIKELY(ret < 0))
        return ret;
    program->len = talloc_array_length(program->filter);
    return 0;
}

static ALWAYS_INLINE int finalize_program_filter(struct sock_fprog *restrict program) {
    const struct sock_filter stmt = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL);
    int ret = add_statements(program, 1, &stmt);
    if (UNLIKELY(ret < 0))
        return ret;
    program->len = talloc_array_length(program->filter);
    return 0;
}

static ALWAYS_INLINE void free_program_filter(struct sock_fprog *restrict program) {
    TALLOC_FREE(program->filter);
    program->len = 0;
}

static int set_seccomp_filters(const FilteredSysnum *restrict sysnums,
                               bool user_notif, int *listener_fd) {
    SeccompArch archs[] = SECCOMP_ARCHS;
    size_t n_arch = sizeof(archs) / sizeof(SeccompArch);
    struct sock_fprog prog = { 0 };
    int ret = 0;

    ret = new_program_filter(&prog);
    if (UNLIKELY(ret < 0))
        goto out;

    for (size_t i = 0; i < n_arch; ++i) {
        size_t n_trace = 0;
        size_t ioctl_extra = 0;
        for (size_t j = 0; j < archs[i].nb_abis; ++j) {
            for (size_t k = 0; sysnums[k].value != PR_void; ++k) {
                word_t sc = detranslate_sysnum(archs[i].abis[j], sysnums[k].value);
                if (sc == SYSCALL_AVOIDER)
                    continue;
                ++n_trace;
                if (sysnums[k].value == PR_ioctl)
                    ioctl_extra += IOCTL_ARGS1_STMTS - 2; /* args1 版比普通版多出的指令 */
            }
        }
        ret = start_arch_section(&prog, archs[i].value, n_trace, ioctl_extra);
        if (UNLIKELY(ret < 0))
            goto out;
        for (size_t j = 0; j < archs[i].nb_abis; ++j) {
            for (size_t k = 0; sysnums[k].value != PR_void; ++k) {
                word_t sc = detranslate_sysnum(archs[i].abis[j], sysnums[k].value);
                if (sc == SYSCALL_AVOIDER)
                    continue;
                if (sysnums[k].value == PR_ioctl) {
                    /* 只对需要改写的 ioctl cmd 停靠（终端 termios2 兼容 + DRM），
                     * 其余 ioctl 直通——nvim 等高频终端 ioctl 不再每次 ptrace 停靠 */
                    static const uint32_t ioctl_cmds[] = {
                        0x5404,      /* TCSETS + 2 */
                        0x802c542a,  /* TCGETS2  _IOR('T',0x2A,termios2) size=0x2c */
                        0x402c542b,  /* TCSETS2  _IOW('T',0x2B,termios2) */
                        0x402c542c,  /* TCSETSW2 _IOW('T',0x2C,termios2) */
                        0x402c542d,  /* TCSETSF2 _IOW('T',0x2D,termios2) */
                        0x40049409,  /* _IOW(0x94, 9, int) DRM */
                        0x00008933,  /* SIOCGIFINDEX _IOR('s', 0x33, int) */
                    };
                    ret = add_trace_syscall_args1(&prog, sc, sysnums[k].flags,
                                                  ioctl_cmds, 7);
                } else if (user_notif && is_user_notif_sysnum(sysnums[k].value)) {
                    ret = add_syscall_ret(&prog, sc, SECCOMP_RET_USER_NOTIF);
                } else {
                    ret = add_trace_syscall(&prog, sc, sysnums[k].flags);
                }
                if (UNLIKELY(ret < 0))
                    goto out;
            }
        }
        ret = end_arch_section(&prog, n_trace, ioctl_extra);
        if (UNLIKELY(ret < 0))
            goto out;
    }

    ret = finalize_program_filter(&prog);
    if (UNLIKELY(ret < 0))
        goto out;

    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (UNLIKELY(ret < 0))
        goto out;
    if (user_notif) {
#ifndef __NR_seccomp
        ret = -ENOSYS;
        goto out;
#else
        int fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                              SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
        if (fd < 0) {
            ret = -errno;
            goto out;
        }
        if (listener_fd)
            *listener_fd = fd;
        ret = 0;
        goto out;
#endif
    }
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    if (UNLIKELY(ret < 0))
        goto out;

    ret = 0;
out:
    free_program_filter(&prog);
    return ret;
}

static FilteredSysnum proot_sysnums[] = {
    { PR_accept,        FILTER_SYSEXIT },
    { PR_accept4,       FILTER_SYSEXIT },
    { PR_access,        0 },
    { PR_acct,          0 },
    { PR_bind,          0 },
    { PR_brk,           FILTER_SYSEXIT },
    { PR_chdir,         FILTER_SYSEXIT },
    { PR_close,         0 },
    { PR_close_range,   0 },
    { PR_chmod,         0 },
    { PR_chown,         0 },
    { PR_chown32,       0 },
    { PR_chroot,        0 },
    { PR_clone,         0 },
    { PR_clone3,        0 },
    { PR_connect,       0 },
    { PR_creat,         0 },
    { PR_execve,        FILTER_SYSEXIT },
    { PR_execveat,      FILTER_SYSEXIT },
    { PR_faccessat,     0 },
    { PR_faccessat2,    FILTER_SYSEXIT },
    { PR_fchdir,        FILTER_SYSEXIT },
    { PR_fchmodat,      0 },
    { PR_fchownat,      0 },
    { PR_fstatat64,     0 },
    { PR_futimesat,     0 },
    { PR_getcwd,        FILTER_SYSEXIT },
    { PR_getpeername,   FILTER_SYSEXIT },
    { PR_getsockname,   FILTER_SYSEXIT },
    { PR_getxattr,      0 },
    { PR_inotify_add_watch, 0 },
#ifdef __ANDROID__
    { PR_ioctl,         FILTER_SYSEXIT },
#endif
    { PR_lchown,        0 },
    { PR_lchown32,      0 },
    { PR_lgetxattr,     0 },
    { PR_link,          0 },
    { PR_linkat,        0 },
    { PR_listxattr,     0 },
    { PR_llistxattr,    0 },
    { PR_lremovexattr,  0 },
    { PR_lsetxattr,     0 },
    { PR_lstat,         0 },
    { PR_lstat64,       0 },
#ifdef __ANDROID__
    { PR_memfd_create,  0 },
#endif
    { PR_mkdir,         0 },
    { PR_mkdirat,       0 },
    { PR_mknod,         0 },
    { PR_mknodat,       0 },
    { PR_mount,         FILTER_SYSEXIT },
    { PR_name_to_handle_at, 0 },
    { PR_newfstatat,    0 },
    { PR_oldlstat,      0 },
    { PR_oldstat,       0 },
    { PR_open,          0 },
    { PR_openat,        0 },
    { PR_openat2,       0 },
    { PR_pivot_root,    FILTER_SYSEXIT },
    { PR_prctl,         0 },
    { PR_prlimit64,     FILTER_SYSEXIT },
    { PR_ptrace,        FILTER_SYSEXIT },
    { PR_readlink,      FILTER_SYSEXIT },
    { PR_readlinkat,    FILTER_SYSEXIT },
    { PR_removexattr,   0 },
    { PR_rename,        FILTER_SYSEXIT },
    { PR_renameat,      FILTER_SYSEXIT },
    { PR_renameat2,     FILTER_SYSEXIT },
    { PR_rmdir,         0 },
    { PR_setrlimit,     FILTER_SYSEXIT },
    { PR_setxattr,      0 },
    { PR_socketcall,    FILTER_SYSEXIT },
    { PR_stat,          0 },
    { PR_stat64,        0 },
    { PR_statfs,        FILTER_SYSEXIT },
    { PR_statfs64,      FILTER_SYSEXIT },
    { PR_statx,         FILTER_SYSEXIT },
    { PR_swapoff,       0 },
    { PR_swapon,        0 },
    { PR_symlink,       0 },
    { PR_symlinkat,     0 },
    { PR_truncate,      0 },
    { PR_truncate64,    0 },
    { PR_umount,        FILTER_SYSEXIT },
    { PR_umount2,       FILTER_SYSEXIT },
    { PR_unshare,       FILTER_SYSEXIT },
    { PR_setns,         FILTER_SYSEXIT },
    { PR_uname,         FILTER_SYSEXIT },
    { PR_unlink,        0 },
    { PR_unlinkat,      0 },
    { PR_uselib,        0 },
    { PR_utime,         FILTER_SYSEXIT },
    { PR_utimensat,     0 },
    { PR_utimes,        0 },
    { PR_wait4,         FILTER_SYSEXIT },
    { PR_waitpid,       FILTER_SYSEXIT },
    FILTERED_SYSNUM_END,
};

/* 仅当宿主拒绝 AF_NETLINK 时才需要拦截这些 syscall 做仿真；
 * 宿主允许时让真实 netlink 直通，避免干扰 glibc/iproute2。 */
static FilteredSysnum netlink_sysnums[] = {
    { PR_close,         0 },
    { PR_recvfrom,      0 },
    { PR_recvmsg,       0 },
    { PR_sendmsg,       0 },
    { PR_sendto,        0 },
    { PR_socket,        FILTER_SYSEXIT },
    FILTERED_SYSNUM_END,
};

static int merge_filtered_sysnums(TALLOC_CTX *ctx,
                                  FilteredSysnum **restrict list,
                                  const FilteredSysnum *restrict new_list) {
    assert(list != NULL);
    if (UNLIKELY(!*list)) {
        *list = talloc_array(ctx, FilteredSysnum, 1);
        if (UNLIKELY(!*list))
            return -ENOMEM;
        (*list)[0].value = PR_void;
    }
    for (size_t i = 0; new_list[i].value != PR_void; ++i) {
        size_t j;
        for (j = 0; (*list)[j].value != PR_void; ++j) {
            if ((*list)[j].value == new_list[i].value)
                break;
        }
        if ((*list)[j].value == PR_void) {
            FilteredSysnum *tmp = talloc_realloc(ctx, *list, FilteredSysnum, j + 2);
            if (UNLIKELY(!tmp))
                return -ENOMEM;
            *list = tmp;
            (*list)[j] = new_list[i];
            (*list)[j + 1].value = PR_void;
        } else {
            (*list)[j].flags |= new_list[i].flags;
        }
    }
    return 0;
}

int probe_seccomp_user_notif(void) {
#ifndef __NR_seccomp
    return -ENOSYS;
#else
    int pipefd[2];
    pid_t pid;
    int status;
    int child_errno = 0;
    ssize_t n;

    if (pipe(pipefd) < 0)
        return -errno;

    pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        return -saved;
    }

    if (pid == 0) {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)__NR_getppid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };
        int fd;
        int e;

        close(pipefd[0]);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            e = errno ? errno : EPERM;
            (void)write(pipefd[1], &e, sizeof(e));
            _exit(1);
        }
        fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
        if (fd < 0) {
            e = errno ? errno : EINVAL;
            (void)write(pipefd[1], &e, sizeof(e));
            _exit(1);
        }
        close(fd);
        _exit(0);
    }

    close(pipefd[1]);
    n = read(pipefd[0], &child_errno, sizeof(child_errno));
    close(pipefd[0]);
    if (waitpid(pid, &status, 0) < 0)
        return -errno;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;
    if (n == (ssize_t)sizeof(child_errno) && child_errno != 0)
        return -child_errno;
    return -EPERM;
#endif
}

/* USER_NOTIF tasks are not in ptrace-stop; PEEK/POKE fail. process_vm_*
 * (then /proc/pid/mem) does not need the task stopped. */
static int notif_vm_io(pid_t pid, word_t addr, void *buf, size_t n, bool writing)
{
    struct iovec local = { .iov_base = buf, .iov_len = n };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)addr, .iov_len = n };
    ssize_t r;
    char mempath[64];
    int fd;
    ssize_t pr;

    if (n == 0)
        return 0;
#ifdef __NR_process_vm_readv
    if (writing)
        r = syscall(__NR_process_vm_writev, pid, &local, 1, &remote, 1, 0);
    else
        r = syscall(__NR_process_vm_readv, pid, &local, 1, &remote, 1, 0);
    if (r == (ssize_t)n)
        return 0;
#endif
    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", (int)pid);
    fd = open(mempath, (writing ? O_RDWR : O_RDONLY) | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    pr = writing ? pwrite(fd, buf, n, (off_t)addr) : pread(fd, buf, n, (off_t)addr);
    close(fd);
    if (pr == (ssize_t)n)
        return 0;
    return pr < 0 ? -errno : -EFAULT;
}

static int notif_read_string(pid_t pid, word_t addr, char *buf, size_t max)
{
    size_t off = 0;
    long page;

    if (max == 0)
        return 0;
    page = sysconf(_SC_PAGE_SIZE);
    if (page <= 0)
        page = 4096;
    while (off < max) {
        size_t page_off = (size_t)((addr + off) & (word_t)(page - 1));
        size_t chunk = (size_t)page - page_off;
        int rc;
        if (chunk > max - off)
            chunk = max - off;
        rc = notif_vm_io(pid, addr + off, buf + off, chunk, false);
        if (rc < 0) {
            if (off == 0)
                return rc;
            break;
        }
        for (size_t i = 0; i < chunk; i++) {
            if (buf[off + i] == '\0')
                return (int)(off + i + 1);
        }
        off += chunk;
    }
    buf[max - 1] = '\0';
    return (int)max;
}

int handle_seccomp_user_notif(int listener_fd) {
    static struct seccomp_notif *req;
    static struct seccomp_notif_resp *resp;
    static uint16_t req_sz;
    static uint16_t resp_sz;
    struct stat st;
    word_t nr_fstatat64;
    word_t nr_newfstatat;
    pid_t target;
    int rc;

    if (listener_fd < 0)
        return -EBADF;

    if (req == NULL || resp == NULL) {
        struct seccomp_notif_sizes sizes = { 0 };
#ifdef __NR_seccomp
        if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
            return -errno;
#else
        return -ENOSYS;
#endif
        if (sizes.seccomp_notif == 0 || sizes.seccomp_notif_resp == 0)
            return -EINVAL;
        /* malloc: this handler runs on the RECV thread; talloc is not MT-safe. */
        req = calloc(1, sizes.seccomp_notif);
        resp = calloc(1, sizes.seccomp_notif_resp);
        if (req == NULL || resp == NULL)
            return -ENOMEM;
        req_sz = sizes.seccomp_notif;
        resp_sz = sizes.seccomp_notif_resp;
    }

    memset(req, 0, req_sz);
    rc = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, req);
    if (rc < 0)
        return -errno;

    memset(resp, 0, resp_sz);
    resp->id = req->id;
    resp->flags = 0;
    resp->val = 0;
    resp->error = -ENOSYS;

    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) < 0) {
        resp->error = -ESRCH;
        (void)ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
        return 0;
    }

    nr_fstatat64 = detranslate_sysnum(ABI_DEFAULT, PR_fstatat64);
    nr_newfstatat = detranslate_sysnum(ABI_DEFAULT, PR_newfstatat);
    if (!((nr_fstatat64 != SYSCALL_AVOIDER && req->data.nr == (int)nr_fstatat64)
          || (nr_newfstatat != SYSCALL_AVOIDER && req->data.nr == (int)nr_newfstatat))) {
        (void)ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
        return 0;
    }

    target = (pid_t)req->pid;
    {
        char path[PATH_MAX];
        char procpath[64];
        int dirfd = (int)req->data.args[0];
        int flags = (int)req->data.args[3];
        int hostdir = -1;
        int n;
        int stat_err;
        const char *base;

        n = notif_read_string(target, (word_t)req->data.args[1], path, sizeof(path));
        if (n < 0) {
            resp->error = n;
            (void)ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
            return 0;
        }
        path[sizeof(path) - 1] = '\0';
        base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (strcmp(path, NEOPROOT_NOTIFY_SENTINEL) == 0
            || strcmp(base, NEOPROOT_NOTIFY_SENTINEL) == 0) {
            memset(&st, 0, sizeof(st));
            st.st_mode = S_IFREG | 0644;
            st.st_nlink = 1;
            st.st_size = NEOPROOT_NOTIFY_PLUMBING_SIZE;
            if (notif_vm_io(target, (word_t)req->data.args[2], &st, sizeof(st), true) < 0)
                resp->error = -EFAULT;
            else {
                resp->error = 0;
                resp->val = 0;
            }
            if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0)
                return -errno;
            return 0;
        }

        /* Identity-rootfs plumbing: use the tracee's cwd/fd. Not a
         * substitute for PRoot path translation (step 3). */
        if (path[0] == '/')
            stat_err = fstatat(AT_FDCWD, path, &st, flags);
        else {
            if (dirfd == AT_FDCWD)
                snprintf(procpath, sizeof(procpath), "/proc/%d/cwd", (int)target);
            else
                snprintf(procpath, sizeof(procpath), "/proc/%d/fd/%d",
                         (int)target, dirfd);
            hostdir = open(procpath, O_PATH | O_CLOEXEC);
            if (hostdir < 0)
                stat_err = -1;
            else {
                stat_err = fstatat(hostdir, path[0] ? path : ".", &st, flags);
                close(hostdir);
            }
        }
        if (stat_err < 0)
            resp->error = errno ? -errno : -ENOENT;
        else if (notif_vm_io(target, (word_t)req->data.args[2], &st, sizeof(st), true) < 0)
            resp->error = -EFAULT;
        else {
            resp->error = 0;
            resp->val = 0;
        }
        if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0)
            return -errno;
        return 0;
    }
}

int enable_syscall_filtering(const Tracee *restrict tracee) {
    FilteredSysnum *filtered = NULL;
    int ret;
    int listener = -1;
    assert(tracee != NULL && tracee->ctx != NULL);
    ret = merge_filtered_sysnums(tracee->ctx, &filtered, proot_sysnums);
    if (UNLIKELY(ret < 0))
        return ret;
    if (host_blocks_af_netlink(tracee)) {
        ret = merge_filtered_sysnums(tracee->ctx, &filtered, netlink_sysnums);
        if (UNLIKELY(ret < 0))
            return ret;
    }
    if (tracee->extensions) {
        Extension *ext;
        LIST_FOREACH(ext, tracee->extensions, link) {
            if (!ext->filtered_sysnums)
                continue;
            ret = merge_filtered_sysnums(tracee->ctx, &filtered, ext->filtered_sysnums);
            if (UNLIKELY(ret < 0))
                return ret;
        }
    }
    ret = set_seccomp_filters(filtered, tracee->seccomp_notify, &listener);
    if (ret < 0)
        return ret;
    if (tracee->seccomp_notify)
        return listener;
    return 0;
}

#else /* !HAVE_SECCOMP_FILTER */

#include <errno.h>
#include "tracee/tracee.h"
#include "attribute.h"

int probe_seccomp_user_notif(void) {
    return -ENOSYS;
}

int handle_seccomp_user_notif([[maybe_unused]] int listener_fd) {
    return -ENOSYS;
}

int enable_syscall_filtering([[maybe_unused]] const Tracee *tracee) {
    return 0;
}

#endif /* HAVE_SECCOMP_FILTER */