#include "build.h"

#include <errno.h>
#include "syscall/seccomp.h"
#include "tracee/tracee.h"
#include "attribute.h"

#if defined(HAVE_SECCOMP_FILTER)

#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <linux/limits.h>

#include "tracee/abi.h"
#include "tracee/statx.h"
#include "syscall/sysnum.h"
#include "path/path.h"
#include "extension/extension.h"
#include "compat.h"

/* USER_NOTIF emulation for --seccomp-notify.
 *
 * Layout:
 *   cli.c          probe_seccomp_user_notif() before launch
 *   seccomp.c      BPF: stat syscalls -> RET_USER_NOTIF + NEW_LISTENER
 *   event.c        child SCM_RIGHTS listener; dedicated RECV thread
 *   this file      blocking RECV, emulate newfstatat, SEND
 *
 * CONTINUE is limited to paths with no metadata extension rewrite. Serialize
 * with event_loop via seccomp_user_notif_lock.
 * Guest memory uses process_vm_* (then /proc/pid/mem): the task is not
 * in ptrace-stop, so PEEK/POKE would EFAULT.
 */

static pthread_mutex_t user_notif_tracee_lock = PTHREAD_MUTEX_INITIALIZER;
static struct seccomp_notif *notif_req;
static struct seccomp_notif_resp *notif_resp;
static uint16_t notif_req_sz;
static uint16_t notif_resp_sz;
static int nr_fstatat64_cached = -2;
static int nr_newfstatat_cached = -2;
static int nr_statx_cached = -2;
static int notif_test_enabled = -1;

static bool notif_test(void)
{
    if (notif_test_enabled < 0)
        notif_test_enabled = getenv("NEOPROOT_TEST_USER_NOTIF") != NULL ? 1 : 0;
    return notif_test_enabled == 1;
}

static void notif_note(const char *what)
{
    if (notif_test())
        fprintf(stderr, "neoproot user-notif: %s\n", what);
}

void seccomp_user_notif_lock(void)
{
    pthread_mutex_lock(&user_notif_tracee_lock);
}

void seccomp_user_notif_unlock(void)
{
    pthread_mutex_unlock(&user_notif_tracee_lock);
}

int probe_seccomp_user_notif(void)
{
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

static void free_notif_bufs(void)
{
    free(notif_req);
    free(notif_resp);
    notif_req = NULL;
    notif_resp = NULL;
    notif_req_sz = 0;
    notif_resp_sz = 0;
}

static int ensure_notif_bufs(void)
{
    struct seccomp_notif_sizes sizes = { 0 };

    if (notif_req != NULL && notif_resp != NULL)
        return 0;
    free_notif_bufs();
#ifdef __NR_seccomp
    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
        return -errno;
#else
    return -ENOSYS;
#endif
    if (sizes.seccomp_notif == 0 || sizes.seccomp_notif_resp == 0)
        return -EINVAL;
    notif_req = calloc(1, sizes.seccomp_notif);
    notif_resp = calloc(1, sizes.seccomp_notif_resp);
    if (notif_req == NULL || notif_resp == NULL) {
        free_notif_bufs();
        return -ENOMEM;
    }
    notif_req_sz = sizes.seccomp_notif;
    notif_resp_sz = sizes.seccomp_notif_resp;
    return 0;
}

static int notif_send_flags(int listener_fd, int error, word_t val,
                            uint32_t flags)
{
    memset(notif_resp, 0, notif_resp_sz);
    notif_resp->id = notif_req->id;
    notif_resp->flags = flags;
    notif_resp->error = error;
    notif_resp->val = (int64_t)val;
    return (int)ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, notif_resp);
}

static void notif_send(int listener_fd, int error, word_t val)
{
    (void)notif_send_flags(listener_fd, error, val, 0);
}

static bool host_may_need_l2s(const char *path, const struct stat *st)
{
    const char *base;

    if (S_ISLNK(st->st_mode))
        return true;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strncmp(base, ".l2s.", 5) == 0;
}

static int fstatat_empty_path(pid_t target, int dirfd, int flags,
                              struct stat *st, char host_path[PATH_MAX])
{
    char procpath[64];
    int hostdir;
    int stat_err;

    if ((flags & AT_EMPTY_PATH) == 0)
        return -ENOENT;
    if (dirfd == AT_FDCWD)
        snprintf(procpath, sizeof(procpath), "/proc/%d/cwd", (int)target);
    else
        snprintf(procpath, sizeof(procpath), "/proc/%d/fd/%d",
                 (int)target, dirfd);
    hostdir = open(procpath, O_PATH | O_CLOEXEC);
    if (hostdir < 0)
        stat_err = -1;
    else {
        stat_err = fstatat(hostdir, "", st, flags | AT_EMPTY_PATH);
        close(hostdir);
    }
    if (stat_err < 0)
        return errno ? -errno : -ENOENT;
    strcpy(host_path, procpath);
    return 0;
}

static int host_statx_path(const char *path, int flags, unsigned int mask,
                           struct statx *stx)
{
#if defined(SYS_statx)
    if (syscall(SYS_statx, AT_FDCWD, path, flags & ~AT_EMPTY_PATH,
                mask, stx) < 0)
#elif defined(__NR_statx)
    if (syscall(__NR_statx, AT_FDCWD, path, flags & ~AT_EMPTY_PATH,
                mask, stx) < 0)
#else
    errno = ENOSYS;
    return -ENOSYS;
#endif
        return errno ? -errno : -ENOENT;
    return 0;
}

static int statx_empty_path(pid_t target, int dirfd, int flags,
                            unsigned int mask, struct statx *stx,
                            char host_path[PATH_MAX])
{
    char procpath[64];

    if ((flags & AT_EMPTY_PATH) == 0)
        return -ENOENT;
    if (dirfd == AT_FDCWD)
        snprintf(procpath, sizeof(procpath), "/proc/%d/cwd", (int)target);
    else
        snprintf(procpath, sizeof(procpath), "/proc/%d/fd/%d",
                 (int)target, dirfd);
    if (host_statx_path(procpath, flags, mask, stx) < 0)
        return errno ? -errno : -ENOENT;
    strcpy(host_path, procpath);
    return 0;
}

/* Fill *st for a guest newfstatat. Caller holds seccomp_user_notif_lock. */
static int emulate_notif_fstatat(Tracee *tracee, pid_t target, int dirfd,
                                 const char *path, int flags, struct stat *st,
                                 char host_path[PATH_MAX])
{
    int rc;

    if (path[0] == '\0') {
        rc = fstatat_empty_path(target, dirfd, flags, st, host_path);
        if (rc < 0)
            return rc;
    } else {
        rc = try_fstatat_cached_host_dirfd(tracee, dirfd, path, flags,
                                           st, host_path);
        if (rc < 0)
            return rc;
        if (rc > 0) {
            rc = translate_path(tracee, host_path, dirfd, path,
                                (flags & AT_SYMLINK_NOFOLLOW) == 0);
            if (rc < 0)
                return rc;
            if (fstatat(AT_FDCWD, host_path, st, flags) < 0)
                return errno ? -errno : -ENOENT;
        }
    }

    if (host_may_need_l2s(host_path, st) || host_may_need_l2s(path, st))
        (void)link2symlink_disguise_stat(tracee, host_path, st);
    (void)fake_id0_disguise_stat(tracee, st);
    return 0;
}

static int emulate_notif_statx(Tracee *tracee, pid_t target, int dirfd,
                               const char *path, int flags,
                               unsigned int mask, struct statx *stx,
                               char host_path[PATH_MAX])
{
    struct statx_syscall_state state = { 0 };
    int rc;

    if (path[0] == '\0') {
        rc = statx_empty_path(target, dirfd, flags, mask, stx, host_path);
        if (rc < 0)
            return rc;
    } else {
        rc = try_statx_cached_host_dirfd(tracee, dirfd, path, flags,
                                         mask, stx, host_path);
        if (rc < 0)
            return rc;
        if (rc > 0) {
            rc = translate_path(tracee, host_path, dirfd, path,
                                (flags & AT_SYMLINK_NOFOLLOW) == 0);
            if (rc < 0)
                return rc;
            rc = host_statx_path(host_path, flags, mask, stx);
            if (rc < 0)
                return rc;
        }
    }

    (void)link2symlink_disguise_statx(tracee, host_path, stx, mask);

    strcpy(state.host_path, host_path);
    state.statx_buf = *stx;
    state.updated_stats = true;
    rc = notify_extensions(tracee, STATX_SYSCALL, (intptr_t)&state, 0);
    if (rc < 0)
        return rc;
    *stx = state.statx_buf;
    return 0;
}

static bool notif_is_fstatat(int nr)
{
    if (nr_fstatat64_cached == -2) {
        word_t sysnr = detranslate_sysnum(ABI_DEFAULT, PR_fstatat64);
        nr_fstatat64_cached = (sysnr == SYSCALL_AVOIDER) ? -1 : (int)sysnr;
        sysnr = detranslate_sysnum(ABI_DEFAULT, PR_newfstatat);
        nr_newfstatat_cached = (sysnr == SYSCALL_AVOIDER) ? -1 : (int)sysnr;
    }
    return (nr_fstatat64_cached >= 0 && nr == nr_fstatat64_cached)
        || (nr_newfstatat_cached >= 0 && nr == nr_newfstatat_cached);
}

static bool notif_is_statx(int nr)
{
    if (nr_statx_cached == -2) {
        word_t sysnr = detranslate_sysnum(ABI_DEFAULT, PR_statx);
        nr_statx_cached = (sysnr == SYSCALL_AVOIDER) ? -1 : (int)sysnr;
    }
    return nr_statx_cached >= 0 && nr == nr_statx_cached;
}

static bool notif_can_continue_fstatat(Tracee *tracee, int dirfd,
                                       const char *path, int flags)
{
    if (get_extension(tracee, link2symlink_callback) != NULL ||
        get_extension(tracee, fake_id0_callback) != NULL)
        return false;
    return can_continue_cached_host_dirfd(tracee, dirfd, path, flags);
}

int handle_seccomp_user_notif(int listener_fd)
{
    Tracee *tracee;
    struct stat st;
    struct statx stx;
    pid_t target;
    char path[PATH_MAX];
    char host_path[PATH_MAX];
    int dirfd;
    int flags;
    unsigned int mask;
    int n;
    int rc;

    if (listener_fd < 0)
        return -EBADF;
    rc = ensure_notif_bufs();
    if (rc < 0)
        return rc;

    memset(notif_req, 0, notif_req_sz);
    rc = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_req);
    if (rc < 0)
        return -errno;

    int nr = (int)notif_req->data.nr;
    bool want_fstatat = notif_is_fstatat(nr);

    if (!want_fstatat && !notif_is_statx(nr)) {
        notif_send(listener_fd, -ENOSYS, 0);
        return 0;
    }

    target = (pid_t)notif_req->pid;
    dirfd = (int)notif_req->data.args[0];
    n = notif_read_string(target, (word_t)notif_req->data.args[1],
                          path, sizeof(path));
    if (n < 0) {
        notif_send(listener_fd, n, 0);
        return 0;
    }
    path[sizeof(path) - 1] = '\0';
    flags = want_fstatat ? (int)notif_req->data.args[3]
                         : (int)notif_req->data.args[2];

    seccomp_user_notif_lock();
    tracee = get_tracee(NULL, target, false);
    if (tracee == NULL) {
        seccomp_user_notif_unlock();
        notif_send(listener_fd, -ESRCH, 0);
        return 0;
    }

    if (want_fstatat && notif_can_continue_fstatat(tracee, dirfd, path, flags)) {
        if (notif_send_flags(listener_fd, 0, 0,
                             SECCOMP_USER_NOTIF_FLAG_CONTINUE) == 0) {
            notif_note("fstatat continue");
            seccomp_user_notif_unlock();
            return 0;
        }
        notif_note("continue unavailable");
    }

    if (want_fstatat) {
        notif_note("fstatat emulate");
        rc = emulate_notif_fstatat(tracee, target, dirfd, path, flags,
                                   &st, host_path);
        if (rc == 0)
            rc = notif_vm_io(target, (word_t)notif_req->data.args[2],
                             &st, sizeof(st), true);
    } else {
        notif_note("statx emulate");
        mask = (unsigned int)notif_req->data.args[3];
        rc = emulate_notif_statx(tracee, target, dirfd, path, flags, mask,
                                 &stx, host_path);
        if (rc == 0)
            rc = notif_vm_io(target, (word_t)notif_req->data.args[4],
                             &stx, sizeof(stx), true);
    }
    seccomp_user_notif_unlock();
    notif_send(listener_fd, rc < 0 ? rc : 0, 0);
    return 0;
}

#else /* !HAVE_SECCOMP_FILTER */

int probe_seccomp_user_notif(void)
{
    return -ENOSYS;
}

int handle_seccomp_user_notif([[maybe_unused]] int listener_fd)
{
    return -ENOSYS;
}

void seccomp_user_notif_lock(void)
{
}

void seccomp_user_notif_unlock(void)
{
}

#endif /* HAVE_SECCOMP_FILTER */
