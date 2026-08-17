#include <errno.h>
#include <talloc.h>
#include <sys/un.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <termios.h>
#include <sched.h>
#include <stddef.h>
#include <stdbool.h>

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "syscall/heap.h"
#include "syscall/pipe_shadow.h"
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
#include "path/temp.h"
#include "arch.h"
#include "attribute.h"

/* 上游 064617f：bubblewrap 等需要剥离命名空间 flag */
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#define CLONE_NS_MASK (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | \
                       CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | \
                       CLONE_NEWCGROUP | CLONE_NEWTIME)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* guest 路径是否为 /proc/self/auxv 或 /proc/<自身pid>/auxv */
static inline bool is_proc_self_auxv(const Tracee *tracee, const char *path)
{
    char prefix[64];
    if (strcmp(path, "/proc/self/auxv") == 0)
        return true;
    snprintf(prefix, sizeof(prefix), "/proc/%d/auxv", tracee->pid);
    return strcmp(path, prefix) == 0;
}

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

/* 上游 100dd09fb（适配）：只翻译父目录、保留最终组件。用于
 * mkdir/symlink/link 这类“目标由内核创建”的 syscall：PRoot 提前
 * 探测尚不存在的最终名字会扰动老 Android 内核/文件系统。 */
static int translate_path2_parent(Tracee *tracee, int dir_fd, char path[PATH_MAX], Reg reg)
{
    char parent[PATH_MAX];
    char translated_parent[PATH_MAX];
    char translated_path[PATH_MAX];
    char *last_slash;
    char *leaf;
    size_t length;
    int status;

    if (path[0] == '\0')
        return 0;

    length = strlen(path);
    if (path[length - 1] == '/')
        return translate_path2(tracee, dir_fd, path, reg, SYMLINK);

    last_slash = strrchr(path, '/');
    if (last_slash == NULL) {
        strcpy(parent, ".");
        leaf = path;
    }
    else if (last_slash == path) {
        strcpy(parent, "/");
        leaf = last_slash + 1;
    }
    else {
        size_t parent_length = (size_t)(last_slash - path);

        if (parent_length >= sizeof(parent))
            return -ENAMETOOLONG;
        memcpy(parent, path, parent_length);
        parent[parent_length] = '\0';
        leaf = last_slash + 1;
    }

    if (leaf[0] == '\0' || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0)
        return translate_path2(tracee, dir_fd, path, reg, SYMLINK);

    status = translate_path(tracee, translated_parent, dir_fd, parent, true);
    if (status < 0)
        return status;

    status = join_paths(2, translated_path, translated_parent, leaf);
    if (status < 0)
        return status;

    return set_sysarg_path(tracee, translated_path, reg);
}


/* 上游 bwrap 基础（064617f^ 已有）：mount/pivot_root 的用户态模拟。
 * 本地 scicat 基线没有这套，先补上，后续 bwrap 系列依赖它。 */
static int guest_canonicalize(Tracee *tracee, const char *user_path,
                              char guest_path[PATH_MAX])
{
    int status;

    if (user_path[0] == '/')
        strcpy(guest_path, "/");
    else {
        status = getcwd2(tracee, guest_path);
        if (status < 0)
            return status;
    }

    status = canonicalize(tracee, user_path, true, guest_path, 0);
    if (status < 0)
        return status;

    chop_finality(guest_path);
    return 0;
}

static void emulate_mount(Tracee *tracee, const char *src_user,
                          const char *target_user, const char *fstype,
                          unsigned long flags)
{
    char host_path[PATH_MAX];
    char guest_path[PATH_MAX];
    const char *tmpdir;

    if ((flags & MS_REMOUNT) != 0)
        return;

    if ((flags & MS_BIND) != 0) {
        if (translate_path(tracee, host_path, AT_FDCWD, src_user, true) < 0)
            return;
    }
    else if (strcmp(fstype, "proc") == 0)
        strcpy(host_path, "/proc");
    else if (strcmp(fstype, "sysfs") == 0)
        strcpy(host_path, "/sys");
    else if (strcmp(fstype, "devtmpfs") == 0)
        strcpy(host_path, "/dev");
    else if (strcmp(fstype, "devpts") == 0)
        strcpy(host_path, "/dev/pts");
    else if (strcmp(fstype, "tmpfs") == 0) {
        tmpdir = create_temp_directory(tracee->fs, "proot-tmpfs-");
        if (tmpdir == NULL)
            return;
        strncpy(host_path, tmpdir, PATH_MAX - 1);
        host_path[PATH_MAX - 1] = '\0';
    }
    else
        return;

    chop_finality(host_path);

    if (guest_canonicalize(tracee, target_user, guest_path) < 0)
        return;

    (void) insort_binding3(tracee, tracee->fs, host_path, guest_path);
}

static void emulate_pivot_root(Tracee *tracee, const char *new_root_user,
                               const char *put_old_user)
{
    char new_root_host[PATH_MAX];
    char new_root_guest[PATH_MAX];
    char put_old_guest[PATH_MAX];
    char old_root_host[PATH_MAX];
    Binding *root_binding;
    size_t prefix_len;
    const char *put_old_after;

    if (translate_path(tracee, new_root_host, AT_FDCWD, new_root_user, true) < 0)
        return;
    chop_finality(new_root_host);

    if (guest_canonicalize(tracee, new_root_user, new_root_guest) < 0)
        return;

    if (put_old_user[0] == '/')
        strcpy(put_old_guest, "/");
    else
        strcpy(put_old_guest, new_root_guest);
    if (canonicalize(tracee, put_old_user, true, put_old_guest, 0) < 0)
        return;

    root_binding = get_binding(tracee, GUEST, "/");
    if (root_binding == NULL)
        return;
    strncpy(old_root_host, root_binding->host.path, PATH_MAX - 1);
    old_root_host[PATH_MAX - 1] = '\0';

    remove_binding_from_all_lists(tracee, root_binding);
    (void) insort_binding3(tracee, tracee->fs, new_root_host, "/");

    prefix_len = strlen(new_root_guest);
    if (   prefix_len > 0
        && strncmp(put_old_guest, new_root_guest, prefix_len) == 0
        && (   put_old_guest[prefix_len] == '/'
            || (prefix_len == 1 && new_root_guest[0] == '/'))) {
        put_old_after = put_old_guest + (prefix_len == 1 ? 0 : prefix_len);
        if (put_old_after[0] == '/' && put_old_after[1] != '\0') {
            Binding *iter;
            Binding *next;
            size_t put_old_len = strlen(put_old_after);
            char aliased[PATH_MAX];

            (void) insort_binding3(tracee, tracee->fs,
                                   old_root_host, put_old_after);

            /* 上游 e6908d2：把已有非 root bind 也重新暴露到
             * oldroot 前缀下，方便沙箱工具继续访问 /proc、/dev 等。 */
            for (iter = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
                 iter != (void *) tracee->fs->bindings.guest;
                 iter = next) {
                next = CIRCLEQ_NEXT(iter, link.guest);

                if (strcmp(iter->guest.path, "/") == 0)
                    continue;
                if (strncmp(iter->guest.path, put_old_after, put_old_len) == 0
                    && (iter->guest.path[put_old_len] == '\0'
                        || iter->guest.path[put_old_len] == '/'))
                    continue;

                if ((size_t) snprintf(aliased, sizeof(aliased), "%s%s",
                                      put_old_after, iter->guest.path)
                    >= sizeof(aliased))
                    continue;

                (void) insort_binding3(tracee, tracee->fs,
                                       iter->host.path, aliased);
            }
        }
    }
}



/* 上游 5c7b2fd：模拟 umount，移除运行时 binding。 */
static void emulate_umount(Tracee *tracee, const char *target_user)
{
    char guest_path[PATH_MAX];
    Binding *binding;

    if (guest_canonicalize(tracee, target_user, guest_path) < 0)
        return;

    if (strcmp(guest_path, "/") == 0)
        return;

    binding = get_binding(tracee, GUEST, guest_path);
    if (binding == NULL)
        return;

    if (strcmp(binding->guest.path, guest_path) != 0)
        return;

    remove_binding_from_all_lists(tracee, binding);
}

void apply_emulated_umount(Tracee *tracee)
{
    char target_user[PATH_MAX];

    if (get_sysarg_path(tracee, target_user, SYSARG_1) < 0)
        return;

    emulate_umount(tracee, target_user);
}

/* 上游 e754452：供普通 sysenter 和 SIGSYS 处理器共用。 */
void apply_emulated_mount(Tracee *tracee)
{
    char src_user[PATH_MAX];
    char target_user[PATH_MAX];
    char fstype[256];
    word_t fstype_addr;
    unsigned long flags;

    fstype[0] = '\0';

    if (get_sysarg_path(tracee, src_user, SYSARG_1) < 0)
        return;
    if (get_sysarg_path(tracee, target_user, SYSARG_2) < 0)
        return;

    fstype_addr = peek_reg(tracee, CURRENT, SYSARG_3);
    if (fstype_addr != 0)
        (void) read_string(tracee, fstype, fstype_addr, sizeof(fstype) - 1);
    flags = peek_reg(tracee, CURRENT, SYSARG_4);

    emulate_mount(tracee, src_user, target_user, fstype, flags);
}

void apply_emulated_pivot_root(Tracee *tracee)
{
    char new_root_user[PATH_MAX];
    char put_old_user[PATH_MAX];

    if (get_sysarg_path(tracee, new_root_user, SYSARG_1) < 0)
        return;
    if (get_sysarg_path(tracee, put_old_user, SYSARG_2) < 0)
        return;

    emulate_pivot_root(tracee, new_root_user, put_old_user);
}

#ifdef __ANDROID__
/* 上游 d30b98846（适配）：Android 常拒绝非 lo 的 SIOCGIFINDEX，
 * 在 tracer 里用 if_nametoindex() 查真实接口号，写回 ifreq。 */
static bool maybe_fake_siocgifindex(Tracee *tracee, word_t cmd, word_t arg)
{
    char name[IFNAMSIZ];
    int ifindex;

    if (cmd != SIOCGIFINDEX || arg == 0)
        return false;

    if (read_data(tracee, name, arg, sizeof(name)) < 0)
        return false;
    name[IFNAMSIZ - 1] = '\0';

    ifindex = (int) if_nametoindex(name);
    if (ifindex <= 0) {
        if (strcmp(name, "lo") != 0)
            return false;
        ifindex = 1;
    }

    if (write_data(tracee, arg + IFNAMSIZ, &ifindex, sizeof(ifindex)) < 0)
        return false;
    return true;
}
#endif /* __ANDROID__ */

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

    case PR_close: {
        /* 上游 a581fbc07：在 close 真正执行前，若 fd 是匿名管道读端，
         * 在 tracer 里开一个 shadow 引用，避免 ptrace 序列化导致子写端
         * 在父读端关闭后 EPIPE（进程替换等场景）。 */
        int closed_fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
        shadow_pipe_read_end(tracee->pid, closed_fd);
        break;
    }

    case PR_clone: {
        /* 上游 064617f + 5c7b2fd：剥离 CLONE_NEW* 命名空间 flag，避免
         * Android 无权限创建命名空间时报 EPERM；fork/thread 本身正常继续。
         * 若请求了 CLONE_NEWNS，记住让子进程获得独立 bindings。 */
        word_t flags = peek_reg(tracee, CURRENT, SYSARG_1);
        if ((flags & CLONE_NS_MASK) != 0) {
            if ((flags & CLONE_NEWNS) != 0)
                tracee->clone_stripped_newns = true;
            poke_reg(tracee, SYSARG_1, flags & ~(word_t)CLONE_NS_MASK);
        }
        status = 0;
        break;
    }

    case PR_clone3: {
        word_t args_addr = peek_reg(tracee, CURRENT, SYSARG_1);
        word_t flags;
        if (args_addr != 0) {
            errno = 0;
            flags = peek_word(tracee, args_addr);
            if (errno == 0 && (flags & CLONE_NS_MASK) != 0) {
                if ((flags & CLONE_NEWNS) != 0)
                    tracee->clone_stripped_newns = true;
                poke_word(tracee, args_addr, flags & ~(word_t)CLONE_NS_MASK);
            }
        }
        status = 0;
        break;
    }

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
        poke_reg(tracee, SYSARG_RESULT, 0);
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

        poke_reg(tracee, SYSARG_RESULT, 0);
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

    /* 上游 5c7b2fd：unshare/setns 假装成功；umount 移除模拟 binding。 */
    case PR_unshare:
    case PR_setns:
        poke_reg(tracee, SYSARG_RESULT, 0);
        set_sysnum(tracee, PR_void);
        status = 0;
        break;

    case PR_umount:
    case PR_umount2:
        apply_emulated_umount(tracee);
        poke_reg(tracee, SYSARG_RESULT, 0);
        set_sysnum(tracee, PR_void);
        status = 0;
        break;

    case PR_open:
        flags = peek_reg(tracee, CURRENT, SYSARG_2);

        /* auxv 通道 2 修复：open(/proc/self/auxv) → 改写为生成的
         * 正确内容临时文件（绕过 -b /proc 绑定优先级；文件由
         * bind_proc_pid_auxv 在 execve 出口重建）。 */
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;
        if (is_proc_self_auxv(tracee, path) && tracee->auxv_host_path != NULL) {
            status = set_sysarg_path(tracee, tracee->auxv_host_path, SYSARG_1);
            if (status < 0)
                break;
            break;
        }

        if ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0) {
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
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;
        status = translate_sysarg(tracee, SYSARG_1, SYMLINK);
        break;

    case PR_mkdir:
        status = get_sysarg_path(tracee, path, SYSARG_1);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;
        /* 上游 c48312521：目标由内核创建，只翻译父目录。 */
        status = translate_path2_parent(tracee, AT_FDCWD, path, SYSARG_1);
        break;

    case PR_pivot_root:
        apply_emulated_pivot_root(tracee);
        poke_reg(tracee, SYSARG_RESULT, 0);
        set_sysnum(tracee, PR_void);
        status = 0;
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

        /* 上游 100dd09fb/c48312521：linkat 的 newpath 由内核创建，
         * 只翻译父目录。 */
        status = translate_path2_parent(tracee, newdirfd, newpath, SYSARG_4);
        break;

    case PR_mount:
        apply_emulated_mount(tracee);
        poke_reg(tracee, SYSARG_RESULT, 0);
        set_sysnum(tracee, PR_void);
        status = 0;
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

        /* auxv 通道 2 修复：同 PR_open（openat2 已改写为 openat，
         * 也走这里） */
        if (is_proc_self_auxv(tracee, path) && tracee->auxv_host_path != NULL) {
            status = set_sysarg_path(tracee, tracee->auxv_host_path, SYSARG_2);
            if (status < 0)
                break;
            break;
        }

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
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;

        status = translate_path2(tracee, dirfd, path, SYSARG_2, SYMLINK);
        break;

    case PR_mkdirat:
        dirfd = peek_reg(tracee, CURRENT, SYSARG_1);

        status = get_sysarg_path(tracee, path, SYSARG_2);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, path);
        if (status < 0)
            break;

        /* 上游 c48312521：目标由内核创建，只翻译父目录。 */
        status = translate_path2_parent(tracee, dirfd, path, SYSARG_2);
        break;

    case PR_link:
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

        /* 上游 100dd09fb：link 的 newpath 由内核创建，只翻译父目录。 */
        status = translate_path2_parent(tracee, AT_FDCWD, newpath, SYSARG_2);
        break;

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
        /* 上游 c48312521：SYSARG_1 是链接内容不是路径；只翻译
         * linkpath（SYSARG_2）的父目录。 */
        status = translate_path2_parent(tracee, AT_FDCWD, newpath, SYSARG_2);
        break;

    case PR_symlinkat:
        newdirfd = peek_reg(tracee, CURRENT, SYSARG_2);

        status = get_sysarg_path(tracee, newpath, SYSARG_3);
        if (status < 0)
            break;
        status = check_bind_readonly(tracee, newpath);
        if (status < 0)
            break;

        /* 上游 c48312521：目标由内核创建，只翻译父目录。 */
        status = translate_path2_parent(tracee, newdirfd, newpath, SYSARG_3);
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
            /* 真实标志已被 neoproot 提前设置（seccomp 过滤器前提），
             * guest 的 SET 必然成功——enter 侧直接标记，无需 exit 停靠。
             * （原 571a6c0 移植用 sysexit_pending+PTRACE_SYSCALL 强制
             * 停靠：旧 seccomp 模式下会触发 IS_IN_SYSENTER 断言，改此
             * 安全写法。）seen_execve 守卫：loader 在初始 execve 前也调
             * SET，那次不算 guest 意图。 */
            if (tracee->seen_execve)
                tracee->no_new_privs = true;
        }
        break;

#ifdef __ANDROID__
    case PR_ioctl: {
        word_t cmd = peek_reg(tracee, CURRENT, SYSARG_2);
        word_t arg = peek_reg(tracee, CURRENT, SYSARG_3);

        /* 上游 d30b98846：SIOCGIFINDEX 由 tracer 用 if_nametoindex 回答，
         * 避免 Android 对非 lo 接口 EACCES。 */
        if (cmd == SIOCGIFINDEX && maybe_fake_siocgifindex(tracee, cmd, arg)) {
            poke_reg(tracee, SYSARG_RESULT, 0);
            set_sysnum(tracee, PR_void);
            break;
        }

        if (cmd == TCSETS + 2) {
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
            /* 上游 b2c194db6：部分 Android 版本上 TCSETSF2 直通会
             * EACCES（apt tcsetattr 报 Permission denied），统一映射到
             * TCSETS。 */
            poke_reg(tracee, SYSARG_2, TCSETS);
        }
        break;
    }
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
