#include <errno.h>
#include <talloc.h>
#include <sys/un.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <termios.h>
#include <sched.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>

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

/* ABI-stable rtnetlink constants for loopback reply. */
#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772
#endif
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

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
    Binding **snapshot;
    size_t new_root_len;
    size_t put_old_len = 0;
    char put_old_after[PATH_MAX];
    bool have_put_old = false;
    size_t count = 0;
    size_t i;
    Binding *iter;

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

    new_root_len = strlen(new_root_guest);

    /* 计算 oldroot 在 new_root 下的暴露路径。 */
    if (   new_root_len > 0
        && strncmp(put_old_guest, new_root_guest, new_root_len) == 0
        && (   put_old_guest[new_root_len] == '/'
            || (new_root_len == 1 && new_root_guest[0] == '/'))) {
        const char *after = put_old_guest + (new_root_len == 1 ? 0 : new_root_len);
        if (after[0] == '/' && after[1] != '\0') {
            strncpy(put_old_after, after, PATH_MAX - 1);
            put_old_after[PATH_MAX - 1] = '\0';
            put_old_len = strlen(put_old_after);
            have_put_old = true;
        }
    }

    /* 先快照当前 bindings，避免边遍历边改。 */
    for (iter = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
         iter != (void *) tracee->fs->bindings.guest;
         iter = CIRCLEQ_NEXT(iter, link.guest))
        count++;

    snapshot = talloc_array(tracee->ctx, Binding *, count);
    if (snapshot == NULL)
        return;
    i = 0;
    for (iter = CIRCLEQ_FIRST(tracee->fs->bindings.guest);
         iter != (void *) tracee->fs->bindings.guest && i < count;
         iter = CIRCLEQ_NEXT(iter, link.guest))
        snapshot[i++] = iter;

    /* 切换 root，并把旧 root 暴露到 put_old。 */
    remove_binding_from_all_lists(tracee, root_binding);
    (void) insort_binding3(tracee, tracee->fs, new_root_host, "/");
    if (have_put_old)
        (void) insort_binding3(tracee, tracee->fs, old_root_host, put_old_after);

    for (i = 0; i < count; i++) {
        Binding *b = snapshot[i];
        size_t blen;

        if (b == root_binding || strcmp(b->guest.path, "/") == 0)
            continue;

        blen = strlen(b->guest.path);

        /* new_root 下的 bind 随 pivot 一起移动：/newroot/usr -> /usr。 */
        if (   new_root_len > 0
            && blen > new_root_len
            && strncmp(b->guest.path, new_root_guest, new_root_len) == 0
            && b->guest.path[new_root_len] == '/') {
            (void) insort_binding3(tracee, tracee->fs, b->host.path,
                                   b->guest.path + new_root_len);
            remove_binding_from_all_lists(tracee, b);
            continue;
        }

        /* 其余属于旧 root 树，重新暴露到 put_old 下。 */
        if (have_put_old) {
            char aliased[PATH_MAX];

            if (   strncmp(b->guest.path, put_old_after, put_old_len) == 0
                && (   b->guest.path[put_old_len] == '\0'
                    || b->guest.path[put_old_len] == '/'))
                continue;

            if ((size_t) snprintf(aliased, sizeof(aliased), "%s%s",
                                  put_old_after, b->guest.path)
                >= sizeof(aliased))
                continue;

            (void) insort_binding3(tracee, tracee->fs,
                                   b->host.path, aliased);
        }
    }

    talloc_free(snapshot);
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
    /* 上游 d7f4764：read_string 不保证末尾 NUL，先钉住最后字节。 */
    fstype[sizeof(fstype) - 1] = '\0';

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


/* 上游 4abc88b + d738215：仅当宿主拒绝 AF_NETLINK 时才启用仿真，
 * 避免破坏 stock Linux 上正常使用 netlink 的程序。 */
static bool host_blocks_af_netlink(const Tracee *tracee)
{
    enum { PROBE_UNKNOWN, PROBE_ALLOWED, PROBE_BLOCKED };
    static int cached = PROBE_UNKNOWN;
    struct {
        struct nlmsghdr  nlh;
        struct ifaddrmsg ifa;
    } request;
    struct sockaddr_nl snl;
    const char *blocked_op;
    int fd;
    int saved_errno;

    if (cached != PROBE_UNKNOWN)
        return cached == PROBE_BLOCKED;

    /* 上游 2ecbad5：像 bubblewrap 一样 socket+bind 都探测，有些宿主
     * 允许建 socket 但 bind 被 SELinux/AppArmor/seccomp 拒绝。 */
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        saved_errno = errno;
        blocked_op = "socket";
        goto blocked;
    }

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *) &snl, sizeof(snl)) < 0) {
        saved_errno = errno;
        close(fd);
        blocked_op = "bind";
        goto blocked;
    }

    /* 上游 4638659：socket+bind 成功不代表能写；Android SELinux 常
     * 允许 nlmsg_read 但拒绝 nlmsg_write。用无害 RTM_NEWADDR 探测
     * sendto 是否被 EACCES/EPERM 拦截。 */
    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(request.ifa));
    request.nlh.nlmsg_type  = RTM_NEWADDR;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.nlh.nlmsg_seq   = 1;
    request.ifa.ifa_family  = AF_UNSPEC;

    if (sendto(fd, &request, sizeof(request), MSG_DONTWAIT,
               (struct sockaddr *) &snl, sizeof(snl)) < 0
        && (errno == EACCES || errno == EPERM)) {
        saved_errno = errno;
        close(fd);
        blocked_op = "sendto";
        goto blocked;
    }

    close(fd);
    cached = PROBE_ALLOWED;
    return false;

blocked:
    cached = PROBE_BLOCKED;
    VERBOSE(tracee, 1, "AF_NETLINK %s denied by host (%s); enabling "
                       "AF_UNIX fallback for sandbox helpers",
            blocked_op, strerror(saved_errno));
    return true;
}

/* 上游 4abc88b：AF_NETLINK 仿真辅助。 */
static bool is_fake_netlink_fd(const Tracee *tracee, int fd)
{
    int i;
    if (fd < 0)
        return false;
    for (i = 0; i < tracee->fake_netlink_fds_count; i++)
        if (tracee->fake_netlink_fds[i] == fd)
            return true;
    return false;
}

static void unmark_fake_netlink_fd(Tracee *tracee, int fd)
{
    int i;
    for (i = 0; i < tracee->fake_netlink_fds_count; i++) {
        if (tracee->fake_netlink_fds[i] == fd) {
            tracee->fake_netlink_fds[i] =
                tracee->fake_netlink_fds[--tracee->fake_netlink_fds_count];
            return;
        }
    }
}

static size_t nl_add_attr(uint8_t *buf, size_t off, size_t max,
                          uint16_t type, const void *data, uint16_t dlen)
{
    struct rtattr *rta;
    size_t space = RTA_SPACE(dlen);

    if (off + space > max)
        return off;

    rta = (struct rtattr *) (buf + off);
    rta->rta_len  = RTA_LENGTH(dlen);
    rta->rta_type = type;
    if (dlen > 0)
        memcpy((char *) rta + RTA_LENGTH(0), data, dlen);
    if (space > RTA_LENGTH(dlen))
        memset(buf + off + RTA_LENGTH(dlen), 0, space - RTA_LENGTH(dlen));
    return off + space;
}

static size_t nl_build_link(uint8_t *buf, size_t off, size_t max,
                            uint32_t seq, uint32_t pid, uint16_t nlflags,
                            int ifindex, uint16_t iftype, uint32_t ifflags,
                            uint32_t mtu, const char *name,
                            const uint8_t *hwaddr, uint8_t hwlen)
{
    size_t start = off;
    struct nlmsghdr *nlh;
    struct ifinfomsg ifi;
    uint32_t txqlen    = 1000;
    uint8_t  operstate = (ifflags & IFF_UP) ? 6 : 2;  /* IF_OPER_UP : _DOWN */
    uint8_t  brd[8];
    size_t len;

    if (start + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifi)) > max)
        return start;

    memset(&ifi, 0, sizeof(ifi));
    ifi.ifi_family = AF_UNSPEC;
    ifi.ifi_type   = iftype;
    ifi.ifi_index  = ifindex;
    ifi.ifi_flags  = ifflags | ((ifflags & IFF_RUNNING) ? IFF_LOWER_UP : 0);
    ifi.ifi_change = 0;

    off = start + NLMSG_HDRLEN;
    memcpy(buf + off, &ifi, sizeof(ifi));
    off += NLMSG_ALIGN(sizeof(ifi));

    off = nl_add_attr(buf, off, max, IFLA_IFNAME, name, strlen(name) + 1);
    off = nl_add_attr(buf, off, max, IFLA_MTU, &mtu, sizeof(mtu));
    off = nl_add_attr(buf, off, max, IFLA_TXQLEN, &txqlen, sizeof(txqlen));
    off = nl_add_attr(buf, off, max, IFLA_OPERSTATE, &operstate, sizeof(operstate));
    if (hwlen > 0) {
        memset(brd, (iftype == ARPHRD_LOOPBACK) ? 0x00 : 0xff, sizeof(brd));
        off = nl_add_attr(buf, off, max, IFLA_ADDRESS, hwaddr, hwlen);
        off = nl_add_attr(buf, off, max, IFLA_BROADCAST, brd, hwlen);
    }

    len = off - start;
    nlh = (struct nlmsghdr *) (buf + start);
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = RTM_NEWLINK;
    nlh->nlmsg_flags = nlflags;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return start + NLMSG_ALIGN(len);
}

static size_t nl_build_addr(uint8_t *buf, size_t off, size_t max,
                            uint32_t seq, uint32_t pid, uint16_t nlflags,
                            int family, int ifindex,
                            const uint8_t *addr, uint8_t addrlen,
                            uint8_t prefixlen, uint8_t scope, const char *label)
{
    size_t start = off;
    struct nlmsghdr *nlh;
    struct ifaddrmsg ifa;
    size_t len;

    if (start + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(ifa)) > max)
        return start;

    memset(&ifa, 0, sizeof(ifa));
    ifa.ifa_family    = family;
    ifa.ifa_prefixlen = prefixlen;
    ifa.ifa_flags     = IFA_F_PERMANENT;
    ifa.ifa_scope     = scope;
    ifa.ifa_index     = ifindex;

    off = start + NLMSG_HDRLEN;
    memcpy(buf + off, &ifa, sizeof(ifa));
    off += NLMSG_ALIGN(sizeof(ifa));

    off = nl_add_attr(buf, off, max, IFA_ADDRESS, addr, addrlen);
    off = nl_add_attr(buf, off, max, IFA_LOCAL, addr, addrlen);
    if (family == AF_INET && label != NULL)
        off = nl_add_attr(buf, off, max, IFA_LABEL, label, strlen(label) + 1);

    len = off - start;
    nlh = (struct nlmsghdr *) (buf + start);
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = RTM_NEWADDR;
    nlh->nlmsg_flags = nlflags;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return start + NLMSG_ALIGN(len);
}

static size_t nl_build_done(uint8_t *buf, size_t off, size_t max,
                            uint32_t seq, uint32_t pid)
{
    struct nlmsghdr *nlh;
    int32_t error = 0;
    size_t len = NLMSG_HDRLEN + sizeof(error);

    if (off + NLMSG_ALIGN(len) > max)
        return off;

    nlh = (struct nlmsghdr *) (buf + off);
    memcpy(buf + off + NLMSG_HDRLEN, &error, sizeof(error));
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = NLMSG_DONE;
    nlh->nlmsg_flags = NLM_F_MULTI;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return off + NLMSG_ALIGN(len);
}

static size_t nl_build_error(uint8_t *buf, size_t off, size_t max,
                             uint32_t seq, uint32_t pid, int error)
{
    struct nlmsghdr *nlh;
    struct nlmsgerr err;
    size_t len = NLMSG_HDRLEN + sizeof(err);

    if (off + NLMSG_ALIGN(len) > max)
        return off;

    memset(&err, 0, sizeof(err));
    err.error = error;

    nlh = (struct nlmsghdr *) (buf + off);
    memcpy(buf + off + NLMSG_HDRLEN, &err, sizeof(err));
    nlh->nlmsg_len   = len;
    nlh->nlmsg_type  = NLMSG_ERROR;
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_seq   = seq;
    nlh->nlmsg_pid   = pid;
    return off + NLMSG_ALIGN(len);
}

static bool nl_request_is_loopback(const uint8_t *req, size_t req_len)
{
    const struct ifinfomsg *ifi;
    size_t off = NLMSG_HDRLEN;
    char name[IFNAMSIZ] = { 0 };
    bool have_name = false;
    int ifindex;

    if (req_len < off + sizeof(*ifi))
        return true;

    ifi = (const struct ifinfomsg *) (req + off);
    ifindex = ifi->ifi_index;

    off += NLMSG_ALIGN(sizeof(*ifi));
    while (off + sizeof(struct rtattr) <= req_len) {
        const struct rtattr *rta = (const struct rtattr *) (req + off);
        size_t rlen = rta->rta_len;

        if (rlen < sizeof(*rta) || off + rlen > req_len)
            break;
        if (rta->rta_type == IFLA_IFNAME) {
            size_t dlen = rlen - RTA_LENGTH(0);
            size_t cpy  = dlen < sizeof(name) ? dlen : sizeof(name) - 1;
            memcpy(name, (const char *) rta + RTA_LENGTH(0), cpy);
            name[cpy] = '\0';
            have_name = true;
        }
        off += RTA_ALIGN(rlen);
    }

    if (have_name)
        return strcmp(name, "lo") == 0;
    return ifindex == 0 || ifindex == 1;
}

static int write_fake_netlink_sockname(Tracee *tracee, word_t addr_ptr,
                                       word_t size_ptr)
{
    struct sockaddr_nl snl;
    uint32_t in_size;
    uint32_t out_size;

    if (size_ptr == 0)
        return -EINVAL;

    in_size = peek_uint32(tracee, size_ptr);
    if (errno != 0)
        return -errno;

    memset(&snl, 0, sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_pid    = (uint32_t) tracee->pid;

    if (addr_ptr != 0 && in_size > 0) {
        uint32_t copy = in_size < sizeof(snl) ? in_size : sizeof(snl);
        if (write_data(tracee, addr_ptr, &snl, copy) < 0)
            return -EFAULT;
    }

    out_size = sizeof(snl);
    poke_uint32(tracee, size_ptr, out_size);
    if (errno != 0)
        return -errno;

    return 0;
}

/* 上游 208a06c：真实主机接口枚举辅助。 */
static uint8_t nl_prefixlen(const uint8_t *mask, size_t len)
{
    uint8_t bits = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        uint8_t b = mask[i];
        if (b == 0xff) {
            bits += 8;
            continue;
        }
        while (b & 0x80) {
            bits++;
            b <<= 1;
        }
        break;
    }
    return bits;
}

static uint8_t nl_addr_scope(int family, const uint8_t *addr)
{
    if (family == AF_INET) {
        if (addr[0] == 127)
            return RT_SCOPE_HOST;
        if (addr[0] == 169 && addr[1] == 254)
            return RT_SCOPE_LINK;
        return RT_SCOPE_UNIVERSE;
    } else {
        static const uint8_t loop[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        if (memcmp(addr, loop, 16) == 0)
            return RT_SCOPE_HOST;
        if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80)
            return RT_SCOPE_LINK;
        return RT_SCOPE_UNIVERSE;
    }
}

static size_t nl_build_loopback_link(uint8_t *buf, size_t off, size_t max,
                                     uint32_t seq, uint32_t pid, uint16_t nlflags)
{
    static const uint8_t zero[6] = { 0 };
    return nl_build_link(buf, off, max, seq, pid, nlflags, 1, ARPHRD_LOOPBACK,
                         IFF_UP | IFF_LOOPBACK | IFF_RUNNING, 65536, "lo", zero, 6);
}

static size_t nl_build_loopback_addr(uint8_t *buf, size_t off, size_t max,
                                     uint32_t seq, uint32_t pid, int family,
                                     uint16_t nlflags)
{
    static const uint8_t v4[4]  = { 127, 0, 0, 1 };
    static const uint8_t v6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    if (family == AF_INET6)
        return nl_build_addr(buf, off, max, seq, pid, nlflags, AF_INET6, 1,
                             v6, 16, 128, RT_SCOPE_HOST, NULL);
    return nl_build_addr(buf, off, max, seq, pid, nlflags, AF_INET, 1,
                         v4, 4, 8, RT_SCOPE_HOST, "lo");
}

static int nl_request_link_target(const uint8_t *req, size_t req_len,
                                  char name[IFNAMSIZ])
{
    const struct ifinfomsg *ifi;
    size_t off = NLMSG_HDRLEN;
    int ifindex;

    name[0] = '\0';
    if (req_len < off + sizeof(*ifi))
        return 0;
    ifi = (const struct ifinfomsg *) (req + off);
    ifindex = ifi->ifi_index;

    off += NLMSG_ALIGN(sizeof(*ifi));
    while (off + sizeof(struct rtattr) <= req_len) {
        const struct rtattr *rta = (const struct rtattr *) (req + off);
        size_t rlen = rta->rta_len;

        if (rlen < sizeof(*rta) || off + rlen > req_len)
            break;
        if (rta->rta_type == IFLA_IFNAME) {
            size_t dlen = rlen - RTA_LENGTH(0);
            size_t cpy  = dlen < IFNAMSIZ ? dlen : IFNAMSIZ - 1;
            memcpy(name, (const char *) rta + RTA_LENGTH(0), cpy);
            name[cpy] = '\0';
        }
        off += RTA_ALIGN(rlen);
    }
    return ifindex;
}

static size_t build_host_links(uint8_t *out, size_t max, uint32_t seq,
                               uint32_t pid, const char *want_name,
                               int want_index, bool dump, int *built)
{
    struct ifaddrs *ifaddr, *ifa;
    char seen[64][IFNAMSIZ];
    int seen_count = 0;
    size_t off = 0;
    int sock;

    *built = 0;
    if (getifaddrs(&ifaddr) != 0)
        return 0;
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        uint32_t ifflags;
        uint16_t iftype;
        uint32_t mtu;
        uint8_t  hwaddr[8] = { 0 };
        uint8_t  hwlen = 0;
        int ifindex;
        int i;
        bool dup = false;

        if (ifa->ifa_name == NULL)
            continue;
        for (i = 0; i < seen_count; i++)
            if (strncmp(seen[i], ifa->ifa_name, IFNAMSIZ) == 0) {
                dup = true;
                break;
            }
        if (dup)
            continue;
        if (seen_count < 64) {
            strncpy(seen[seen_count], ifa->ifa_name, IFNAMSIZ - 1);
            seen[seen_count][IFNAMSIZ - 1] = '\0';
            seen_count++;
        }

        ifflags = ifa->ifa_flags;
        iftype  = (ifflags & IFF_LOOPBACK) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        mtu     = (ifflags & IFF_LOOPBACK) ? 65536 : 1500;
        ifindex = (int) if_nametoindex(ifa->ifa_name);

        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *) ifa->ifa_addr;
            if (sll->sll_ifindex != 0)
                ifindex = sll->sll_ifindex;
            iftype = sll->sll_hatype;
            if (sll->sll_halen > 0 && sll->sll_halen <= sizeof(hwaddr)) {
                memcpy(hwaddr, sll->sll_addr, sll->sll_halen);
                hwlen = sll->sll_halen;
            }
        }

        if (sock >= 0) {
            struct ifreq ifr;

            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            if (ioctl(sock, SIOCGIFMTU, &ifr) == 0)
                mtu = ifr.ifr_mtu;
            if (hwlen == 0) {
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    iftype = ifr.ifr_hwaddr.sa_family;
                    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
                    hwlen = 6;
                }
            }
        }

        if (!dump) {
            if (want_name != NULL && want_name[0] != '\0') {
                if (strcmp(want_name, ifa->ifa_name) != 0)
                    continue;
            } else if (want_index > 0 && ifindex != want_index) {
                continue;
            }
        }

        if (off + 256 > max)
            break;
        off = nl_build_link(out, off, max, seq, pid,
                            dump ? NLM_F_MULTI : 0, ifindex, iftype,
                            ifflags, mtu, ifa->ifa_name, hwaddr, hwlen);
        (*built)++;
        if (!dump)
            break;
    }

    if (sock >= 0)
        close(sock);
    freeifaddrs(ifaddr);
    return off;
}

static size_t build_host_addrs(uint8_t *out, size_t max, uint32_t seq,
                               uint32_t pid, int want_family, bool dump,
                               int *built)
{
    struct ifaddrs *ifaddr, *ifa;
    size_t off = 0;

    *built = 0;
    if (getifaddrs(&ifaddr) != 0)
        return 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        const uint8_t *addr;
        const uint8_t *mask = NULL;
        uint8_t addrlen, masklen = 0;
        uint8_t prefixlen, scope;
        int family, ifindex;

        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;
        if (want_family != AF_UNSPEC && family != want_family)
            continue;

        if (family == AF_INET) {
            addr = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            addrlen = 4;
            if (ifa->ifa_netmask != NULL) {
                mask = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;
                masklen = 4;
            }
        } else {
            addr = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            addrlen = 16;
            if (ifa->ifa_netmask != NULL) {
                mask = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
                masklen = 16;
            }
        }

        prefixlen = (mask != NULL) ? nl_prefixlen(mask, masklen)
                                   : (family == AF_INET ? 32 : 128);
        scope = nl_addr_scope(family, addr);
        ifindex = (int) if_nametoindex(ifa->ifa_name);

        if (off + 256 > max)
            break;
        off = nl_build_addr(out, off, max, seq, pid,
                            dump ? NLM_F_MULTI : 0, family, ifindex,
                            addr, addrlen, prefixlen, scope, ifa->ifa_name);
        (*built)++;
    }

    freeifaddrs(ifaddr);
    return off;
}

static size_t relay_route_dump(const uint8_t *req, size_t req_len,
                               uint8_t *out, size_t max,
                               uint32_t seq, uint32_t pid)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
    } dreq;
    struct sockaddr_nl sa;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    uint8_t family = (req_len > NLMSG_HDRLEN) ? req[NLMSG_HDRLEN] : 0;
    size_t off = 0;
    bool done = false;
    bool saw_done = false;
    int fd;
    int rounds;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return 0;
    (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&dreq, 0, sizeof(dreq));
    dreq.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    dreq.nlh.nlmsg_type  = RTM_GETROUTE;
    dreq.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    dreq.nlh.nlmsg_seq   = seq;
    dreq.rtm.rtm_family  = family;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &dreq, dreq.nlh.nlmsg_len, 0,
               (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }

    for (rounds = 0; !done && rounds < 64; rounds++) {
        uint8_t buf[8192] __attribute__((aligned(8)));
        struct nlmsghdr *h;
        ssize_t n;
        size_t len;

        n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        len = (size_t) n;
        for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, len);
             h = NLMSG_NEXT(h, len)) {
            size_t mlen = h->nlmsg_len;
            size_t aligned = NLMSG_ALIGN(mlen);

            if (off + aligned + 64 > max) {
                done = true;
                break;
            }
            h->nlmsg_seq = seq;
            h->nlmsg_pid = pid;
            memcpy(out + off, h, mlen);
            if (aligned > mlen)
                memset(out + off + mlen, 0, aligned - mlen);
            off += aligned;
            if (h->nlmsg_type == NLMSG_DONE) {
                saw_done = true;
                done = true;
                break;
            }
        }
    }

    close(fd);

    if (off == 0)
        return 0;
    if (!saw_done)
        off = nl_build_done(out, off, max, seq, pid);
    return off;
}

static void build_fake_netlink_reply(Tracee *tracee, word_t buf_addr,
                                     word_t buf_len)
{
    uint8_t req[256] __attribute__((aligned(8)));
    size_t  req_len;
    struct nlmsghdr hdr;
    uint8_t *out = tracee->fake_netlink_reply;
    size_t   max = sizeof(tracee->fake_netlink_reply);
    uint32_t pid = (uint32_t) tracee->pid;
    uint32_t seq = 0;
    uint16_t type, flags;
    bool dump;
    size_t off = 0;

    tracee->fake_netlink_reply_len = 0;

    if (buf_addr == 0 || buf_len < sizeof(hdr))
        goto reply;
    req_len = buf_len < sizeof(req) ? buf_len : sizeof(req);
    if (read_data(tracee, req, buf_addr, req_len) < 0)
        goto reply;

    memcpy(&hdr, req, sizeof(hdr));
    type  = hdr.nlmsg_type;
    flags = hdr.nlmsg_flags;
    seq   = hdr.nlmsg_seq;
    dump  = (flags & NLM_F_DUMP) == NLM_F_DUMP;

    switch (type) {
    case RTM_GETLINK: {
        char want_name[IFNAMSIZ];
        int want_index = nl_request_link_target(req, req_len, want_name);
        int n = 0;

        off = build_host_links(out, max, seq, pid,
                               dump ? NULL : want_name,
                               dump ? 0 : want_index, dump, &n);
        if (n == 0) {
            off = 0;
            if (dump)
                off = nl_build_loopback_link(out, off, max, seq, pid, NLM_F_MULTI);
            else if (nl_request_is_loopback(req, req_len))
                off = nl_build_loopback_link(out, off, max, seq, pid, 0);
            else
                off = nl_build_error(out, off, max, seq, pid, -ENODEV);
        }
        if (dump)
            off = nl_build_done(out, off, max, seq, pid);
        break;
    }

    case RTM_GETADDR: {
        uint8_t family = (req_len > NLMSG_HDRLEN) ? req[NLMSG_HDRLEN] : 0;
        int want_family = (family == AF_INET || family == AF_INET6)
                          ? family : AF_UNSPEC;
        int n = 0;

        off = build_host_addrs(out, max, seq, pid, want_family, dump, &n);
        if (n == 0) {
            off = 0;
            if (family == 0 || family == AF_INET)
                off = nl_build_loopback_addr(out, off, max, seq, pid,
                                             AF_INET, dump ? NLM_F_MULTI : 0);
            if (family == 0 || family == AF_INET6)
                off = nl_build_loopback_addr(out, off, max, seq, pid,
                                             AF_INET6, dump ? NLM_F_MULTI : 0);
        }
        if (dump)
            off = nl_build_done(out, off, max, seq, pid);
        break;
    }

    case RTM_GETROUTE:
        if (dump) {
            off = relay_route_dump(req, req_len, out, max, seq, pid);
            if (off == 0)
                off = nl_build_done(out, off, max, seq, pid);
        } else {
            off = nl_build_error(out, off, max, seq, pid, 0);
        }
        break;

    default:
        if (dump)
            off = nl_build_done(out, off, max, seq, pid);
        else
            off = nl_build_error(out, off, max, seq, pid, 0);
        break;
    }

reply:
    /* 上游 c81a1c9：绝不返回零长度 netlink 消息。 */
    if (off == 0)
        off = nl_build_error(out, off, max, seq, pid, -EINVAL);

    tracee->fake_netlink_reply_len = off;
}

static size_t scatter_fake_netlink_reply(Tracee *tracee, word_t iov_ptr,
                                         word_t iov_count)
{
    size_t reply_len = tracee->fake_netlink_reply_len;
    size_t w = sizeof_word(tracee);
    size_t done = 0;
    word_t i;

    for (i = 0; i < iov_count && done < reply_len; i++) {
        word_t base = peek_word(tracee, iov_ptr + i * 2 * w);
        word_t len  = (errno == 0) ? peek_word(tracee, iov_ptr + i * 2 * w + w) : 0;
        size_t chunk;

        errno = 0;
        chunk = reply_len - done;
        if (chunk > len)
            chunk = len;
        if (base != 0 && chunk > 0) {
            if (write_data(tracee, base,
                           tracee->fake_netlink_reply + done, chunk) < 0)
                break;
        }
        done += chunk;
    }

    return done;
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
        /* 上游 4abc88b：关闭假 netlink fd 时从跟踪表移除。 */
        unmark_fake_netlink_fd(tracee, closed_fd);
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

        /* 上游 4abc88b：对已替换成 AF_UNIX 的假 netlink fd，bind
         * 直接假装成功。 */
        if (syscall_number == PR_bind
            && is_fake_netlink_fd(tracee, peek_reg(tracee, CURRENT, SYSARG_1))) {
            poke_reg(tracee, SYSARG_RESULT, 0);
            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }

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

        /* 上游 30e0644：假 netlink fd 返回 sockaddr_nl，避免 iproute2
         * 报 "Wrong address length 2"。 */
        if ((syscall_number == PR_getsockname || syscall_number == PR_getpeername)
            && is_fake_netlink_fd(tracee, peek_reg(tracee, CURRENT, SYSARG_1))) {
            word_t addr_ptr = peek_reg(tracee, CURRENT, SYSARG_2);
            word_t size_ptr = peek_reg(tracee, CURRENT, SYSARG_3);
            int    rc = write_fake_netlink_sockname(tracee, addr_ptr, size_ptr);

            poke_reg(tracee, SYSARG_RESULT, (word_t) rc);
            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }

        size = (int) PEEK_WORD(peek_reg(tracee, ORIGINAL, SYSARG_3), special ? -EINVAL : 0);
        poke_reg(tracee, SYSARG_6, size);

        status = 0;
        break;
    }


    /* 上游 4abc88b：AF_NETLINK 仿真。 */
    case PR_socket: {
        word_t domain = peek_reg(tracee, CURRENT, SYSARG_1);
        word_t protocol = peek_reg(tracee, CURRENT, SYSARG_3);
        if (   domain == AF_NETLINK
            && protocol == NETLINK_ROUTE
            && host_blocks_af_netlink(tracee)) {
            word_t type = peek_reg(tracee, CURRENT, SYSARG_2);
            poke_reg(tracee, SYSARG_1, AF_UNIX);
            poke_reg(tracee, SYSARG_2, SOCK_DGRAM | (type & SOCK_CLOEXEC));
            poke_reg(tracee, SYSARG_3, 0);
            tracee->pending_fake_netlink_socket = true;
            tracee->sysexit_pending = true;
            tracee->restart_how = PTRACE_SYSCALL;
        }
        status = 0;
        break;
    }

    case PR_sendto: {
        int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
        if (is_fake_netlink_fd(tracee, fd)) {
            word_t buf = peek_reg(tracee, CURRENT, SYSARG_2);
            word_t len = peek_reg(tracee, CURRENT, SYSARG_3);

            build_fake_netlink_reply(tracee, buf, len);

            poke_reg(tracee, SYSARG_RESULT, len);
            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }
        status = 0;
        break;
    }

    case PR_sendmsg: {
        int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
        if (is_fake_netlink_fd(tracee, fd)) {
            word_t msghdr_addr = peek_reg(tracee, CURRENT, SYSARG_2);
            size_t w = sizeof_word(tracee);
            word_t total = 0;
            word_t iov_ptr, iov_count;

            if (msghdr_addr != 0) {
                iov_ptr   = peek_word(tracee, msghdr_addr + 2 * w);
                iov_count = (errno == 0)
                            ? peek_word(tracee, msghdr_addr + 3 * w)
                            : 0;
                errno = 0;

                if (iov_ptr != 0 && iov_count > 0) {
                    word_t base = peek_word(tracee, iov_ptr);
                    word_t len  = (errno == 0)
                                  ? peek_word(tracee, iov_ptr + w)
                                  : 0;
                    errno = 0;

                    build_fake_netlink_reply(tracee, base, len);
                    total = len;
                }
            }

            poke_reg(tracee, SYSARG_RESULT, total);
            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }
        status = 0;
        break;
    }

    case PR_recvfrom: {
        int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
        if (is_fake_netlink_fd(tracee, fd)) {
            word_t buf       = peek_reg(tracee, CURRENT, SYSARG_2);
            word_t len       = peek_reg(tracee, CURRENT, SYSARG_3);
            int    flags     = (int) peek_reg(tracee, CURRENT, SYSARG_4);
            word_t addr_ptr  = peek_reg(tracee, CURRENT, SYSARG_5);
            word_t size_ptr  = peek_reg(tracee, CURRENT, SYSARG_6);
            size_t reply_len = tracee->fake_netlink_reply_len;
            size_t copied    = 0;
            size_t result;

            /* 上游 c81a1c9：空接收队列交给真实 socket 报 EAGAIN/阻塞，
             * 不要回零长度消息。 */
            if (reply_len == 0) {
                status = 0;
                break;
            }

            if (buf != 0) {
                copied = len < reply_len ? len : reply_len;
                if (copied > 0 &&
                    write_data(tracee, buf,
                               tracee->fake_netlink_reply, copied) < 0)
                    copied = 0;
            }

            /* MSG_PEEK leaves the reply pending for the real read
             * that follows; MSG_TRUNC asks for the untruncated length. */
            if (!(flags & MSG_PEEK))
                tracee->fake_netlink_reply_len = 0;
            result = (flags & MSG_TRUNC) ? reply_len : copied;

            if (addr_ptr != 0 && size_ptr != 0)
                (void) write_fake_netlink_sockname(tracee, addr_ptr, size_ptr);
            errno = 0;

            poke_reg(tracee, SYSARG_RESULT, (word_t) result);
            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }
        status = 0;
        break;
    }

    case PR_recvmsg: {
        int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
        if (is_fake_netlink_fd(tracee, fd)) {
            word_t msghdr_addr = peek_reg(tracee, CURRENT, SYSARG_2);
            int    flags = (int) peek_reg(tracee, CURRENT, SYSARG_3);
            size_t w = sizeof_word(tracee);
            word_t msg_name = 0;
            word_t iov_ptr = 0, iov_count = 0;
            size_t reply_len = tracee->fake_netlink_reply_len;
            size_t scattered = 0;
            size_t result;

            /* 上游 c81a1c9：同 recvfrom。 */
            if (reply_len == 0) {
                status = 0;
                break;
            }

            if (msghdr_addr != 0) {
                msg_name  = peek_word(tracee, msghdr_addr);
                if (errno != 0) { errno = 0; msg_name = 0; }
                iov_ptr   = peek_word(tracee, msghdr_addr + 2 * w);
                if (errno != 0) { errno = 0; iov_ptr   = 0; }
                iov_count = peek_word(tracee, msghdr_addr + 3 * w);
                if (errno != 0) { errno = 0; iov_count = 0; }
            }

            if (iov_ptr != 0 && iov_count > 0)
                scattered = scatter_fake_netlink_reply(tracee, iov_ptr,
                                                       iov_count);

            /* MSG_PEEK leaves the reply pending for the real read
             * that follows; MSG_TRUNC asks for the untruncated length. */
            if (!(flags & MSG_PEEK))
                tracee->fake_netlink_reply_len = 0;
            result = (flags & MSG_TRUNC) ? reply_len : scattered;

            if (msg_name != 0 && msghdr_addr != 0) {
                struct sockaddr_nl snl;
                uint32_t in_namelen = peek_uint32(tracee, msghdr_addr + w);
                if (errno == 0 && in_namelen > 0) {
                    uint32_t copy = in_namelen < sizeof(snl)
                                    ? in_namelen
                                    : sizeof(snl);
                    memset(&snl, 0, sizeof(snl));
                    snl.nl_family = AF_NETLINK;
                    (void) write_data(tracee, msg_name, &snl, copy);
                    poke_uint32(tracee, msghdr_addr + w,
                                (uint32_t) sizeof(snl));
                }
                errno = 0;
            }

            if (msghdr_addr != 0) {
                poke_uint32(tracee, msghdr_addr + 6 * w,
                            scattered < reply_len ? MSG_TRUNC : 0);
                errno = 0;
            }

            poke_reg(tracee, SYSARG_RESULT, (word_t) result);
            set_sysnum(tracee, PR_void);
            status = 0;
            break;
        }
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
