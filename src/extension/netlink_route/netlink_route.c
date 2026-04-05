#include <errno.h>
#include <linux/netlink.h>
#include <linux/net.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <talloc.h>
#include <unistd.h>

#include "extension/netlink_route/netlink_route.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"

struct NetlinkRouteFd {
    int fd;
    int protocol;
};

struct PendingReply {
    int fd;
    uint8_t *buf;
    size_t len;
    size_t off;
    uint32_t seq;
    uint32_t pid;
};

typedef struct {
    struct NetlinkRouteFd *fds;
    size_t len;
    struct PendingReply *pending;
    size_t pending_len;
    bool force_emulation;
} Config;

static Config *get_config(Extension *extension)
{
    return talloc_get_type_abort(extension->config, Config);
}

static void remember_fd(Config *config, int fd, int protocol)
{
    size_t i;
    for (i = 0; i < config->len; i++) {
        if (config->fds[i].fd == fd) {
            config->fds[i].protocol = protocol;
            return;
        }
    }

    config->fds = talloc_realloc(config, config->fds, struct NetlinkRouteFd, config->len + 1);
    if (!config->fds)
        return;

    config->fds[config->len].fd = fd;
    config->fds[config->len].protocol = protocol;
    config->len++;
}

static void forget_fd(Config *config, int fd)
{
    size_t i;
    for (i = 0; i < config->len; i++) {
        if (config->fds[i].fd == fd) {
            config->fds[i] = config->fds[config->len - 1];
            config->len--;
            return;
        }
    }
}

static bool is_route_fd(Config *config, int fd)
{
    size_t i;
    for (i = 0; i < config->len; i++) {
        if (config->fds[i].fd == fd)
            return config->fds[i].protocol == NETLINK_ROUTE;
    }
    return false;
}

static struct PendingReply *get_pending(Config *config, int fd, bool create)
{
    size_t i;
    for (i = 0; i < config->pending_len; i++) {
        if (config->pending[i].fd == fd)
            return &config->pending[i];
    }

    if (!create)
        return NULL;

    config->pending = talloc_realloc(config, config->pending, struct PendingReply, config->pending_len + 1);
    if (!config->pending)
        return NULL;

    config->pending[config->pending_len].fd = fd;
    config->pending[config->pending_len].buf = NULL;
    config->pending[config->pending_len].len = 0;
    config->pending[config->pending_len].off = 0;
    config->pending[config->pending_len].seq = 0;
    config->pending[config->pending_len].pid = 0;
    config->pending_len++;
    return &config->pending[config->pending_len - 1];
}

static void clear_pending(struct PendingReply *pending)
{
    if (pending->buf) {
        free(pending->buf);
        pending->buf = NULL;
    }
    pending->len = 0;
    pending->off = 0;
}

static int ensure_cap(uint8_t **buf, size_t *cap, size_t need)
{
    if (*cap >= need)
        return 0;
    *cap = (need + 1023) & ~1023UL;
    *buf = realloc(*buf, *cap);
    return *buf ? 0 : -ENOMEM;
}

static int nlmsg_start(uint8_t **buf, size_t *len, size_t *cap,
                       uint16_t type, uint16_t flags, uint32_t seq, uint32_t pid,
                       const void *payload, size_t payload_len, size_t *msg_start_out)
{
    size_t msg_start;
    size_t hdr_len = NLMSG_LENGTH(payload_len);

    *len = NLMSG_ALIGN(*len);
    msg_start = *len;
    if (ensure_cap(buf, cap, msg_start + hdr_len) < 0)
        return -ENOMEM;

    struct nlmsghdr *hdr = (struct nlmsghdr *)(*buf + msg_start);
    hdr->nlmsg_len = hdr_len;
    hdr->nlmsg_type = type;
    hdr->nlmsg_flags = flags;
    hdr->nlmsg_seq = seq;
    hdr->nlmsg_pid = pid;

    if (payload_len > 0 && payload)
        memcpy(*buf + msg_start + NLMSG_HDRLEN, payload, payload_len);

    *len = msg_start + hdr_len;
    *msg_start_out = msg_start;
    return 0;
}

static int nlmsg_add_attr(uint8_t **buf, size_t *len, size_t *cap,
                          size_t msg_start, uint16_t type, const void *data, size_t data_len)
{
    struct nlmsghdr *hdr;
    struct rtattr *rta;
    size_t rta_len = RTA_LENGTH(data_len);
    size_t needed = *len + RTA_ALIGN(rta_len);

    if (ensure_cap(buf, cap, needed) < 0)
        return -ENOMEM;

    rta = (struct rtattr *)(*buf + *len);
    rta->rta_type = type;
    rta->rta_len = rta_len;
    if (data_len > 0 && data)
        memcpy(RTA_DATA(rta), data, data_len);

    *len += RTA_ALIGN(rta_len);

    hdr = (struct nlmsghdr *)(*buf + msg_start);
    hdr->nlmsg_len = *len - msg_start;
    return 0;
}

static int nlmsg_add_done(uint8_t **buf, size_t *len, size_t *cap, uint32_t seq, uint32_t pid)
{
    size_t msg_start;
    return nlmsg_start(buf, len, cap, NLMSG_DONE, 0, seq, pid, NULL, 0, &msg_start);
}

static int ipv4_prefixlen(const struct sockaddr_in *mask)
{
    uint32_t m = ntohl(mask->sin_addr.s_addr);
    int bits = 0;
    while (m) {
        bits += m & 1;
        m >>= 1;
    }
    return bits;
}

static int build_link_reply(uint8_t **out_buf, size_t *out_len, uint32_t seq, uint32_t pid)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -errno;

    struct ifconf ifc = {0};
    char buf[8192];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        close(sock);
        return -errno;
    }

    size_t len = 0, cap = 0;
    uint8_t *out = NULL;
    int status = 0;

    for (int i = 0; i < ifc.ifc_len / (int)sizeof(struct ifreq); i++) {
        struct ifreq *ifr = &ifc.ifc_req[i];
        struct ifreq ifr_flags_req = {0};
        strncpy(ifr_flags_req.ifr_name, ifr->ifr_name, IFNAMSIZ-1);

        if (ioctl(sock, SIOCGIFFLAGS, &ifr_flags_req) < 0)
            continue;

        unsigned int index = if_nametoindex(ifr->ifr_name);
        if (!index)
            continue;

        struct ifinfomsg ifi = {0};
        ifi.ifi_family = AF_UNSPEC;
        ifi.ifi_index = (int)index;
        ifi.ifi_flags = ifr_flags_req.ifr_flags;
        ifi.ifi_change = 0xFFFFFFFFU;

        size_t msg_start;
        status = nlmsg_start(&out, &len, &cap, RTM_NEWLINK,
                             NLM_F_MULTI, seq, pid, &ifi, sizeof(ifi), &msg_start);
        if (status < 0)
            break;

        status = nlmsg_add_attr(&out, &len, &cap, msg_start, IFLA_IFNAME,
                                ifr->ifr_name, strlen(ifr->ifr_name)+1);
        if (status < 0)
            break;
    }

    if (status == 0)
        status = nlmsg_add_done(&out, &len, &cap, seq, pid);

    close(sock);
    if (status < 0) {
        free(out);
        return status;
    }

    *out_buf = out;
    *out_len = len;
    return 0;
}

static int build_addr_reply(uint8_t **out_buf, size_t *out_len, uint32_t seq, uint32_t pid)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -errno;

    struct ifconf ifc = {0};
    char buf[8192];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        close(sock);
        return -errno;
    }

    size_t len = 0, cap = 0;
    uint8_t *out = NULL;
    int status = 0;

    for (int i = 0; i < ifc.ifc_len / (int)sizeof(struct ifreq); i++) {
        struct ifreq *ifr = &ifc.ifc_req[i];
        if (ifr->ifr_addr.sa_family != AF_INET)
            continue;

        unsigned int index = if_nametoindex(ifr->ifr_name);
        if (!index)
            continue;

        struct ifreq ifr_mask = {0};
        strncpy(ifr_mask.ifr_name, ifr->ifr_name, IFNAMSIZ-1);
        if (ioctl(sock, SIOCGIFNETMASK, &ifr_mask) < 0)
            continue;

        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr->ifr_addr;
        struct sockaddr_in *mask = (struct sockaddr_in *)&ifr_mask.ifr_netmask;

        struct ifaddrmsg ifa = {0};
        ifa.ifa_family = AF_INET;
        ifa.ifa_prefixlen = (uint8_t)ipv4_prefixlen(mask);
        ifa.ifa_scope = RT_SCOPE_UNIVERSE;
        ifa.ifa_index = (int)index;

        size_t msg_start;
        status = nlmsg_start(&out, &len, &cap, RTM_NEWADDR,
                             NLM_F_MULTI, seq, pid, &ifa, sizeof(ifa), &msg_start);
        if (status < 0)
            break;

        status = nlmsg_add_attr(&out, &len, &cap, msg_start, IFA_ADDRESS,
                                &sin->sin_addr, sizeof(sin->sin_addr));
        if (status < 0)
            break;
        status = nlmsg_add_attr(&out, &len, &cap, msg_start, IFA_LOCAL,
                                &sin->sin_addr, sizeof(sin->sin_addr));
        if (status < 0)
            break;
        status = nlmsg_add_attr(&out, &len, &cap, msg_start, IFA_LABEL,
                                ifr->ifr_name, strlen(ifr->ifr_name)+1);
        if (status < 0)
            break;
    }

    if (status == 0)
        status = nlmsg_add_done(&out, &len, &cap, seq, pid);

    close(sock);
    if (status < 0) {
        free(out);
        return status;
    }

    *out_buf = out;
    *out_len = len;
    return 0;
}

static int build_reply_for_request(uint16_t type, uint32_t seq, uint32_t pid,
                                   uint8_t **out_buf, size_t *out_len)
{
    switch (type) {
        case RTM_GETLINK: return build_link_reply(out_buf, out_len, seq, pid);
        case RTM_GETADDR: return build_addr_reply(out_buf, out_len, seq, pid);
        default: return -EOPNOTSUPP;
    }
}

static void handle_socket_exit(Tracee *tracee, Config *config)
{
    int fd = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (fd < 0) return;

    int domain = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
    int protocol = (int)peek_reg(tracee, ORIGINAL, SYSARG_3);

    if (domain == AF_NETLINK)
        remember_fd(config, fd, protocol);
}

static void handle_socketcall_exit(Tracee *tracee, Config *config)
{
    long args[6];
    int call = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
    if (call != SYS_SOCKET) return;

    int fd = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (fd < 0) return;

    if (read_data(tracee, args, peek_reg(tracee, ORIGINAL, SYSARG_2), sizeof(args)) < 0)
        return;

    int domain = (int)args[0];
    int protocol = (int)args[2];

    if (domain == AF_NETLINK)
        remember_fd(config, fd, protocol);
}

static void handle_close_exit(Tracee *tracee, Config *config)
{
    if ((int)peek_reg(tracee, CURRENT, SYSARG_RESULT) < 0)
        return;

    int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
    struct PendingReply *pending = get_pending(config, fd, false);
    if (pending)
        clear_pending(pending);
    forget_fd(config, fd);
}

static void handle_bind_exit(Tracee *tracee, Config *config)
{
    int rc = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (rc != -EACCES && rc != -EPERM)
        return;

    int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
    if (!is_route_fd(config, fd))
        return;

    word_t addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    word_t addr_len = peek_reg(tracee, ORIGINAL, SYSARG_3);
    struct sockaddr_nl addr;

    if (addr_ptr == 0 || addr_len < sizeof(addr))
        return;
    if (read_data(tracee, &addr, addr_ptr, sizeof(addr)) < 0)
        return;
    if (addr.nl_family != AF_NETLINK)
        return;

    poke_reg(tracee, SYSARG_RESULT, 0);
}

static void handle_sendto_enter(Tracee *tracee, Config *config)
{
    if (!config->force_emulation)
        return;

    int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
    if (!is_route_fd(config, fd))
        return;

    word_t buf_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    word_t buf_len = peek_reg(tracee, ORIGINAL, SYSARG_3);
    struct nlmsghdr hdr;

    if (buf_ptr == 0 || buf_len < sizeof(hdr))
        return;
    if (read_data(tracee, &hdr, buf_ptr, sizeof(hdr)) < 0)
        return;

    struct PendingReply *pending = get_pending(config, fd, true);
    if (!pending)
        return;

    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int status = build_reply_for_request(hdr.nlmsg_type, hdr.nlmsg_seq, hdr.nlmsg_pid,
                                         &reply, &reply_len);
    if (status < 0)
        return;

    clear_pending(pending);
    pending->buf = reply;
    pending->len = reply_len;
    pending->off = 0;
    pending->seq = hdr.nlmsg_seq;
    pending->pid = hdr.nlmsg_pid;

    poke_reg(tracee, SYSARG_RESULT, buf_len);
    set_sysnum(tracee, PR_void);
}

static void handle_sendto_exit(Tracee *tracee, Config *config)
{
    int rc = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (rc != -EACCES && rc != -EPERM)
        return;

    int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
    if (!is_route_fd(config, fd))
        return;

    word_t buf_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    word_t buf_len = peek_reg(tracee, ORIGINAL, SYSARG_3);
    struct nlmsghdr hdr;

    if (buf_ptr == 0 || buf_len < sizeof(hdr))
        return;
    if (read_data(tracee, &hdr, buf_ptr, sizeof(hdr)) < 0)
        return;

    struct PendingReply *pending = get_pending(config, fd, true);
    if (!pending)
        return;

    uint8_t *reply = NULL;
    size_t reply_len = 0;
    int status = build_reply_for_request(hdr.nlmsg_type, hdr.nlmsg_seq, hdr.nlmsg_pid,
                                         &reply, &reply_len);
    if (status < 0)
        return;

    clear_pending(pending);
    pending->buf = reply;
    pending->len = reply_len;
    pending->off = 0;
    pending->seq = hdr.nlmsg_seq;
    pending->pid = hdr.nlmsg_pid;

    poke_reg(tracee, SYSARG_RESULT, buf_len);
}

static int serve_pending_recvfrom(Tracee *tracee, struct PendingReply *pending)
{
    if (pending->off >= pending->len)
        return 0;

    word_t buf_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    word_t buf_len = peek_reg(tracee, ORIGINAL, SYSARG_3);
    if (buf_ptr == 0 || buf_len == 0)
        return 0;

    size_t avail = pending->len - pending->off;
    size_t to_copy = (avail < buf_len) ? avail : buf_len;

    if (write_data(tracee, buf_ptr, pending->buf + pending->off, to_copy) < 0)
        return 0;

    word_t addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_5);
    word_t addrlen_ptr = peek_reg(tracee, ORIGINAL, SYSARG_6);
    if (addr_ptr && addrlen_ptr) {
        struct sockaddr_nl addr = {0};
        addr.nl_family = AF_NETLINK;
        write_data(tracee, addr_ptr, &addr, sizeof(addr));
        poke_int32(tracee, addrlen_ptr, sizeof(addr));
    }

    pending->off += to_copy;
    if (pending->off >= pending->len)
        clear_pending(pending);

    poke_reg(tracee, SYSARG_RESULT, (word_t)to_copy);
    set_sysnum(tracee, PR_void);
    return 1;
}

static int serve_pending_recvmsg(Tracee *tracee, struct PendingReply *pending)
{
    if (pending->off >= pending->len)
        return 0;

    word_t msg_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    struct msghdr msg;
    if (msg_ptr == 0 || read_data(tracee, &msg, msg_ptr, sizeof(msg)) < 0)
        return 0;

    struct iovec iov;
    if (!msg.msg_iov || msg.msg_iovlen == 0 || read_data(tracee, &iov, (word_t)msg.msg_iov, sizeof(iov)) < 0)
        return 0;

    size_t avail = pending->len - pending->off;
    size_t to_copy = (avail < iov.iov_len) ? avail : iov.iov_len;
    if (to_copy == 0)
        return 0;

    if (write_data(tracee, (word_t)iov.iov_base, pending->buf + pending->off, to_copy) < 0)
        return 0;

    if (msg.msg_name && msg.msg_namelen >= sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl addr = {0};
        addr.nl_family = AF_NETLINK;
        write_data(tracee, (word_t)msg.msg_name, &addr, sizeof(addr));
        msg.msg_namelen = sizeof(addr);
        write_data(tracee, msg_ptr, &msg, sizeof(msg));
    }

    pending->off += to_copy;
    if (pending->off >= pending->len)
        clear_pending(pending);

    poke_reg(tracee, SYSARG_RESULT, (word_t)to_copy);
    set_sysnum(tracee, PR_void);
    return 1;
}

int netlink_route_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
    (void)data1;
    (void)data2;

    switch (event) {
        case INITIALIZATION: {
            static const FilteredSysnum filtered_sysnums[] = {
                { PR_socket,     FILTER_SYSEXIT },
                { PR_socketcall, FILTER_SYSEXIT },
                { PR_bind,       FILTER_SYSEXIT },
                { PR_sendto,     FILTER_SYSEXIT },
                { PR_recvfrom,   FILTER_SYSEXIT },
                { PR_recvmsg,    FILTER_SYSEXIT },
                { PR_close,      FILTER_SYSEXIT },
                FILTERED_SYSNUM_END
            };

            Config *config = talloc_zero(extension, Config);
            if (!config)
                return -1;
            config->force_emulation = true;
            extension->config = config;
            extension->filtered_sysnums = (FilteredSysnum *)filtered_sysnums;
            return 0;
        }

        case SYSCALL_ENTER_END: {
            Tracee *tracee = TRACEE(extension);
            Config *config = get_config(extension);
            Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

            switch (sysnum) {
                case PR_sendto:
                    handle_sendto_enter(tracee, config);
                    return 0;

                case PR_recvfrom: {
                    int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
                    struct PendingReply *pending = get_pending(config, fd, false);
                    if (pending)
                        return serve_pending_recvfrom(tracee, pending);
                    if (config->force_emulation && is_route_fd(config, fd)) {
                        poke_reg(tracee, SYSARG_RESULT, (word_t)-EAGAIN);
                        set_sysnum(tracee, PR_void);
                        return 1;
                    }
                    return 0;
                }

                case PR_recvmsg: {
                    int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
                    struct PendingReply *pending = get_pending(config, fd, false);
                    if (pending)
                        return serve_pending_recvmsg(tracee, pending);
                    if (config->force_emulation && is_route_fd(config, fd)) {
                        poke_reg(tracee, SYSARG_RESULT, (word_t)-EAGAIN);
                        set_sysnum(tracee, PR_void);
                        return 1;
                    }
                    return 0;
                }

                default:
                    return 0;
            }
        }

        case SYSCALL_EXIT_END: {
            Tracee *tracee = TRACEE(extension);
            Config *config = get_config(extension);
            Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

            switch (sysnum) {
                case PR_socket:
                    handle_socket_exit(tracee, config);
                    return 0;
                case PR_socketcall:
                    handle_socketcall_exit(tracee, config);
                    return 0;
                case PR_bind:
                    handle_bind_exit(tracee, config);
                    return 0;
                case PR_sendto:
                    handle_sendto_exit(tracee, config);
                    return 0;
                case PR_close:
                    handle_close_exit(tracee, config);
                    return 0;
                default:
                    return 0;
            }
        }

        default:
            return 0;
    }
}
