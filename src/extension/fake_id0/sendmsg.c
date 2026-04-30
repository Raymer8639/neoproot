#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/net.h>
#include <string.h>

#include "cli/note.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "syscall/syscall.h"
#include "extension/fake_id0/sendmsg.h"

#define MAX_CONTROLLEN 1024

// 已修复：纯64位模式，移除所有32位兼容逻辑
static void sendmsg_unpack_control_and_len(const Tracee *tracee, const struct msghdr *msghdr,
                                           word_t *out_control, size_t *out_controllen)
{
    (void)tracee; // 根源修复 unused parameter
    *out_control    = (word_t)msghdr->msg_control;
    *out_controllen = msghdr->msg_controllen;
}

// 已修复：纯64位模式，移除所有32位兼容逻辑
static void sendmsg_pack_control(const Tracee *tracee, struct msghdr *msghdr, word_t control)
{
    (void)tracee; // 根源修复 unused parameter
    msghdr->msg_control = (void *)control;
}

// 已修复：纯64位模式，移除所有32位兼容逻辑
static void sendmsg_unpack_cmsghdr(const Tracee *tracee, const struct cmsghdr *cmsghdr,
                                   size_t *out_len, int *out_level, int *out_type)
{
    (void)tracee; // 根源修复 unused parameter
    *out_len   = cmsghdr->cmsg_len;
    *out_level = cmsghdr->cmsg_level;
    *out_type  = cmsghdr->cmsg_type;
}

int handle_sendmsg_enter_end(Tracee *tracee, word_t sysnum)
{
    struct msghdr msg = { 0 };
    unsigned long socket_args[3] = { 0 };
    bool is_socketcall = (sysnum == PR_socketcall);
    size_t sz_msghdr, sz_cmsghdr, align_mask;
    word_t msg_control, hdr_addr;
    size_t msg_controllen, pos;
    char cmsg_buf[MAX_CONTROLLEN];
    bool modified = false;
    int ret;

    // 已修复：纯64位模式，固定结构大小与对齐，移除32位兼容注释与分支
    sz_msghdr  = sizeof(struct msghdr);
    sz_cmsghdr = sizeof(struct cmsghdr);
    align_mask = sizeof(long) - 1;

    // 读取 msghdr
    if (!is_socketcall) {
        ret = read_data(tracee, &msg, peek_reg(tracee, CURRENT, SYSARG_2), sz_msghdr);
        if (ret < 0) return ret;
    } else {
        word_t call = peek_reg(tracee, CURRENT, SYSARG_1);
        if (call != SYS_SENDMSG) return 0;

        ret = read_data(tracee, socket_args, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(socket_args));
        if (ret < 0) return ret;
        ret = read_data(tracee, &msg, socket_args[1], sz_msghdr);
        if (ret < 0) return ret;
    }

    sendmsg_unpack_control_and_len(tracee, &msg, &msg_control, &msg_controllen);

    if (msg_control == 0 || msg_controllen == 0)
        return 0;
    if (msg_controllen > MAX_CONTROLLEN) {
        VERBOSE(tracee, 1, "sendmsg: msg_controllen=%zu too big", msg_controllen);
        return 0;
    }

    // 读取控制数据
    ret = read_data(tracee, cmsg_buf, msg_control, msg_controllen);
    if (ret < 0) return ret;

    // 遍历 cmsg
    for (pos = 0; pos + sz_cmsghdr <= msg_controllen; ) {
        size_t cmsg_len;
        int level, type;

        sendmsg_unpack_cmsghdr(tracee, (struct cmsghdr *)&cmsg_buf[pos], &cmsg_len, &level, &type);

        if (cmsg_len < sz_cmsghdr || cmsg_len > msg_controllen - pos)
            break;

        // 替换 SCM_CREDENTIALS
        if (level == SOL_SOCKET && type == SCM_CREDENTIALS) {
            if (cmsg_len == sz_cmsghdr + sizeof(struct ucred)) {
                struct ucred *uc = (struct ucred *)(cmsg_buf + pos + sz_cmsghdr);
                uc->uid = getuid();
                uc->gid = getgid();
                modified = true;
            }
        }

        pos = (pos + cmsg_len + align_mask) & ~align_mask;
    }

    if (!modified)
        return 0;

    // 重写控制缓冲区
    msg_control = alloc_mem(tracee, msg_controllen);
    if (!msg_control) return -ENOMEM;
    ret = write_data(tracee, msg_control, cmsg_buf, msg_controllen);
    if (ret < 0) return -ENOMEM;

    // 重写 msghdr
    hdr_addr = alloc_mem(tracee, sz_msghdr);
    if (!hdr_addr) return -ENOMEM;
    sendmsg_pack_control(tracee, &msg, msg_control);
    ret = write_data(tracee, hdr_addr, &msg, sz_msghdr);
    if (ret < 0) return -ENOMEM;

    // 回写寄存器
    if (!is_socketcall) {
        poke_reg(tracee, SYSARG_2, hdr_addr);
    } else {
        socket_args[1] = hdr_addr;
        ret = set_sysarg_data(tracee, socket_args, sizeof(socket_args), SYSARG_2);
        if (ret < 0) return ret;
    }

    return 0;
}
