#include <errno.h>
#include <sys/socket.h>   // 用于 AF_NETLINK
#include <linux/netlink.h> // 用于 NETLINK_AUDIT

#include "tracee/reg.h"
#include "extension/fake_id0/socket.h"

int handle_socket_exit_end(Tracee *tracee, Config *config)
{
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);

    // 只处理权限错误
    if ((int)result != -EPERM && (int)result != -EACCES)
        return 0;

    // 模拟内核未开启的 audit netlink 功能
    if (peek_reg(tracee, ORIGINAL, SYSARG_1) == AF_NETLINK &&
        peek_reg(tracee, ORIGINAL, SYSARG_3) == NETLINK_AUDIT &&
        config->euid == 0)
    {
        return -EPROTONOSUPPORT;
    }

    return 0;
}
