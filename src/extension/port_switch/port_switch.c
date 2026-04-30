#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <linux/net.h>
#include <stdlib.h>

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"

/* 端口配置：特权端口阈值 + 偏移量 */
#define PORT_THRESHOLD  1024
#define PORT_ADDITION   2000
#define MAX_SOCKET_ARGS 6

/**
 * 获取用户自定义的端口偏移量，从环境变量PROOT_PORT_ADD读取
 * 非法值/未设置时返回默认 PORT_ADDITION
 */
static int get_port_addition(void)
{
    static int cached = -1;
    const char *env;
    char *endptr;
    long value;

    if (cached >= 0)
        return cached;

    env = getenv("PROOT_PORT_ADD");
    if (env == NULL || env[0] == '\0') {
        cached = PORT_ADDITION;
        return cached;
    }

    endptr = NULL;
    value = strtol(env, &endptr, 10);
    if (endptr == env || *endptr != '\0' || value < 0 || value > 65535)
        cached = PORT_ADDITION;
    else
        cached = (int)value;

    return cached;
}

/**
 * 计算偏移后的端口，仅处理特权端口（1~1023）
 */
static in_port_t calc_offset_port(in_port_t original_port)
{
    uint16_t port = ntohs(original_port);
    if (port > 0 && port < PORT_THRESHOLD) {
        return htons(port + get_port_addition());
    }
    return original_port;
}

/**
 * 修改 IPv4 端口并写回内存
 */
static int modify_ipv4_port(Tracee *tracee, word_t addr_ptr, bool is_bind)
{
    struct sockaddr_in in4 = {0};
    int ret = read_data(tracee, &in4, addr_ptr, sizeof(in4));
    if (ret < 0)
        return ret;

    in_port_t old_port = in4.sin_port;
    in4.sin_port = calc_offset_port(old_port);

    if (is_bind && in4.sin_port != old_port) {
        printf("\nATTENTION: Bind requested on port %d\n", ntohs(old_port));
        printf("Port redirected to %d (use this for external connections)\n\n", ntohs(in4.sin_port));
    }

    return write_data(tracee, addr_ptr, &in4, sizeof(in4));
}

/**
 * 修改 IPv6 端口并写回内存
 */
static int modify_ipv6_port(Tracee *tracee, word_t addr_ptr, bool is_bind)
{
    struct sockaddr_in6 in6 = {0};
    int ret = read_data(tracee, &in6, addr_ptr, sizeof(in6));
    if (ret < 0)
        return ret;

    in_port_t old_port = in6.sin6_port;
    in6.sin6_port = calc_offset_port(old_port);

    if (is_bind && in6.sin6_port != old_port) {
        printf("\nATTENTION: Bind requested on port %d\n", ntohs(old_port));
        printf("Port redirected to %d (use this for external connections)\n\n", ntohs(in6.sin6_port));
    }

    return write_data(tracee, addr_ptr, &in6, sizeof(in6));
}

/**
 * 处理标准 socket 系统调用（bind/connect/sendto）
 */
static int handle_standard_socketcall(Tracee *tracee, Sysnum sysnum)
{
    bool is_bind = (sysnum == PR_bind);
    bool is_udp = (sysnum == PR_sendto);
    word_t addr_ptr = 0;

    if (is_udp) {
        addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_5);
        if (addr_ptr == 0)
            return 0;
    } else {
        addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    }

    struct sockaddr_storage addr = {0};
    int ret = read_data(tracee, &addr, addr_ptr, sizeof(addr.ss_family));
    if (ret < 0)
        return ret;

    switch (addr.ss_family) {
    case AF_INET:
        return modify_ipv4_port(tracee, addr_ptr, is_bind);
    case AF_INET6:
        return modify_ipv6_port(tracee, addr_ptr, is_bind);
    default:
        return 0;
    }
}

/**
 * 端口转发扩展核心回调（纯 ARM64 版本）
 */
int port_switch_callback(Extension *extension, ExtensionEvent event,
                         intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -EINVAL;

    switch (event) {
    case INITIALIZATION: {
        static const FilteredSysnum filtered_sysnums[] = {
            { PR_bind,        FILTER_SYSEXIT },
            { PR_connect,     FILTER_SYSEXIT },
            { PR_sendto,      FILTER_SYSEXIT },
            { PR_recvfrom,    FILTER_SYSEXIT },
            FILTERED_SYSNUM_END
        };
        extension->filtered_sysnums = (FilteredSysnum *)filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        Tracee *tracee = TRACEE(extension);
        if (tracee == NULL)
            return 0;

        Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
        int ret = 0;

        switch (sysnum) {
        case PR_bind:
        case PR_connect:
        case PR_sendto:
            ret = handle_standard_socketcall(tracee, sysnum);
            break;

        default:
            break;
        }

        return ret;
    }

    default:
        return 0;
    }
}
