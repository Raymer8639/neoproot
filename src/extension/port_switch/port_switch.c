#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <linux/net.h>

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"

/* 端口配置：特权端口阈值 + 偏移量 */
#define PORT_THRESHOLD  1024
#define PORT_ADDITION   2000
#define MAX_SOCKET_ARGS 6

/**
 * 计算偏移后的端口，仅处理特权端口（1~1023）
 * @param original_port 原始端口（网络字节序）
 * @return 偏移后的端口（网络字节序），无偏移则返回原端口
 */
static in_port_t calc_offset_port(in_port_t original_port)
{
    uint16_t port = ntohs(original_port);
    if (port > 0 && port < PORT_THRESHOLD) {
        return htons(port + PORT_ADDITION);
    }
    return original_port;
}

/**
 * 修改 IPv4 地址的端口并写回内存
 * @param tracee 进程追踪句柄
 * @param addr_ptr 地址结构体在进程内存中的地址
 * @return 0-成功，非0-错误码
 */
static int modify_ipv4_port(Tracee *tracee, word_t addr_ptr, bool is_bind)
{
    struct sockaddr_in in4 = {0};
    int ret = read_data(tracee, &in4, addr_ptr, sizeof(in4));
    if (ret < 0)
        return ret;

    in_port_t old_port = in4.sin_port;
    in4.sin_port = calc_offset_port(old_port);

    // bind 操作打印端口变更提示
    if (is_bind && in4.sin_port != old_port) {
        printf("\nATTENTION: Bind requested on port %d\n", ntohs(old_port));
        printf("Port redirected to %d (use this for external connections)\n\n", ntohs(in4.sin_port));
    }

    return write_data(tracee, addr_ptr, &in4, sizeof(in4));
}

/**
 * 修改 IPv6 地址的端口并写回内存
 * @param tracee 进程追踪句柄
 * @param addr_ptr 地址结构体在进程内存中的地址
 * @return 0-成功，非0-错误码
 */
static int modify_ipv6_port(Tracee *tracee, word_t addr_ptr, bool is_bind)
{
    struct sockaddr_in6 in6 = {0};
    int ret = read_data(tracee, &in6, addr_ptr, sizeof(in6));
    if (ret < 0)
        return ret;

    in_port_t old_port = in6.sin6_port;
    in6.sin6_port = calc_offset_port(old_port);

    // bind 操作打印端口变更提示
    if (is_bind && in6.sin6_port != old_port) {
        printf("\nATTENTION: Bind requested on port %d\n", ntohs(old_port));
        printf("Port redirected to %d (use this for external connections)\n\n", ntohs(in6.sin6_port));
    }

    return write_data(tracee, addr_ptr, &in6, sizeof(in6));
}

/**
 * 处理标准 socket 系统调用（bind/connect/sendto）的端口修改
 * @param tracee 进程追踪句柄
 * @param sysnum 系统调用号
 * @return 0-成功，非0-错误码
 */
static int handle_standard_socketcall(Tracee *tracee, Sysnum sysnum)
{
    bool is_bind = (sysnum == PR_bind);
    bool is_udp = (sysnum == PR_sendto);
    word_t addr_ptr = 0;

    // 确定地址参数的寄存器位置
    if (is_udp) {
        // sendto: 地址参数在 SYSARG_5
        addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_5);
        if (addr_ptr == 0)
            return 0; // 已连接的 TCP 调用，无需修改
    } else {
        // bind/connect: 地址参数在 SYSARG_2
        addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);
    }

    // 读取地址族，选择对应处理逻辑
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
 * 处理 socketcall 封装调用（i386 架构）的端口修改
 * @param tracee 进程追踪句柄
 * @param call socketcall 子调用类型（SYS_BIND/SYS_CONNECT/SYS_SENDTO）
 * @param args_ptr 子调用参数数组的地址
 * @return 0-成功，非0-错误码
 */
static int handle_socketcall_wrapper(Tracee *tracee, int call, word_t args_ptr)
{
    bool is_bind = (call == SYS_BIND);
    bool is_udp = (call == SYS_SENDTO);
    long args[MAX_SOCKET_ARGS] = {0};
    word_t addr_ptr = 0;

    // 读取 socketcall 子调用参数
    int ret = read_data(tracee, args, args_ptr, sizeof(args));
    if (ret < 0)
        return ret;

    // 确定地址参数在 args 数组中的索引
    if (is_udp) {
        addr_ptr = args[4];
        if (addr_ptr == 0)
            return 0; // 已连接的 TCP 调用，无需修改
    } else {
        addr_ptr = args[1]; // SYS_BIND/SYS_CONNECT: 地址参数在 args[1]
    }

    // 读取地址族，选择对应处理逻辑
    struct sockaddr_storage addr = {0};
    ret = read_data(tracee, &addr, addr_ptr, sizeof(addr.ss_family));
    if (ret < 0)
        return ret;

    switch (addr.ss_family) {
    case AF_INET:
        ret = modify_ipv4_port(tracee, addr_ptr, is_bind);
        break;
    case AF_INET6:
        ret = modify_ipv6_port(tracee, addr_ptr, is_bind);
        break;
    default:
        return 0;
    }

    // 修改后写回参数数组（仅需写回被修改的地址参数）
    if (ret == 0) {
        size_t write_len = is_udp ? 5 * sizeof(long) : 2 * sizeof(long);
        ret = write_data(tracee, args_ptr, args, write_len);
    }

    return ret;
}

/**
 * 端口转发扩展核心回调函数
 */
int port_switch_callback(Extension *extension, ExtensionEvent event,
                         intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -EINVAL;

    switch (event) {
    case INITIALIZATION: {
        // 注册需要处理的系统调用
        static const FilteredSysnum filtered_sysnums[] = {
            { PR_bind,        FILTER_SYSEXIT },
            { PR_connect,     FILTER_SYSEXIT },
            { PR_socketcall,  FILTER_SYSEXIT },
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
            // 处理标准 socket 系统调用
            ret = handle_standard_socketcall(tracee, sysnum);
            break;

        case PR_socketcall: {
            // 处理 socketcall 封装调用
            int call = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
            word_t args_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);

            switch (call) {
            case SYS_BIND:
            case SYS_CONNECT:
            case SYS_SENDTO:
                ret = handle_socketcall_wrapper(tracee, call, args_ptr);
                break;
            default:
                break;
            }
            break;
        }

        default:
            break;
        }

        return ret;
    }

    default:
        return 0;
    }
}
