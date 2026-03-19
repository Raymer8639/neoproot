/*
 * This file is part of proot-scicat.
 *
 * Copyright (C) 2026 Scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 *
 * Description: Static port mapping for bind/connect (e.g. 80→8080, 443→8443)
 * Support: IPv4/IPv6, socketcall wrapper, localhost-only connect mapping
 */

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

/* 静态端口映射配置 */
#define STATIC_PORT_MAP_SIZE 16
typedef struct {
    uint16_t from_port;  // 原始端口（主机字节序）
    uint16_t to_port;    // 映射端口（主机字节序）
    bool active;         // 映射是否启用
} PortMapEntry;

static PortMapEntry static_port_map[STATIC_PORT_MAP_SIZE];
static bool port_map_initialized = false;

/**
 * 初始化静态端口映射表（仅执行一次）
 */
static void init_static_port_map(void)
{
    if (port_map_initialized)
        return;

    // 清空映射表
    memset(static_port_map, 0, sizeof(static_port_map));

    // 常用端口映射配置（可按需修改）
    static const PortMapEntry init_entries[] = {
        {.from_port = 80,    .to_port = 8080,  .active = true},
        {.from_port = 443,   .to_port = 8443,  .active = true},
        {.from_port = 22,    .to_port = 8022,  .active = true},
        {.from_port = 3000,  .to_port = 13000, .active = true},
        {.from_port = 8080,  .to_port = 18080, .active = true},
        {.from_port = 9000,  .to_port = 19000, .active = true},
    };

    // 复制初始化条目到映射表
    size_t init_count = sizeof(init_entries) / sizeof(PortMapEntry);
    for (size_t i = 0; i < init_count && i < STATIC_PORT_MAP_SIZE; i++) {
        static_port_map[i] = init_entries[i];
    }

    port_map_initialized = true;
}

/**
 * 查找端口映射（主机字节序输入/输出）
 * @param original_port 原始端口（主机字节序）
 * @return 映射端口（主机字节序），未找到返回0
 */
static uint16_t lookup_port_mapping(uint16_t original_port)
{
    for (int i = 0; i < STATIC_PORT_MAP_SIZE; i++) {
        if (static_port_map[i].active && static_port_map[i].from_port == original_port) {
            return static_port_map[i].to_port;
        }
    }
    return 0;
}

/**
 * 判断地址是否为本地地址（localhost/INADDR_ANY/IN6ADDR_ANY）
 * @param addr 通用socket地址结构体
 * @return true-是本地地址，false-否
 */
static bool is_localhost(const struct sockaddr_storage *addr)
{
    if (addr == NULL)
        return false;

    switch (addr->ss_family) {
    case AF_INET: {
        const struct sockaddr_in *in4 = (const struct sockaddr_in *)addr;
        // 匹配 127.0.0.1（回环）或 0.0.0.0（任意地址）
        return (in4->sin_addr.s_addr == htonl(INADDR_LOOPBACK) ||
                in4->sin_addr.s_addr == htonl(INADDR_ANY));
    }
    case AF_INET6: {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        static const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
        static const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
        // 匹配 ::1（IPv6回环）或 ::（IPv6任意地址）
        return (memcmp(&in6->sin6_addr, &in6addr_loopback, sizeof(in6->sin6_addr)) == 0 ||
                memcmp(&in6->sin6_addr, &in6addr_any, sizeof(in6->sin6_addr)) == 0);
    }
    default:
        return false;
    }
}

/**
 * 修改 IPv4 地址的端口并写回进程内存
 * @param tracee 进程追踪句柄
 * @param addr_ptr 地址结构体在进程内存中的地址
 * @return 0-成功，非0-错误码
 */
static int modify_ipv4_port(Tracee *tracee, word_t addr_ptr)
{
    struct sockaddr_in in4 = {0};
    int ret = read_data(tracee, &in4, addr_ptr, sizeof(in4));
    if (ret < 0)
        return ret;

    // 转换为本地字节序查找映射
    uint16_t orig_port = ntohs(in4.sin_port);
    uint16_t mapped_port = lookup_port_mapping(orig_port);
    if (mapped_port == 0)
        return 0; // 无匹配映射，不修改

    // 应用端口映射（转换为网络字节序）
    in4.sin_port = htons(mapped_port);

    // 打印映射提示（仅bind操作，避免冗余输出）
    printf("\nPort mapped: %d → %d\n", orig_port, mapped_port);

    // 写回修改后的地址结构
    return write_data(tracee, addr_ptr, &in4, sizeof(in4));
}

/**
 * 修改 IPv6 地址的端口并写回进程内存
 * @param tracee 进程追踪句柄
 * @param addr_ptr 地址结构体在进程内存中的地址
 * @return 0-成功，非0-错误码
 */
static int modify_ipv6_port(Tracee *tracee, word_t addr_ptr)
{
    struct sockaddr_in6 in6 = {0};
    int ret = read_data(tracee, &in6, addr_ptr, sizeof(in6));
    if (ret < 0)
        return ret;

    // 转换为本地字节序查找映射
    uint16_t orig_port = ntohs(in6.sin6_port);
    uint16_t mapped_port = lookup_port_mapping(orig_port);
    if (mapped_port == 0)
        return 0; // 无匹配映射，不修改

    // 应用端口映射（转换为网络字节序）
    in6.sin6_port = htons(mapped_port);

    // 打印映射提示（仅bind操作，避免冗余输出）
    printf("\nPort mapped: %d → %d (IPv6)\n", orig_port, mapped_port);

    // 写回修改后的地址结构
    return write_data(tracee, addr_ptr, &in6, sizeof(in6));
}

/**
 * 处理标准 socket 系统调用（bind/connect）的端口映射
 * @param tracee 进程追踪句柄
 * @param sysnum 系统调用号
 * @return 0-成功，非0-错误码
 */
static int handle_standard_socketcall(Tracee *tracee, Sysnum sysnum)
{
    bool is_connect = (sysnum == PR_connect);
    word_t addr_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);

    // connect 仅处理本地地址
    if (is_connect) {
        struct sockaddr_storage addr = {0};
        int ret = read_data(tracee, &addr, addr_ptr, sizeof(addr.ss_family));
        if (ret < 0)
            return ret;
        if (!is_localhost(&addr))
            return 0;
    }

    // 读取地址族，选择对应端口修改逻辑
    struct sockaddr_storage addr = {0};
    int ret = read_data(tracee, &addr, addr_ptr, sizeof(addr.ss_family));
    if (ret < 0)
        return ret;

    switch (addr.ss_family) {
    case AF_INET:
        return modify_ipv4_port(tracee, addr_ptr);
    case AF_INET6:
        return modify_ipv6_port(tracee, addr_ptr);
    default:
        return 0;
    }
}

/**
 * 处理 socketcall 封装调用（i386 架构）的端口映射
 * @param tracee 进程追踪句柄
 * @param call socketcall 子调用类型（SYS_BIND/SYS_CONNECT）
 * @param args_ptr 子调用参数数组的地址
 * @return 0-成功，非0-错误码
 */
static int handle_socketcall_wrapper(Tracee *tracee, int call, word_t args_ptr)
{
    bool is_connect = (call == SYS_CONNECT);
    long args[6] = {0};
    word_t addr_ptr = 0;

    // 读取 socketcall 子调用参数
    int ret = read_data(tracee, args, args_ptr, sizeof(args));
    if (ret < 0)
        return ret;

    // 获取地址参数指针（SYS_BIND/SYS_CONNECT 的第二个参数）
    addr_ptr = args[1];
    if (addr_ptr == 0)
        return 0;

    // connect 仅处理本地地址
    if (is_connect) {
        struct sockaddr_storage addr = {0};
        ret = read_data(tracee, &addr, addr_ptr, sizeof(addr.ss_family));
        if (ret < 0)
            return ret;
        if (!is_localhost(&addr))
            return 0;
    }

    // 读取地址族，选择对应端口修改逻辑
    struct sockaddr_storage addr = {0};
    ret = read_data(tracee, &addr, addr_ptr, sizeof(addr.ss_family));
    if (ret < 0)
        return ret;

    switch (addr.ss_family) {
    case AF_INET:
        ret = modify_ipv4_port(tracee, addr_ptr);
        break;
    case AF_INET6:
        ret = modify_ipv6_port(tracee, addr_ptr);
        break;
    default:
        return 0;
    }

    // 写回修改后的参数数组（仅需写回前2个参数，包含地址指针）
    if (ret == 0) {
        ret = write_data(tracee, args_ptr, args, 2 * sizeof(long));
    }

    return ret;
}

/**
 * 静态端口映射扩展核心回调函数
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
            { PR_bind,       FILTER_SYSEXIT },
            { PR_connect,    FILTER_SYSEXIT },
            { PR_socketcall, FILTER_SYSEXIT },
            FILTERED_SYSNUM_END
        };
        extension->filtered_sysnums = (FilteredSysnum *)filtered_sysnums;

        // 初始化端口映射表
        init_static_port_map();
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
            // 处理标准 bind/connect 调用
            ret = handle_standard_socketcall(tracee, sysnum);
            break;

        case PR_socketcall: {
            // 处理 socketcall 封装的 bind/connect
            int call = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
            word_t args_ptr = peek_reg(tracee, ORIGINAL, SYSARG_2);

            switch (call) {
            case SYS_BIND:
            case SYS_CONNECT:
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
