/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the
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
 */

#include <stddef.h>      /* offsetof(3), */
#include <strings.h>     /* bzero(3), */
#include <string.h>      /* strncpy(3), strlen(3), strcpy(3), strnlen(3) */
#include <unistd.h>      /* close(2), unlink(2), mkstemp(3) */
#include <assert.h>      /* assert(3), */
#include <errno.h>       /* E*, errno */
#include <sys/socket.h>  /* struct sockaddr_un, AF_UNIX, */
#include <sys/un.h>      /* struct sockaddr_un, */
#include <sys/param.h>   /* MIN(), MAX(), */
#include <stdlib.h>      /* mkstemp(3) */
#include <stdint.h>      /* int32_t, uint32_t */

#include "syscall/socket.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "path/binding.h"
#include "path/temp.h"
#include "path/path.h"
#include "arch.h"
#include "cli/note.h"

#include "compat.h"

/* 全局sockaddr_un定义声明，匹配外部引用 */
extern struct sockaddr_un sockaddr_un__;

/* 常量全局化，一次计算复用，避免重复sizeof/offsetof，提升效率 */
static const off_t  offsetof_path    = offsetof(struct sockaddr_un, sun_path);
static const size_t sizeof_path      = sizeof(sockaddr_un__.sun_path);
static const size_t sizeof_sockaddr  = sizeof(struct sockaddr_un);
static const size_t path_max_safe    = PATH_MAX - 1; /* 预计算安全路径长度，防越界 */

/**
 * 从tracee内存读取sockaddr_un结构体，解析Unix域套接字路径
 * 返回：-errno=读取失败，0=非AF_UNIX/无效结构，1=解析成功
 * 入参：max_size<=sizeof_sockaddr，size=tracee传入的结构体长度
 */
static int read_sockaddr_un(Tracee *tracee, struct sockaddr_un *sockaddr, word_t max_size,
			char path[PATH_MAX], word_t address, int size)
{
	int status = 0;

	/* 全参数非空+合法性强校验，拦截野指针/非法值 */
	if (tracee == NULL || sockaddr == NULL || path == NULL || address == 0)
		return -EINVAL;
	if (max_size > sizeof_sockaddr || size < 0)
		return 0;

	/* 无效长度：小于sun_path偏移 或 超过最大安全长度 */
	if (size <= (int)offsetof_path || (word_t)size > max_size)
		return 0;

	/* 初始化结构体，避免脏数据干扰 */
	bzero(sockaddr, sizeof_sockaddr);

	/* 从tracee内存读取结构体，失败返回错误码 */
	status = read_data(tracee, sockaddr, address, size);
	if (status < 0)
		return status;

	/* 非命名Unix域套接字，直接返回 */
	if (sockaddr->sun_family != AF_UNIX || sockaddr->sun_path[0] == '\0')
		return 0;

	/* 安全拷贝sun_path：强制截断+手动终止，避免非空终止字符串越界 */
	strncpy(path, sockaddr->sun_path, sizeof_path);
	path[sizeof_path] = '\0';

	return 1;
}

/**
 * 进入阶段：翻译tracee中Unix域套接字的路径，超长路径自动绑定为临时短路径
 * 输出：*address=新的sockaddr_un在tracee中的内存地址
 * 返回：-errno=失败，0=无需翻译，1=翻译成功
 */
int translate_socketcall_enter(Tracee *tracee, word_t *address, int size)
{
	struct sockaddr_un sockaddr = {0};
	char user_path[PATH_MAX] = {0};
	char host_path[PATH_MAX] = {0};
	int status = 0;
	char *shorter_host_path = NULL;
	Binding *binding = NULL;
	word_t new_addr = 0;

	/* 核心参数非空校验，拦截野指针 */
	if (tracee == NULL || address == NULL || tracee->ctx == NULL)
		return -EINVAL;
	/* 空地址，无需翻译 */
	if (*address == 0 || size < 0)
		return 0;

	/* 读取并解析tracee中的sockaddr_un */
	status = read_sockaddr_un(tracee, &sockaddr, sizeof_sockaddr, user_path, *address, size);
	if (status <= 0)
		return status;

	/* 翻译路径：guest -> host */
	status = translate_path(tracee, host_path, AT_FDCWD, user_path, true);
	if (status < 0)
		return status;

	/* 超长路径处理：sun_path容不下时，创建临时短路径绑定 */
	if (strnlen(host_path, path_max_safe) > sizeof_path) {
		/* 创建PRoot临时短路径 */
		shorter_host_path = create_temp_name(tracee->ctx, "proot");
		if (shorter_host_path == NULL)
			return -ENOMEM;

		/* 二次校验临时路径长度，避免创建后超标 */
		if (strnlen(shorter_host_path, path_max_safe) > sizeof_path) {
			talloc_free(shorter_host_path);
			return -EINVAL;
		}

		/* 创建并立即删除临时文件，避免残留 */
		int fd = mkstemp(shorter_host_path);
		if (fd >= 0) {
			close(fd);
			unlink(shorter_host_path);
		}

		/* 规范化guest路径，确保绑定有效性 */
		strncpy(user_path, host_path, path_max_safe);
		user_path[path_max_safe] = '\0';
		status = detranslate_path(tracee, user_path, NULL);
		if (status < 0) {
			talloc_free(shorter_host_path);
			return status;
		}

		/* 插入guest路径 -> 临时短路径的绑定 */
		binding = insort_binding3(tracee, tracee->ctx, shorter_host_path, user_path);
		if (binding == NULL) {
			talloc_free(shorter_host_path);
			return -EINVAL;
		}

		/* 临时路径挂载到binding，随binding销毁自动释放，避免内存泄漏 */
		talloc_reparent(tracee->ctx, binding, shorter_host_path);
		shorter_host_path = NULL; /* 释放所有权，防止重复free */

		/* 使用临时短路径作为新的host路径 */
		strncpy(host_path, binding->host.path, path_max_safe);
		host_path[path_max_safe] = '\0';
	}

	/* 安全写入host路径到sockaddr：强制截断，避免sun_path越界 */
	strncpy(sockaddr.sun_path, host_path, sizeof_path - 1);
	sockaddr.sun_path[sizeof_path - 1] = '\0';
	sockaddr.sun_family = AF_UNIX;

	/* 为新的sockaddr_un在tracee中分配内存 */
	new_addr = alloc_mem(tracee, sizeof_sockaddr);
	if (new_addr == 0)
		return -EFAULT;

	/* 将翻译后的sockaddr_un写入tracee内存，失败直接返回（PRoot原生alloc_mem由框架统一管理） */
	status = write_data(tracee, new_addr, &sockaddr, sizeof_sockaddr);
	if (status < 0)
		return status;

	/* 更新为新的内存地址 */
	*address = new_addr;
	return 1;
}

/**
 * 退出阶段：反翻译Unix域套接字路径，host -> guest，适配accept截断规则
 * 入参：sock_addr=tracee中sockaddr_un地址，size_addr=tracee中socklen地址
 * 返回：-errno=失败，0=成功/无需反翻译
 */
int translate_socketcall_exit(Tracee *tracee, word_t sock_addr, word_t size_addr, word_t max_size)
{
	struct sockaddr_un sockaddr = {0};
	char path[PATH_MAX] = {0};
	int status = 0;
	int size = 0;
	bool is_truncated = false;
	int path_len = 0;
	int new_size = 0;

	/* 核心参数非空校验，拦截野指针/空地址 */
	if (tracee == NULL || sock_addr == 0 || size_addr == 0)
		return 0;

	/* 读取tracee中的socklen值 */
	size = peek_int32(tracee, size_addr);
	if (errno != 0)
		return -errno;
	if (size < 0)
		return 0;

	/* 限制max_size上限，避免内存越界访问 */
	max_size = MIN(max_size, (word_t)sizeof_sockaddr);

	/* 读取并解析tracee中的sockaddr_un */
	status = read_sockaddr_un(tracee, &sockaddr, max_size, path, sock_addr, size);
	if (status <= 0)
		return status;

	/* 反翻译路径：host -> guest */
	status = detranslate_path(tracee, path, NULL);
	if (status < 0)
		return status;

	/* 计算新的sockaddr长度：sun_family + 路径 + 终止符 */
	path_len = (int)strnlen(path, path_max_safe);
	new_size = (int)offsetof_path + path_len + 1;

	/* 长度越界处理：超过max_size则标记截断，按max_size处理 */
	if (new_size < 0 || (word_t)new_size > max_size) {
		new_size = (int)max_size;
		is_truncated = true;
	}

	/* 安全写入反翻译后的路径，强制截断防越界 */
	strncpy(sockaddr.sun_path, path, sizeof_path - 1);
	sockaddr.sun_path[sizeof_path - 1] = '\0';
	sockaddr.sun_family = AF_UNIX;

	/* 将反翻译后的sockaddr_un写回tracee内存 */
	status = write_data(tracee, sock_addr, &sockaddr, new_size);
	if (status < 0)
		return status;

	/* 适配accept截断规则：缓冲区过小则返回比传入值大的长度 */
	if (is_truncated)
		new_size = (int)max_size + 1;

	/* 将新的socklen写回tracee内存 */
	poke_int32(tracee, size_addr, new_size);
	if (errno != 0)
		return -errno;

	return 0;
}
