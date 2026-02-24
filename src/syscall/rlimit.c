/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
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
 */

#include <stdbool.h>		/* bool, true/false */
#include <sys/time.h>		/* prlimit(2), prlimit64(2) */
#include <sys/resource.h>	/* prlimit(2), rlimit64, RLIMIT_STACK */
#include <errno.h>		/* errno, E* */
#include <stdint.h>		/* uint64_t, uint32_t */
#include <assert.h>		/* assert(3) */
#include <stdio.h>		/* unsigned long long format */
#include <string.h>		/* strerror(3) */

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "cli/note.h"

/**
 * 适配Linux内核bug(#91791)：tracer访问tracee栈时错误校验tracer的栈限制，
 * 而非tracee自身。策略：将PRoot的栈软限制提升至tracee的栈软限制（若更大），
 * 兼顾安全性（避免无限递归崩溃）与兼容性（解决栈访问失败）。
 * 支持setrlimit/setrlimit64/prlimit/prlimit64全调用，适配32/64/32on64架构，
 * is_prlimit: true=prlimit/prlimit64调用，false=setrlimit/setrlimit64调用
 * 返回：-errno=致命错误，0=成功/非目标资源/非致命错误
 */
int translate_setrlimit_exit(const Tracee *tracee, bool is_prlimit)
{
	/* 提前声明所有变量，规避C23标签后声明警告，统一作用域 */
	struct rlimit64 proot_stack = {0};
	word_t resource = 0, address = 0;
	uint64_t tracee_stack_limit = 0;
	Reg sysarg = SYSARG_1;
	int status = 0;
	const char *caller = is_prlimit ? "prlimit" : "setrlimit";
	int saved_errno = 0;

	/* 核心参数非空校验，提前拦截野指针 */
	assert(tracee != NULL);
	assert(tracee->pid > 0);

	/* 区分prlimit/setrlimit的系统调用参数索引 */
	sysarg = is_prlimit ? SYSARG_2 : SYSARG_1;

	/* 读取原始资源类型和rlimit结构体地址，跳过内核修改后的脏数据 */
	resource = peek_reg(tracee, ORIGINAL, sysarg);
	address  = peek_reg(tracee, ORIGINAL, sysarg + 1);

	/* 非栈资源限制，直接返回，不处理 */
	if (resource != RLIMIT_STACK) {
		VERBOSE(tracee, 5, "%s: skip non-stack resource %lu", caller, (unsigned long)resource);
		return 0;
	}

	/* 地址为空，无有效rlimit配置，直接返回 */
	if (address == 0) {
		VERBOSE(tracee, 4, "%s: empty rlimit address for RLIMIT_STACK", caller);
		return 0;
	}

	/* 读取tracee的新栈软限制，适配prlimit/setrlimit+32/64/32on64架构 */
	if (is_prlimit) {
		/* prlimit默认使用64位rlimit64，直接读取uint64_t */
		tracee_stack_limit = peek_uint64(tracee, address);
	}
	else {
		/* setrlimit区分32/64，32on64下将-1转换为64位无限值 */
		tracee_stack_limit = (uint64_t)peek_word(tracee, address);
		if (is_32on64_mode(tracee) && tracee_stack_limit == (uint64_t)(uint32_t)-1) {
			tracee_stack_limit = RLIM_INFINITY;
			VERBOSE(tracee, 4, "setrlimit: 32on64 convert 0xFFFFFFFF to RLIM_INFINITY");
		}
	}

	/* 读取tracee内存失败，返回致命错误 */
	saved_errno = errno;
	if (saved_errno != 0) {
		VERBOSE(tracee, 0, "%s: read tracee rlimit failed: %s", caller, strerror(saved_errno));
		return -saved_errno;
	}

	/* 无限值防护：避免将PRoot栈限制设为无限，防止递归崩溃 */
	if (tracee_stack_limit == RLIM_INFINITY) {
		/* 取系统默认硬限制作为兜底，不使用无限值 */
		status = prlimit64(0, RLIMIT_STACK, NULL, &proot_stack);
		if (status == 0) {
			tracee_stack_limit = proot_stack.rlim_max;
			VERBOSE(tracee, 3, "%s: replace RLIM_INFINITY with hard limit %llu", caller,
				(unsigned long long)tracee_stack_limit);
		}
		else {
			saved_errno = errno;
			VERBOSE(tracee, 0, "%s: get hard limit failed, skip infinity stack limit: %s", caller, strerror(saved_errno));
			return 0;
		}
	}

	/* 获取PRoot当前的栈限制（软/硬） */
	status = prlimit64(0, RLIMIT_STACK, NULL, &proot_stack);
	if (status < 0) {
		saved_errno = errno;
		VERBOSE(tracee, 0, "%s: get proot stack limit failed: %s", caller, strerror(saved_errno));
		return 0; /* 非致命错误，仅日志提示 */
	}

	/* 无需提升：PRoot当前软限制已大于等于tracee的限制 */
	if (proot_stack.rlim_cur >= tracee_stack_limit) {
		VERBOSE(tracee, 5, "%s: proot stack limit %llu >= tracee %llu, skip", caller,
			(unsigned long long)proot_stack.rlim_cur, (unsigned long long)tracee_stack_limit);
		return 0;
	}

	/* 硬限制校验：避免超过PRoot的栈硬限制，内核会拒绝设置 */
	if (tracee_stack_limit > proot_stack.rlim_max) {
		VERBOSE(tracee, 0, "%s: tracee stack limit %llu > proot hard limit %llu, skip", caller,
			(unsigned long long)tracee_stack_limit, (unsigned long long)proot_stack.rlim_max);
		return 0;
	}

	/* 提升PRoot的栈软限制至tracee的限制 */
	proot_stack.rlim_cur = tracee_stack_limit;
	status = prlimit64(0, RLIMIT_STACK, &proot_stack, NULL);
	if (status < 0) {
		saved_errno = errno;
		VERBOSE(tracee, 0, "%s: set proot stack limit to %llu failed: %s", caller,
			(unsigned long long)tracee_stack_limit, strerror(saved_errno));
	}
	else {
		VERBOSE(tracee, 1, "%s: fix kernel bug#91791, proot stack soft limit increased to %llu bytes",
			caller, (unsigned long long)proot_stack.rlim_cur);
	}

	/* 所有情况均返回0，设置失败为非致命错误（不影响tracee执行） */
	return 0;
}
