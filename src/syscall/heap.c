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

#include <sys/mman.h>	/* PROT_*, MAP_*, */
#include <assert.h>	/* assert(3),  */
#include <string.h>     /* strerror(3), */
#include <unistd.h>     /* sysconf(3), */
#include <sys/param.h>  /* MIN(), MAX(), */
#include <errno.h>      /* errno, EFAULT */
#include <stdint.h>     /* int64_t, uint64_t */

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/sysnum.h"
#include "execve/execve.h"
#include "cli/note.h"
#include "arch.h"

#include "compat.h"

#define DEBUG_BRK(...) /* fprintf(stderr, __VA_ARGS__) */

/* 堆偏移：丢弃mmap的第一页以模拟空堆，全局静态初始化避免未定义 */
static word_t heap_offset = 0;

/**
 * 重定向brk系统调用，将tracee的堆映射到可靠地址（解决内核默认堆地址后接其他映射导致堆无法增长的问题）
 * 首次brk替换为mmap/mmap2创建堆映射，后续brk替换为mremap调整堆大小，兼容32/64位架构
 */
void translate_brk_enter(Tracee *tracee)
{
	word_t new_brk_address = 0;
	size_t old_heap_size = 0;
	size_t new_heap_size = 0;
	Sysnum sysnum = PR_void;
	Mapping *mappings = NULL;
	Mapping *bss = NULL;

	/* 核心参数非空校验，拦截野指针 */
	if (tracee == NULL || tracee->heap == NULL)
		return;

	/* 堆模拟禁用，直接返回 */
	if (tracee->heap->disabled)
		return;

	/* 初始化堆偏移为页大小，兼容sysconf失败场景 */
	if (heap_offset == 0) {
		long page_size = sysconf(_SC_PAGE_SIZE);
		heap_offset = (page_size > 0) ? (word_t)page_size : 0x1000;
	}

	/* 读取tracee传入的新brk地址 */
	new_brk_address = peek_reg(tracee, CURRENT, SYSARG_1);
	DEBUG_BRK("brk(0x%lx)\n", new_brk_address);

	/* 首次brk调用：分配mmap映射作为模拟堆 */
	if (tracee->heap->base == 0) {
		/* 异常场景：首次brk非空地址，日志警告并返回 */
		if (new_brk_address != 0) {
			if (tracee->verbose > 0)
				VERBOSE(tracee, 0, "process %d is doing suspicious brk(): non-null first call", tracee->pid);
			return;
		}

		/* 校验加载信息和映射表，避免空指针访问 */
		if (tracee->load_info == NULL || tracee->load_info->mappings == NULL) {
			VERBOSE(tracee, 0, "process %d: invalid load info/mappings for brk heap init", tracee->pid);
			return;
		}
		mappings = tracee->load_info->mappings;
		bss = &mappings[talloc_array_length(mappings) - 1];

		/* 堆地址紧跟BSS段末尾（天然页对齐） */
		new_brk_address = bss->addr + bss->length;

		/* 选择mmap2/mmap：优先mmap2（解决部分架构mmap EFAULT问题） */
		sysnum = (detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER)
			? PR_mmap2
			: PR_mmap;

		/* 替换为mmap/mmap2系统调用，设置堆映射参数 */
		set_sysnum(tracee, sysnum);
		poke_reg(tracee, SYSARG_1, new_brk_address);  /* 映射地址 */
		poke_reg(tracee, SYSARG_2, heap_offset);      /* 映射大小（堆偏移） */
		poke_reg(tracee, SYSARG_3, PROT_READ | PROT_WRITE); /* 读写权限 */
		poke_reg(tracee, SYSARG_4, MAP_PRIVATE | MAP_ANONYMOUS); /* 私有匿名映射 */
		poke_reg(tracee, SYSARG_5, (word_t)-1);       /* 无效文件描述符 */
		poke_reg(tracee, SYSARG_6, (word_t)0);        /* 偏移量0 */

		return;
	}

	/* 非法地址：新brk小于堆基址，替换为空调用 */
	if (new_brk_address < tracee->heap->base) {
		set_sysnum(tracee, PR_void);
		return;
	}

	/* 计算堆大小，替换为mremap调整堆 */
	new_heap_size = new_brk_address - tracee->heap->base;
	old_heap_size = tracee->heap->size;

	set_sysnum(tracee, PR_mremap);
	poke_reg(tracee, SYSARG_1, tracee->heap->base - heap_offset); /* 原始映射基址 */
	poke_reg(tracee, SYSARG_2, old_heap_size + heap_offset);      /* 原始映射大小 */
	poke_reg(tracee, SYSARG_3, new_heap_size + heap_offset);      /* 新映射大小 */
	poke_reg(tracee, SYSARG_4, (word_t)0);                        /* 无标志 */
	poke_reg(tracee, SYSARG_5, (word_t)0);                        /* 不指定新地址 */

	return;
}

/**
 * brk系统调用退出阶段处理：解析mmap/mmap2/mremap结果，更新堆状态，适配brk的返回值规则
 */
void translate_brk_exit(Tracee *tracee)
{
	word_t result = 0;
	Sysnum sysnum = PR_void;
	int tracee_errno = 0;
	word_t modified_sysarg3 = 0;

	/* 核心参数非空校验，拦截野指针 */
	if (tracee == NULL || tracee->heap == NULL)
		return;

	/* 堆模拟禁用，直接返回 */
	if (tracee->heap->disabled)
		return;

	/* 堆偏移已初始化，断言兜底 */
	assert(heap_offset > 0);

	/* 读取修改后的系统调用号、执行结果、错误码 */
	sysnum = get_sysnum(tracee, MODIFIED);
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	tracee_errno = (int)result;

	/* 根据替换的系统调用类型，处理结果并更新堆状态 */
	switch (sysnum) {
	case PR_void:
		/* 非法brk：返回当前堆顶地址 */
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mmap:
	case PR_mmap2:
		/* mmap/mmap2失败：返回0（符合brk规则），成功则初始化堆状态 */
		if (tracee_errno < 0 && tracee_errno > -4096) {
			poke_reg(tracee, SYSARG_RESULT, (word_t)0);
			break;
		}

		/* 堆基址 = mmap结果 + 堆偏移，堆大小初始化为0 */
		tracee->heap->base = result + heap_offset;
		tracee->heap->size = 0;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mremap:
		/* mremap失败 或 地址不匹配：返回当前堆顶地址 */
		if ((tracee_errno < 0 && tracee_errno > -4096) || (tracee->heap->base != result + heap_offset)) {
			poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
			break;
		}

		/* 成功调整：从修改后的参数读取新大小，更新堆大小 */
		modified_sysarg3 = peek_reg(tracee, MODIFIED, SYSARG_3);
		tracee->heap->size = modified_sysarg3 - heap_offset;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_brk:
		/* 可疑brk调用验证：结果与原始参数一致则禁用堆模拟 */
		if (result == peek_reg(tracee, ORIGINAL, SYSARG_1))
			tracee->heap->disabled = true;
		break;

	default:
		/* 未知系统调用，断言兜底 */
		VERBOSE(tracee, 0, "process %d: unexpected sysnum %d in brk exit", tracee->pid, (int)sysnum);
		assert(0 && "unexpected sysnum in translate_brk_exit");
		break;
	}

	DEBUG_BRK("brk() = 0x%lx\n", peek_reg(tracee, CURRENT, SYSARG_RESULT));
}
