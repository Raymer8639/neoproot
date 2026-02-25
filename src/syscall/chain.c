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

#include <talloc.h>     /* talloc*, TALLOC_FREE */
#include <sys/queue.h>  /* STAILQ_*, */
#include <errno.h>      /* E*, ENOMEM */
#include <assert.h>     /* assert(3), */
#include <stddef.h>     /* NULL */

#include "cli/note.h"
#include "syscall/chain.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "arch.h"

struct chained_syscall {
	Sysnum sysnum;
	word_t sysargs[6];
	STAILQ_ENTRY(chained_syscall) link;
};

STAILQ_HEAD(chained_syscalls, chained_syscall);

static int register_chained_syscall_internal(Tracee *tracee, Sysnum sysnum,
			word_t sysarg_1, word_t sysarg_2, word_t sysarg_3,
			word_t sysarg_4, word_t sysarg_5, word_t sysarg_6,
			bool at_front)
{
	struct chained_syscall *syscall = NULL;

	/* 核心参数非空强校验，拦截野指针 */
	if (tracee == NULL)
		return -EINVAL;

	/* 初始化调用链头节点，首次注册时创建 */
	if (tracee->chain.syscalls == NULL) {
		tracee->chain.syscalls = talloc_zero(tracee, struct chained_syscalls);
		if (tracee->chain.syscalls == NULL) {
			VERBOSE(tracee, 0, "register_chained_syscall: talloc syscalls head failed (ENOMEM)");
			return -ENOMEM;
		}
		STAILQ_INIT(tracee->chain.syscalls);
	}

	/* 分配单个链式调用节点，挂接到头节点的内存上下文 */
	syscall = talloc_zero(tracee->chain.syscalls, struct chained_syscall);
	if (syscall == NULL) {
		VERBOSE(tracee, 0, "register_chained_syscall: talloc syscall node failed (ENOMEM)");
		return -ENOMEM;
	}

	/* 赋值系统调用号和6个参数，原生逻辑无修改 */
	syscall->sysnum     = sysnum;
	syscall->sysargs[0] = sysarg_1;
	syscall->sysargs[1] = sysarg_2;
	syscall->sysargs[2] = sysarg_3;
	syscall->sysargs[3] = sysarg_4;
	syscall->sysargs[4] = sysarg_5;
	syscall->sysargs[5] = sysarg_6;

	/* 头插/尾插，控制调用链执行顺序 */
	if (at_front)
		STAILQ_INSERT_HEAD(tracee->chain.syscalls, syscall, link);
	else
		STAILQ_INSERT_TAIL(tracee->chain.syscalls, syscall, link);

	return 0;
}

/**
 * Append a new syscall (@sysnum, @sysarg_*) to the tail of tracee's syscall chain.
 * Triggered in FIFO order after current syscall finished.
 * Return: -errno on error, 0 on success.
 */
int register_chained_syscall(Tracee *tracee, Sysnum sysnum,
			word_t sysarg_1, word_t sysarg_2, word_t sysarg_3,
			word_t sysarg_4, word_t sysarg_5, word_t sysarg_6)
{
	return register_chained_syscall_internal(
		tracee, sysnum,
		sysarg_1, sysarg_2, sysarg_3,
		sysarg_4, sysarg_5, sysarg_6,
		false
	);
}

/**
 * Forge next syscall from the head of tracee's syscall chain (FIFO).
 * Only call at the end of sysexit stage.
 */
void chain_next_syscall(Tracee *tracee)
{
	struct chained_syscall *syscall = NULL;
	word_t instr_pointer = 0;
	word_t sysnum = 0;
	word_t systrap_size = 0;

	/* 前置非空校验，兼容异常场景（避免assert崩溃） */
	if (tracee == NULL || tracee->chain.syscalls == NULL)
		return;

	/* 无剩余链式调用：清理资源+强制设置最终结果（若需要） */
	if (STAILQ_EMPTY(tracee->chain.syscalls)) {
		TALLOC_FREE(tracee->chain.syscalls); // 释放整个调用链内存

		if (tracee->chain.force_final_result)
			poke_reg(tracee, SYSARG_RESULT, tracee->chain.final_result);

		/* 重置调用链状态，恢复初始值 */
		tracee->chain.force_final_result = false;
		tracee->chain.final_result = 0;

		VERBOSE(tracee, 2, "chain_next_syscall: finished, no more chained syscalls");
		return;
	}

	VERBOSE(tracee, 2, "chain_next_syscall: continue with next chained syscall");

	/* 链式调用执行中，暂不恢复原始寄存器 */
	tracee->restore_original_regs = false;

	/* 取出FIFO头节点并从链表移除 */
	syscall = STAILQ_FIRST(tracee->chain.syscalls);
	if (syscall == NULL) // 空节点防护，避免野指针
		return;
	STAILQ_REMOVE_HEAD(tracee->chain.syscalls, link);

	/* 写入6个系统调用参数到寄存器 */
	poke_reg(tracee, SYSARG_1, syscall->sysargs[0]);
	poke_reg(tracee, SYSARG_2, syscall->sysargs[1]);
	poke_reg(tracee, SYSARG_3, syscall->sysargs[2]);
	poke_reg(tracee, SYSARG_4, syscall->sysargs[3]);
	poke_reg(tracee, SYSARG_5, syscall->sysargs[4]);
	poke_reg(tracee, SYSARG_6, syscall->sysargs[5]);

	/* 转换中性系统调用号为架构相关值，写入陷阱寄存器 */
	sysnum = detranslate_sysnum(get_abi(tracee), syscall->sysnum);
	poke_reg(tracee, SYSTRAP_NUM, sysnum);

	/* 指令指针回退，重新触发系统调用陷阱 */
	systrap_size = get_systrap_size(tracee);
	instr_pointer = peek_reg(tracee, CURRENT, INSTR_POINTER);
	poke_reg(tracee, INSTR_POINTER, instr_pointer - systrap_size);

	/* 释放当前节点内存，避免内存泄漏 */
	TALLOC_FREE(syscall);

	/* 设置重启方式，继续处理下一个链式调用 */
	tracee->restart_how = PTRACE_SYSCALL;
}

/**
 * Force the final result of tracee's current syscall chain to @forced_result.
 */
void force_chain_final_result(Tracee *tracee, word_t forced_result)
{
	if (tracee == NULL) // 非空校验
		return;
	tracee->chain.force_final_result = true;
	tracee->chain.final_result = forced_result;
}

/**
 * Restart the original syscall (ORIGINAL reg version) as a chained syscall.
 * Return: same as register_chained_syscall().
 */
int restart_original_syscall(Tracee *tracee)
{
	/* 非空校验，避免peek_reg访问野指针 */
	if (tracee == NULL)
		return -EINVAL;

	return register_chained_syscall(tracee,
					get_sysnum(tracee, ORIGINAL),
					peek_reg(tracee, ORIGINAL, SYSARG_1),
					peek_reg(tracee, ORIGINAL, SYSARG_2),
					peek_reg(tracee, ORIGINAL, SYSARG_3),
					peek_reg(tracee, ORIGINAL, SYSARG_4),
					peek_reg(tracee, ORIGINAL, SYSARG_5),
					peek_reg(tracee, ORIGINAL, SYSARG_6));
}

/**
 * Restart current syscall (CURRENT reg version) as a chained syscall (head insert).
 * For sysnum workaround scenario only.
 * Return: same as register_chained_syscall_internal().
 */
int restart_current_syscall_as_chained(Tracee *tracee)
{
	/* 非空+状态校验，增强断言的容错性 */
	if (tracee == NULL)
		return -EINVAL;
	assert(tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_INACTIVE);

	tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL;
	return register_chained_syscall_internal(tracee,
					get_sysnum(tracee, CURRENT),
					peek_reg(tracee, CURRENT, SYSARG_1),
					peek_reg(tracee, CURRENT, SYSARG_2),
					peek_reg(tracee, CURRENT, SYSARG_3),
					peek_reg(tracee, CURRENT, SYSARG_4),
					peek_reg(tracee, CURRENT, SYSARG_5),
					peek_reg(tracee, CURRENT, SYSARG_6),
					true);
}
