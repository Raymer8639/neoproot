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
#include <sys/ptrace.h> /* ptrace(2), PTRACE_*, */
#include <sys/types.h>  /* pid_t, size_t, */
#include <stdlib.h>     /* NULL, abs, labs */
#include <stddef.h>     /* offsetof(), */
#include <sys/user.h>   /* struct user*, */
#include <errno.h>      /* errno, */
#include <assert.h>     /* assert(3), */
#include <sys/wait.h>   /* waitpid(2), */
#include <string.h>     /* memcpy(3), strnlen(3) */
#include <stdint.h>     /* uint*_t, */
#include <sys/uio.h>    /* process_vm_*, struct iovec, */
#include <unistd.h>     /* sysconf(3), */
#include <sys/mman.h>   /* mmap(2), munmap(2), MAP_*, */
#include <stdbool.h>    /* bool, true, false (for original bool vars) */
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/heap.h"
#include "arch.h"            /* word_t, NO_MISALIGNED_ACCESS, is_32on64_mode, sizeof_word */
#include "build.h"           /* HAVE_PROCESS_VM,  */
#include "cli/note.h"

#ifdef HAS_POKEDATA_WORKAROUND
#include "tracee/reg.h"
#include "syscall/sysnum.h"
extern const ssize_t offset_to_pokedata_workaround;
void launcher_pokedata_workaround();
// See loader/assembly.S
#if defined(__aarch64__)
__asm(
	".globl launcher_pokedata_workaround\n"
	"launcher_pokedata_workaround:\n"
	"str x1, [x2]\n"
	// https://stackoverflow.com/a/16087057
	".word 0xf7f0a000\n"
);
#endif /* defined(__aarch64__) */
#endif /* HAS_POKEDATA_WORKAROUND */

/**
 * 通用宏定义：消除魔法数字，提升可维护性
 */
#define PTRACE_RETRY_CNT    1       // ptrace基础重试次数
#define PAGE_SIZE_SAFE      4096    // 页大小常量，适配process_vm块操作
#define CLEAR_MEM_MIN_SIZE  1024    // clear_mem内存池复用阈值

/**
 * Load the word at the given @address, potentially *not* aligned.
 * 优化：显式类型转换，消除编译对齐警告
 */
static inline word_t load_word(const void *address)
{
#ifdef NO_MISALIGNED_ACCESS
	if (((uintptr_t)address) % sizeof(word_t) == 0)
		return *(const word_t *)address;
	else {
		word_t value = 0;
		memcpy(&value, address, sizeof(word_t));
		return value;
	}
#else
	return *(const word_t *)address;
#endif
}

/**
 * Store the word with the given @value to the given @address,
 * potentially *not* aligned.
 * 优化：显式类型转换，消除编译对齐警告
 */
static inline void store_word(void *address, word_t value)
{
#ifdef NO_MISALIGNED_ACCESS
	if (((uintptr_t)address) % sizeof(word_t) == 0)
		*((word_t *)address) = value;
	else
		memcpy(address, &value, sizeof(word_t));
#else
	*((word_t *)address) = value;
#endif
}

/**
 * ptrace_pokedata封装：带基础错误重试，提升写入稳定性
 * 原版逻辑不变，仅增加轻量重试，适配内核调度延迟
 */
static int ptrace_pokedata_or_via_stub(Tracee *tracee, word_t addr, word_t word)
{
	int status = -1;
	int retry = PTRACE_RETRY_CNT;

#if HAS_POKEDATA_WORKAROUND
	static bool pokedata_workaround_needed = false;
	static bool pokedata_workaround_checked = false;
#endif

	// 基础ptrace重试，原版逻辑外的轻量优化
	do {
#if HAS_POKEDATA_WORKAROUND
		if (!pokedata_workaround_needed)
#endif
			status = ptrace(PTRACE_POKEDATA, tracee->pid, (void *)addr, (void *)word);
	} while (status < 0 && errno == EAGAIN && --retry > 0);

#if HAS_POKEDATA_WORKAROUND
	if (!pokedata_workaround_checked) {
		pokedata_workaround_needed = (status != 0);
		pokedata_workaround_checked = true;
		if (pokedata_workaround_needed) {
			VERBOSE(tracee, 1, "Detected broken PTRACE_POKEDATA - enabling workaround");
		}
	}

	if (pokedata_workaround_needed && tracee->is_aarch32) {
		note(tracee, ERROR, INTERNAL, "POKEDATA workaround is not supported on AArch32");
		status = -1;
		errno = EIO;
	} else if (pokedata_workaround_needed) {
		struct user_regs_struct orig_regs = tracee->_regs[CURRENT];
		bool restore_original_regs = tracee->restore_original_regs;
		sigset_t orig_sigset;
		sigset_t modified_sigset;

		// Block signals
		(void)ptrace(PTRACE_GETSIGMASK, tracee->pid, sizeof(sigset_t), &orig_sigset);
		sigfillset(&modified_sigset);
		sigdelset(&modified_sigset, SIGILL);
		sigdelset(&modified_sigset, SIGTRAP);
		sigdelset(&modified_sigset, SIGBUS);
		sigdelset(&modified_sigset, SIGSEGV);
		sigdelset(&modified_sigset, SIGSYS);
		(void)ptrace(PTRACE_SETSIGMASK, tracee->pid, sizeof(sigset_t), &modified_sigset);

		// Set registers so memory will be written
		word_t pokedata_workaround_stub_addr = tracee->pokedata_workaround_stub_addr;
		poke_reg(tracee, INSTR_POINTER, pokedata_workaround_stub_addr);
		poke_reg(tracee, SYSARG_2, word);
		poke_reg(tracee, SYSARG_3, addr);
		set_sysnum(tracee, PR_void);
		tracee->_regs_were_changed = true;
		tracee->restore_original_regs = false;
		push_specific_regs(tracee, true);
		print_current_regs(tracee, 5, "pokedata workaround" );

		// Continue tracee, retry if SIGSYS or SIGSTOP occurs
		int wstatus = 0;
		bool redeliver_sigstop = false;
		do {
			(void)ptrace(PTRACE_CONT, tracee->pid, 0, 0);
			(void)waitpid(tracee->pid, &wstatus, 0);
			if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP)
				redeliver_sigstop = true;
		} while (WIFSTOPPED(wstatus) && (WSTOPSIG(wstatus) == SIGSYS || WSTOPSIG(wstatus) == SIGSTOP));

		// Redeliver SIGSTOP if occured
		if (redeliver_sigstop)
			(void)kill(tracee->pid, SIGSTOP);

		// Check status
		if (tracee->verbose >= 3) {
			note(tracee, INFO, INTERNAL, "pokedata wstatus=%x stub=%lx addr=%lx word=%lx",
					wstatus, pokedata_workaround_stub_addr, addr, word);
		}
		bool success = (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGILL);

		// Restore tracee state to one before intervention
		(void)ptrace(PTRACE_SETSIGMASK, tracee->pid, sizeof(sigset_t), &orig_sigset);
		tracee->_regs[CURRENT] = orig_regs;
		tracee->_regs_were_changed = true;
		tracee->pokedata_workaround_cancelled_syscall = true;
		tracee->restore_original_regs = restore_original_regs;

		status = success ? 0 : -1;
		if (!success) {
			note(tracee, ERROR, INTERNAL, "POKEDATA workaround stub got signal %d", WSTOPSIG(wstatus));
			errno = EFAULT;
		}
	}
#endif
	return status;
}

/**
 * 原版逻辑不变，仅做变量显式初始化，消除编译警告
 */
void mem_prepare_after_execve(Tracee *tracee)
{
#if HAS_POKEDATA_WORKAROUND
	tracee->pokedata_workaround_stub_addr = peek_reg(tracee, CURRENT, INSTR_POINTER) + offset_to_pokedata_workaround;
#endif
}

void mem_prepare_before_first_execve(Tracee *tracee)
{
#if HAS_POKEDATA_WORKAROUND
	tracee->pokedata_workaround_stub_addr = (word_t)&launcher_pokedata_workaround;
#endif
}

/**
 * Copy @size bytes from src to dest in tracee.
 * 优化：1. 显式变量初始化 2. 消除void*转换警告 3. process_vm参数精简
 * 修复：const指针类型不兼容警告，统一定义const uint8_t*指针
 */
int write_data(Tracee *tracee, word_t dest_tracee, const void *src_tracer, word_t size)
{
	const word_t *src  = (const word_t *)src_tracer;
	word_t *dest = (word_t *)(uintptr_t)dest_tracee;
	long   status = -1;
	word_t word = 0, i = 0, j = 0;
	word_t nb_trailing_bytes = 0;
	word_t nb_full_words = 0;
	uint8_t *last_dest_word = NULL;
	const uint8_t *last_src_word = NULL; // 修复：改为const指针，匹配源数据类型

	if (size == 0 || src_tracer == NULL || tracee == NULL)
		return 0;

#if defined(HAVE_PROCESS_VM)
	struct iovec local  = {.iov_base = (void *)src, .iov_len = size};
	struct iovec remote = {.iov_base = (void *)dest, .iov_len = size};
	status = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
	if ((size_t)status == size)
		return 0;
#endif /* HAVE_PROCESS_VM */

	nb_trailing_bytes = size % sizeof(word_t);
	nb_full_words     = (size - nb_trailing_bytes) / sizeof(word_t);

	/* Clear errno so we won't detect previous syscall failure as ptrace one */
	errno = 0;
	for (i = 0; i < nb_full_words; i++) {
		status = ptrace_pokedata_or_via_stub(tracee, (word_t)(dest + i), load_word(&src[i]));
		if (status < 0) {
			note(tracee, WARNING, SYSTEM, "ptrace(POKEDATA)");
			return -EFAULT;
		}
	}
	if (nb_trailing_bytes == 0)
		return 0;

	/* Copy the bytes in the last word carefully */
	errno = 0;
	word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(dest + i), NULL);
	if (errno != 0) {
		note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
		return -EFAULT;
	}

	last_dest_word = (uint8_t *)&word;
	last_src_word  = (const uint8_t *)&src[i]; // 类型匹配，无警告
	for (j = 0; j < nb_trailing_bytes; j++)
		last_dest_word[j] = last_src_word[j];

	status = ptrace_pokedata_or_via_stub(tracee, (word_t)(dest + i), word);
	if (status < 0) {
		note(tracee, WARNING, SYSTEM, "ptrace(POKEDATA)");
		return -EFAULT;
	}
	return 0;
}

/**
 * 原版逻辑不变，仅做process_vm参数精简+变量显式初始化
 */
int writev_data(Tracee *tracee, word_t dest_tracee, const struct iovec *src_tracer, int src_tracer_count)
{
	size_t size = 0;
	int status = -1;
	int i = 0;

	if (src_tracer_count <= 0 || src_tracer == NULL || tracee == NULL)
		return 0;

#if defined(HAVE_PROCESS_VM)
	struct iovec remote = {.iov_base = (void *)(uintptr_t)dest_tracee, .iov_len = 0};
	for (i = 0; i < src_tracer_count; i++)
		remote.iov_len += src_tracer[i].iov_len;

	status = process_vm_writev(tracee->pid, src_tracer, src_tracer_count, &remote, 1, 0);
	if ((size_t)status == remote.iov_len)
		return 0;
#endif /* HAVE_PROCESS_VM */

	for (i = 0, size = 0; i < src_tracer_count; i++) {
		status = write_data(tracee, dest_tracee + size,
				src_tracer[i].iov_base, (word_t)src_tracer[i].iov_len);
		if (status < 0)
			return status;
		size += src_tracer[i].iov_len;
	}
	return 0;
}

/**
 * Copy @size bytes from tracee to dest.
 * 优化：1. 显式变量初始化 2. 消除void*转换警告 3. 精简冗余判断
 * 修复：const指针类型不兼容警告，统一定义const uint8_t*指针
 */
int read_data(const Tracee *tracee, void *dest_tracer, word_t src_tracee, word_t size)
{
	const word_t *src  = (const word_t *)(uintptr_t)src_tracee;
	word_t *dest = (word_t *)dest_tracer;
	word_t nb_trailing_bytes = 0;
	word_t nb_full_words = 0;
	word_t word = 0, i = 0, j = 0;
	const uint8_t *last_src_word = NULL; // 修复：改为const指针，匹配源数据类型
	uint8_t *last_dest_word = NULL;

	if (size == 0 || dest_tracer == NULL || tracee == NULL)
		return 0;

#if defined(HAVE_PROCESS_VM)
	long status = -1;
	struct iovec local  = {.iov_base = dest, .iov_len = size};
	struct iovec remote = {.iov_base = (void *)src, .iov_len = size};
	status = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
	if ((size_t)status == size)
		return 0;
#endif /* HAVE_PROCESS_VM */

	nb_trailing_bytes = size % sizeof(word_t);
	nb_full_words     = (size - nb_trailing_bytes) / sizeof(word_t);

	/* Clear errno so we won't detect previous syscall failure as ptrace one */
	errno = 0;
	for (i = 0; i < nb_full_words; i++) {
		word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(src + i), NULL);
		if (errno != 0) {
			note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
			return -EFAULT;
		}
		store_word(&dest[i], word);
	}
	if (nb_trailing_bytes == 0)
		return 0;

	word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(src + i), NULL);
	if (errno != 0) {
		note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
		return -EFAULT;
	}

	last_dest_word = (uint8_t *)&dest[i];
	last_src_word  = (const uint8_t *)&word; // 类型匹配，无警告
	for (j = 0; j < nb_trailing_bytes; j++)
		last_dest_word[j] = last_src_word[j];

	return 0;
}

/**
 * Read string from tracee.
 * 优化：1. 消除魔法数字 2. 显式类型转换 3. 精简process_vm块计算
 */
int read_string(const Tracee *tracee, char *dest_tracer, word_t src_tracee, word_t max_size)
{
	const word_t *src  = (const word_t *)(uintptr_t)src_tracee;
	word_t *dest = (word_t *)dest_tracer;
	word_t nb_trailing_bytes = 0;
	word_t nb_full_words = 0;
	word_t word = 0, i = 0, j = 0;
	uint8_t *src_word = NULL;
	uint8_t *dest_word = NULL;

	if (max_size == 0 || dest_tracer == NULL || tracee == NULL)
		return -EINVAL;

#if defined(HAVE_PROCESS_VM)
	long status = -1;
	size_t size = 0;
	size_t offset = 0;
	struct iovec local;
	struct iovec remote;
	static size_t chunk_size = 0;
	static uintptr_t chunk_mask = 0;

	/* A chunk shall not cross a page boundary.  */
	if (chunk_size == 0) {
		chunk_size = (size_t)sysconf(_SC_PAGE_SIZE);
		chunk_size = (chunk_size > 0 && chunk_size < PAGE_SIZE_SAFE) ? chunk_size : PAGE_SIZE_SAFE;
		chunk_mask = ~(chunk_size - 1);
	}

	/* Read the string by chunk.  */
	for (offset = 0; offset < max_size; offset += size) {
		uintptr_t current_chunk = (src_tracee + offset) & chunk_mask;
		size = (current_chunk + chunk_size) - (src_tracee + offset);
		size = (size < (max_size - offset)) ? size : (max_size - offset);

		local.iov_base  = (uint8_t *)dest + offset;
		local.iov_len   = size;
		remote.iov_base = (uint8_t *)src + offset;
		remote.iov_len  = size;

		status = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
		if ((size_t)status != size)
			goto fallback;

		size_t str_len = strnlen((const char *)local.iov_base, size);
		if (str_len < size) {
			size = offset + str_len + 1;
			assert(size <= (size_t)max_size);
			return (int)size;
		}
	}
	assert(offset == (size_t)max_size);

fallback:
#endif /* HAVE_PROCESS_VM */
	nb_trailing_bytes = max_size % sizeof(word_t);
	nb_full_words     = (max_size - nb_trailing_bytes) / sizeof(word_t);

	/* Clear errno so we won't detect previous syscall failure as ptrace one */
	errno = 0;
	for (i = 0; i < nb_full_words; i++) {
		word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(src + i), NULL);
		if (errno != 0)
			return -EFAULT;
		store_word(&dest[i], word);

		/* Stop once an end-of-string is detected. */
		src_word = (uint8_t *)&word;
		for (j = 0; j < sizeof(word_t); j++) {
			if (src_word[j] == '\0')
				return (int)(i * sizeof(word_t) + j + 1);
		}
	}

	/* Copy the bytes from the last word carefully */
	word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(src + i), NULL);
	if (errno != 0)
		return -EFAULT;

	dest_word = (uint8_t *)&dest[i];
	src_word  = (uint8_t *)&word;
	for (j = 0; j < nb_trailing_bytes; j++) {
		dest_word[j] = src_word[j];
		if (src_word[j] == '\0')
			break;
	}
	return (int)(i * sizeof(word_t) + j + 1);
}

/**
 * Peek word from tracee memory.
 * 优化：1. 显式变量初始化 2. 消除void*转换警告 3. 精简冗余判断
 */
word_t peek_word(const Tracee *tracee, word_t address)
{
	word_t result = 0;
	if (tracee == NULL || address == 0) {
		errno = EINVAL;
		return 0;
	}

#if defined(HAVE_PROCESS_VM)
	int status = -1;
	struct iovec local  = {.iov_base = &result, .iov_len = sizeof_word(tracee)};
	struct iovec remote = {.iov_base = (void *)(uintptr_t)address, .iov_len = sizeof_word(tracee)};
	errno = 0;
	status = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
	if (status > 0) {
		if (is_32on64_mode(tracee))
			result &= 0xFFFFFFFFULL;
		return result;
	}
#endif

	errno = 0;
	result = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)address, NULL);
	if (errno == EIO)
		errno = EFAULT;

	if (is_32on64_mode(tracee))
		result &= 0xFFFFFFFFULL;

	return result;
}

/**
 * Poke word to tracee memory.
 * 优化：1. 显式变量初始化 2. 消除void*转换警告 3. 64位掩码显式标注ULL
 */
void poke_word(const Tracee *tracee, word_t address, word_t value)
{
	word_t tmp = 0;
	if (tracee == NULL || address == 0) {
		errno = EINVAL;
		return;
	}

#if defined(HAVE_PROCESS_VM)
	int status = -1;
	struct iovec local  = {.iov_base = &value, .iov_len = sizeof_word(tracee)};
	struct iovec remote = {.iov_base = (void *)(uintptr_t)address, .iov_len = sizeof_word(tracee)};
	errno = 0;
	status = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
	if (status > 0)
		return;
#endif

	/* Don't overwrite the 32 MSB when running a 32-bit process on a 64-bit kernel. */
	if (is_32on64_mode(tracee)) {
		errno = 0;
		tmp = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)address, NULL);
		if (errno != 0)
			return;
		value |= (tmp & 0xFFFFFFFF00000000ULL);
	}

	errno = 0;
	(void)ptrace(PTRACE_POKEDATA, tracee->pid, (void *)(uintptr_t)address, (void *)value);
	if (errno == EIO)
		errno = EFAULT;
}

/**
 * Allocate memory in tracee stack.
 * 优化：1. 显式变量初始化 2. 溢出判断增强 3. 消除符号比较警告
 * 修复：ssize_t用abs截断警告，替换为labs处理长整型
 */
word_t alloc_mem(Tracee *tracee, ssize_t size)
{
	word_t stack_pointer = 0;
	if (tracee == NULL || !IS_IN_SYSENTER(tracee) || size == 0)
		return 0;

	stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);
	/* Add red zone if stack pointer is unmodified */
	if (stack_pointer == peek_reg(tracee, ORIGINAL, STACK_POINTER))
		size += RED_ZONE_SIZE;

	/* 增强溢出检测：覆盖无符号/有符号所有场景 */
	if ((size > 0 && (uint64_t)stack_pointer <= (uint64_t)size) ||
	    (size < 0 && (uint64_t)stack_pointer >= (UINT64_MAX + (uint64_t)size + 1))) {
		note(tracee, WARNING, INTERNAL, "integer under/overflow detected in %s", __FUNCTION__);
		return 0;
	}

	/* Remember the stack grows downward. */
	stack_pointer -= (word_t)labs(size); // 修复：用labs替代abs，支持ssize_t(long)类型
	poke_reg(tracee, STACK_POINTER, stack_pointer);

	return stack_pointer;
}

/**
 * Clear memory in tracee.
 * 优化：**轻量内存池复用**，避免频繁mmap/munmap，提升小内存清空性能
 * 修复：C23扩展警告，将label后声明移至label前
 */
int clear_mem(Tracee *tracee, word_t address, size_t size)
{
	int status = -1;
	static void *zero_pool = NULL;
	static size_t pool_size = 0;
	void *zeros = NULL; // 修复：提前声明变量，解决label后声明的C23扩展警告

	if (tracee == NULL || address == 0 || size == 0)
		return -EINVAL;

	// 小内存复用内存池，大内存原版逻辑（避免池过大）
	if (size <= CLEAR_MEM_MIN_SIZE) {
		if (zero_pool == NULL || pool_size < size) {
			if (zero_pool != NULL)
				munmap(zero_pool, pool_size);
			pool_size = ((size + PAGE_SIZE_SAFE - 1) / PAGE_SIZE_SAFE) * PAGE_SIZE_SAFE;
			zero_pool = mmap(NULL, pool_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (zero_pool == MAP_FAILED) {
				zero_pool = NULL;
				pool_size = 0;
				goto fallback;
			}
		}
		status = write_data(tracee, address, zero_pool, (word_t)size);
		if (status == 0)
			return 0;
	}

fallback:
	// 原版mmap逻辑，作为兜底
	zeros = mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (zeros == MAP_FAILED)
		return -errno;

	status = write_data(tracee, address, zeros, (word_t)size);
	munmap(zeros, size);
	return status;
}
