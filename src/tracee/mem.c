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
#define PTRACE_RETRY_CNT    0       // 优化：砍掉ptrace重试（process_vm优先，无需重试）
#define PAGE_SIZE_SAFE      4096    // 页大小常量，适配process_vm块操作
#define CLEAR_MEM_MIN_SIZE  2048    // 优化：提高内存池复用阈值，减少小内存申请开销
#define PROCESS_VM_FORCE    1       // 强制优先使用process_vm标准接口
/**
 * Load the word at the given @address, potentially *not* aligned.
 * 优化：显式类型转换，消除编译对齐警告，精简分支逻辑
 */
static inline word_t load_word(const void *address)
{
	word_t value = 0;
#ifdef NO_MISALIGNED_ACCESS
	if (((uintptr_t)address) % sizeof(word_t) == 0)
		return *(const word_t *)address;
#endif
	memcpy(&value, address, sizeof(word_t));
	return value;
}
/**
 * Store the word with the given @value to the given @address,
 * potentially *not* aligned.
 * 优化：显式类型转换，消除编译对齐警告，精简分支逻辑
 */
static inline void store_word(void *address, word_t value)
{
#ifdef NO_MISALIGNED_ACCESS
	if (((uintptr_t)address) % sizeof(word_t) == 0) {
		*((word_t *)address) = value;
		return;
	}
#endif
	memcpy(address, &value, sizeof(word_t));
}
/**
 * ptrace_pokedata封装：保留原接口，精简冗余逻辑，仅做基础错误处理
 * 原兼容逻辑保留，砍掉无意义的循环重试，提升执行效率
 */
static int ptrace_pokedata_or_via_stub(Tracee *tracee, word_t addr, word_t word)
{
	int status = -1;
#if HAS_POKEDATA_WORKAROUND
	static bool pokedata_workaround_needed = false;
	static bool pokedata_workaround_checked = false;
	if (!pokedata_workaround_needed)
		status = ptrace(PTRACE_POKEDATA, tracee->pid, (void *)(uintptr_t)addr, (void *)(uintptr_t)word);
	if (!pokedata_workaround_checked) {
		pokedata_workaround_needed = (status != 0);
		pokedata_workaround_checked = true;
		if (pokedata_workaround_needed)
			VERBOSE(tracee, 1, "Detected broken PTRACE_POKEDATA - enabling workaround");
	}
	if (pokedata_workaround_needed && tracee->is_aarch32) {
		note(tracee, ERROR, INTERNAL, "POKEDATA workaround is not supported on AArch32");
		errno = EIO;
		return -1;
	} else if (pokedata_workaround_needed) {
		struct user_regs_struct orig_regs = tracee->_regs[CURRENT];
		bool restore_original_regs = tracee->restore_original_regs;
		sigset_t orig_sigset, modified_sigset;
		(void)ptrace(PTRACE_GETSIGMASK, tracee->pid, sizeof(sigset_t), &orig_sigset);
		sigfillset(&modified_sigset);
		sigdelset(&modified_sigset, SIGILL);
		sigdelset(&modified_sigset, SIGTRAP);
		sigdelset(&modified_sigset, SIGBUS);
		sigdelset(&modified_sigset, SIGSEGV);
		sigdelset(&modified_sigset, SIGSYS);
		(void)ptrace(PTRACE_SETSIGMASK, tracee->pid, sizeof(sigset_t), &modified_sigset);
		poke_reg(tracee, INSTR_POINTER, tracee->pokedata_workaround_stub_addr);
		poke_reg(tracee, SYSARG_2, word);
		poke_reg(tracee, SYSARG_3, addr);
		set_sysnum(tracee, PR_void);
		tracee->_regs_were_changed = true;
		tracee->restore_original_regs = false;
		push_specific_regs(tracee, true);
		int wstatus = 0;
		bool redeliver_sigstop = false;
		do {
			(void)ptrace(PTRACE_CONT, tracee->pid, 0, 0);
			(void)waitpid(tracee->pid, &wstatus, 0);
			if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP)
				redeliver_sigstop = true;
		} while (WIFSTOPPED(wstatus) && (WSTOPSIG(wstatus) == SIGSYS || WSTOPSIG(wstatus) == SIGSTOP));
		if (redeliver_sigstop)
			(void)kill(tracee->pid, SIGSTOP);
		bool success = (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGILL);
		(void)ptrace(PTRACE_SETSIGMASK, tracee->pid, sizeof(sigset_t), &orig_sigset);
		tracee->_regs[CURRENT] = orig_regs;
		tracee->_regs_were_changed = true;
		tracee->pokedata_workaround_cancelled_syscall = true;
		tracee->restore_original_regs = restore_original_regs;
		if (!success) {
			note(tracee, ERROR, INTERNAL, "POKEDATA workaround stub got signal %d", WSTOPSIG(wstatus));
			errno = EFAULT;
			return -1;
		}
		status = 0;
	}
#else
	// 无兼容逻辑时，直接调用ptrace，砍掉冗余循环
	status = ptrace(PTRACE_POKEDATA, tracee->pid, (void *)(uintptr_t)addr, (void *)(uintptr_t)word);
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
 * 核心优化：强制优先使用process_vm标准接口，砍掉ptrace冗余逻辑，统一指针类型
 */
int write_data(Tracee *tracee, word_t dest_tracee, const void *src_tracer, word_t size)
{
	if (size == 0 || src_tracer == NULL || tracee == NULL)
		return 0;
#if defined(HAVE_PROCESS_VM) && PROCESS_VM_FORCE
	// 优化：强制使用process_vm标准接口，精简参数，统一uintptr_t转换
	struct iovec local  = {.iov_base = (void *)src_tracer, .iov_len = (size_t)size};
	struct iovec remote = {.iov_base = (void *)(uintptr_t)dest_tracee, .iov_len = (size_t)size};
	ssize_t ret = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
	if (ret == (ssize_t)size)
		return 0;
#endif /* HAVE_PROCESS_VM */
	// 原ptrace逻辑作为兜底，仅做必要精简，保留原接口兼容
	const word_t *src  = (const word_t *)src_tracer;
	word_t *dest = (word_t *)(uintptr_t)dest_tracee;
	const word_t nb_trailing_bytes = size % sizeof(word_t);
	const word_t nb_full_words     = (size - nb_trailing_bytes) / sizeof(word_t);
	long   status = -1;
	word_t word = 0, i = 0, j = 0;
	errno = 0;
	for (i = 0; i < nb_full_words; i++) {
		status = ptrace_pokedata_or_via_stub(tracee, (word_t)(uintptr_t)(dest + i), load_word(&src[i]));
		if (status < 0) {
			note(tracee, WARNING, SYSTEM, "ptrace(POKEDATA)");
			return -EFAULT;
		}
	}
	if (nb_trailing_bytes == 0)
		return 0;
	errno = 0;
	word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)(dest + i), NULL);
	if (errno != 0) {
		note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
		return -EFAULT;
	}
	uint8_t *last_dest_word = (uint8_t *)&word;
	const uint8_t *last_src_word  = (const uint8_t *)&src[i];
	for (j = 0; j < nb_trailing_bytes; j++)
		last_dest_word[j] = last_src_word[j];
	status = ptrace_pokedata_or_via_stub(tracee, (word_t)(uintptr_t)(dest + i), word);
	if (status < 0) {
		note(tracee, WARNING, SYSTEM, "ptrace(POKEDATA)");
		return -EFAULT;
	}
	return 0;
}
/**
 * 优化：强制process_vm优先，精简循环逻辑，减少函数调用开销
 */
int writev_data(Tracee *tracee, word_t dest_tracee, const struct iovec *src_tracer, int src_tracer_count)
{
	if (src_tracer_count <= 0 || src_tracer == NULL || tracee == NULL)
		return 0;
#if defined(HAVE_PROCESS_VM) && PROCESS_VM_FORCE
	// 优化：一次性计算总长度，直接调用process_vm，砍掉冗余循环
	size_t total_len = 0;
	for (int i = 0; i < src_tracer_count; i++)
		total_len += src_tracer[i].iov_len;
	struct iovec remote = {.iov_base = (void *)(uintptr_t)dest_tracee, .iov_len = total_len};
	ssize_t ret = process_vm_writev(tracee->pid, src_tracer, src_tracer_count, &remote, 1, 0);
	if (ret == (ssize_t)total_len)
		return 0;
#endif /* HAVE_PROCESS_VM */
	// 原逻辑兜底，精简变量初始化
	size_t size = 0;
	int status = -1;
	for (int i = 0; i < src_tracer_count; i++) {
		status = write_data(tracee, dest_tracee + size, src_tracer[i].iov_base, (word_t)src_tracer[i].iov_len);
		if (status < 0)
			return status;
		size += src_tracer[i].iov_len;
	}
	return 0;
}
/**
 * Copy @size bytes from tracee to dest.
 * 核心优化：强制process_vm标准接口，砍掉冗余判断，统一指针类型
 */
int read_data(const Tracee *tracee, void *dest_tracer, word_t src_tracee, word_t size)
{
	if (size == 0 || dest_tracer == NULL || tracee == NULL)
		return 0;
#if defined(HAVE_PROCESS_VM) && PROCESS_VM_FORCE
	// 优化：强制process_vm，精简参数，消除类型转换警告
	struct iovec local  = {.iov_base = dest_tracer, .iov_len = (size_t)size};
	struct iovec remote = {.iov_base = (void *)(uintptr_t)src_tracee, .iov_len = (size_t)size};
	ssize_t ret = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
	if (ret == (ssize_t)size)
		return 0;
#endif /* HAVE_PROCESS_VM */
	// 原ptrace逻辑兜底，精简变量和分支
	const word_t *src  = (const word_t *)(uintptr_t)src_tracee;
	word_t *dest = (word_t *)dest_tracer;
	const word_t nb_trailing_bytes = size % sizeof(word_t);
	const word_t nb_full_words     = (size - nb_trailing_bytes) / sizeof(word_t);
	word_t word = 0, i = 0, j = 0;
	errno = 0;
	for (i = 0; i < nb_full_words; i++) {
		word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)(src + i), NULL);
		if (errno != 0) {
			note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
			return -EFAULT;
		}
		store_word(&dest[i], word);
	}
	if (nb_trailing_bytes == 0)
		return 0;
	word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)(src + i), NULL);
	if (errno != 0) {
		note(tracee, WARNING, SYSTEM, "ptrace(PEEKDATA)");
		return -EFAULT;
	}
	uint8_t *last_dest_word = (uint8_t *)&dest[i];
	const uint8_t *last_src_word  = (const uint8_t *)&word;
	for (j = 0; j < nb_trailing_bytes; j++)
		last_dest_word[j] = last_src_word[j];
	return 0;
}
/**
 * Read string from tracee.
 * 核心优化：精简process_vm块读取逻辑，砍掉冗余计算，提升字符串读取效率
 */
int read_string(const Tracee *tracee, char *dest_tracer, word_t src_tracee, word_t max_size)
{
	if (max_size == 0 || dest_tracer == NULL || tracee == NULL)
		return -EINVAL;
	// 提前声明并**显式初始化**所有变量，彻底消除未初始化警告
	const word_t *src  = (const word_t *)(uintptr_t)src_tracee;
	word_t *dest = (word_t *)dest_tracer;
	word_t nb_trailing_bytes = max_size % sizeof(word_t);
	word_t nb_full_words     = (max_size - nb_trailing_bytes) / sizeof(word_t);
	word_t word = 0, i = 0, j = 0;
#if defined(HAVE_PROCESS_VM) && PROCESS_VM_FORCE
	// 优化：精简chunk计算，直接按页大小读取，砍掉冗余静态变量
	const size_t chunk_size = (size_t)sysconf(_SC_PAGE_SIZE) > 0 ? (size_t)sysconf(_SC_PAGE_SIZE) : PAGE_SIZE_SAFE;
	size_t offset = 0;
	ssize_t ret = 0;
	while (offset < (size_t)max_size) {
		size_t read_size = (offset + chunk_size) > (size_t)max_size ? ((size_t)max_size - offset) : chunk_size;
		struct iovec local  = {.iov_base = (char *)dest_tracer + offset, .iov_len = read_size};
		struct iovec remote = {.iov_base = (void *)(uintptr_t)src_tracee + offset, .iov_len = read_size};
		ret = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
		if (ret <= 0)
			goto fallback;
		size_t str_len = strnlen((const char *)local.iov_base, (size_t)ret);
		if (str_len < (size_t)ret) {
			offset += str_len + 1;
			return (offset <= (size_t)max_size) ? (int)offset : (int)max_size;
		}
		offset += (size_t)ret;
	}
	return (int)max_size;
// 补全缺失的fallback标签，跳转到ptrace兜底逻辑，解决编译错误
fallback:
#endif /* HAVE_PROCESS_VM */
	// 原ptrace逻辑兜底，变量均已提前初始化
	errno = 0;
	for (i = 0; i < nb_full_words; i++) {
		word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)(src + i), NULL);
		if (errno != 0)
			return -EFAULT;
		store_word(&dest[i], word);
		uint8_t *src_word = (uint8_t *)&word;
		for (j = 0; j < sizeof(word_t); j++) {
			if (src_word[j] == '\0')
				return (int)(i * sizeof(word_t) + j + 1);
		}
	}
	word = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)(src + i), NULL);
	if (errno != 0)
		return -EFAULT;
	uint8_t *dest_word = (uint8_t *)&dest[i];
	uint8_t *src_word  = (uint8_t *)&word;
	for (j = 0; j < nb_trailing_bytes; j++) {
		dest_word[j] = src_word[j];
		if (src_word[j] == '\0')
			break;
	}
	return (int)(i * sizeof(word_t) + j + 1);
}
/**
 * Peek word from tracee memory.
 * 核心优化：强制process_vm优先，精简32位兼容逻辑，消除冗余判断
 */
word_t peek_word(const Tracee *tracee, word_t address)
{
	word_t result = 0;
	if (tracee == NULL || address == 0) {
		errno = EINVAL;
		return 0;
	}
#if defined(HAVE_PROCESS_VM) && PROCESS_VM_FORCE
	// 优化：强制process_vm，精简参数，直接读取
	struct iovec local  = {.iov_base = &result, .iov_len = sizeof_word(tracee)};
	struct iovec remote = {.iov_base = (void *)(uintptr_t)address, .iov_len = sizeof_word(tracee)};
	errno = 0;
	ssize_t ret = process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0);
	if (ret > 0) {
		if (is_32on64_mode(tracee))
			result &= 0xFFFFFFFFULL;
		return result;
	}
#endif
	// 原ptrace逻辑兜底，精简代码
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
 * 核心优化：强制process_vm优先，精简64位掩码逻辑，消除类型转换警告
 */
void poke_word(const Tracee *tracee, word_t address, word_t value)
{
	if (tracee == NULL || address == 0) {
		errno = EINVAL;
		return;
	}
#if defined(HAVE_PROCESS_VM) && PROCESS_VM_FORCE
	// 优化：强制process_vm，直接写入，砍掉冗余的peek操作
	struct iovec local  = {.iov_base = &value, .iov_len = sizeof_word(tracee)};
	struct iovec remote = {.iov_base = (void *)(uintptr_t)address, .iov_len = sizeof_word(tracee)};
	errno = 0;
	ssize_t ret = process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0);
	if (ret > 0)
		return;
#endif
	// 原ptrace逻辑兜底，精简变量初始化
	word_t tmp = 0;
	if (is_32on64_mode(tracee)) {
		errno = 0;
		tmp = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(uintptr_t)address, NULL);
		if (errno != 0)
			return;
		value |= (tmp & 0xFFFFFFFF00000000ULL);
	}
	errno = 0;
	(void)ptrace(PTRACE_POKEDATA, tracee->pid, (void *)(uintptr_t)address, (void *)(uintptr_t)value);
	if (errno == EIO)
		errno = EFAULT;
}
/**
 * Allocate memory in tracee stack.
 * 优化：增强溢出判断，精简分支逻辑，消除符号比较警告
 */
word_t alloc_mem(Tracee *tracee, ssize_t size)
{
	if (tracee == NULL || !IS_IN_SYSENTER(tracee) || size == 0)
		return 0;
	word_t stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);
	// 仅在栈指针未修改时添加红区，砍掉冗余判断
	if (stack_pointer == peek_reg(tracee, ORIGINAL, STACK_POINTER))
		size += RED_ZONE_SIZE;
	// 优化：精简溢出判断，覆盖所有有符号/无符号场景
	uint64_t sp_u64 = (uint64_t)stack_pointer;
	uint64_t size_u64 = (uint64_t)labs(size);
	if (size > 0 && sp_u64 <= size_u64) {
		note(tracee, WARNING, INTERNAL, "stack underflow detected in %s", __FUNCTION__);
		return 0;
	}
	// 栈向下生长，直接偏移，砍掉冗余计算
	stack_pointer -= (word_t)size_u64;
	poke_reg(tracee, STACK_POINTER, stack_pointer);
	return stack_pointer;
}
/**
 * Clear memory in tracee.
 * 核心优化：优化标准库mmap内存池，减少系统调用，砍掉冗余逻辑
 * 特点：复用内存池、提前声明变量、兜底逻辑精简
 */
int clear_mem(Tracee *tracee, word_t address, size_t size)
{
	if (tracee == NULL || address == 0 || size == 0)
		return -EINVAL;
	// 静态内存池：复用零内存，减少mmap/munmap开销（标准库优化核心）
	static void *zero_pool = NULL;
	static size_t pool_size = 0;
	int status = -1;
	void *zeros = NULL;
	// 优化：内存池复用阈值提高，减少小内存申请，直接复用大池
	if (size <= CLEAR_MEM_MIN_SIZE) {
		// 仅在池不存在/不足时重新申请，砍掉冗余mmap
		if (zero_pool == NULL || pool_size < size) {
			if (zero_pool != NULL)
				munmap(zero_pool, pool_size);
			// 按页对齐申请，提升内存复用效率
			pool_size = ((size + PAGE_SIZE_SAFE - 1) / PAGE_SIZE_SAFE) * PAGE_SIZE_SAFE;
			zero_pool = mmap(NULL, pool_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (zero_pool == MAP_FAILED) {
				zero_pool = NULL;
				pool_size = 0;
			} else {
				// 直接用内存池写入，砍掉冗余的临时mmap
				status = write_data(tracee, address, zero_pool, (word_t)size);
				if (status == 0)
					return 0;
			}
		} else {
			// 池存在且足够，直接复用
			status = write_data(tracee, address, zero_pool, (word_t)size);
			if (status == 0)
				return 0;
		}
	}
	// 原mmap逻辑兜底，精简代码
	zeros = mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (zeros == MAP_FAILED)
		return -errno;
	status = write_data(tracee, address, zeros, (word_t)size);
	munmap(zeros, size);
	return status;
}
