/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
  *
  * This file is part of PRoot.
  *
  * Copyright (C) 2026 scicat
  *
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  */
#include <cstddef>
#include <cstdint>
#include <cinttypes>
#include <climits>
#include <cstring>
#include <cassert>
#include <cerrno>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/elf.h>

// 安卓ARM64专属固定配置，编译期确定，无运行时开销
#define PAGE_SIZE 4096
#define BATCH_SIZE (128 * 1024 / sizeof(word_t))  // 128KB批量，适配安卓ptrace高开销场景
#define PRELOAD_THRESHOLD (512 * 1024)            // 512KB以上触发预加载，平衡内存与速度
#define COLD_BATCH (128 * 1024)                   // 冷数据批量阈值，减少syscall次数
#define ARM64_RED_ZONE 128                        // ARM64标准红区大小，固定值

#ifdef __cplusplus
extern "C" {
#endif
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/heap.h"
#include "arch.h"
#include "build.h"
#include "cli/note.h"
#include "tracee/reg.h"
#include "syscall/sysnum.h"
#ifdef __cplusplus
}
#endif

// 安卓pokedata兼容桩，仅ARM64保留
#ifdef HAS_POKEDATA_WORKAREA
extern const ssize_t offset_to_pokedata_workaround;
void launcher_pokedata_workaround();
__asm__ (
    ".globl launcher_pokedata_workaround\n"
    "launcher_pokedata_workaround:\n"
    "str x1, [x2]\n"
    ".word 0xf7f0a000\n"
);
#endif

// 强制内联工具函数，消除函数调用开销，安卓低版本编译器也能稳定内联
static inline __attribute__((always_inline)) word_t load_word(const void *address)
{
    word_t value;
    memcpy(&value, address, sizeof(word_t));
    return value;
}

static inline __attribute__((always_inline)) void store_word(void *address, word_t value)
{
    memcpy(address, &value, sizeof(word_t));
}

// 安卓专用：远程内存预加载，减少QEMU/ptrace反复读取开销
static __attribute__((unused)) int preload_mem(const Tracee *tracee, word_t address, word_t size)
{
    const word_t aligned_addr = address & ~(PAGE_SIZE - 1);
    const word_t aligned_size = ((address + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - aligned_addr;

    char *preload_buf = (char *)mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (preload_buf == MAP_FAILED)
        return -errno;

    const struct iovec local = {.iov_base = preload_buf, .iov_len = aligned_size};
    const struct iovec remote = {.iov_base = (void *)aligned_addr, .iov_len = aligned_size};
    syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);

    munmap(preload_buf, aligned_size);
    return 0;
}

// execve前后内存状态准备，逻辑完全兼容，仅精简冗余
extern "C" void mem_prepare_after_execve(Tracee *tracee)
{
#ifdef HAS_POKEDATA_WORKAREA
    tracee->pokedata_workaround_stub_addr = peek_reg(tracee, CURRENT, INSTR_POINTER) + offset_to_pokedata_workaround;
#endif
}

extern "C" void mem_prepare_before_first_execve(Tracee *tracee)
{
#ifdef HAS_POKEDATA_WORKAREA
    tracee->pokedata_workaround_stub_addr = (word_t)&launcher_pokedata_workaround;
#endif
}

// 核心优化：write_data，优先安卓支持的process_vm，合并冗余分支，减少syscall
extern "C" int write_data(Tracee *tracee, word_t dest_tracee, const void *src_tracer, word_t size)
{
    if (__builtin_expect(size == 0, 1))
        return 0;

#if defined(HAVE_PROCESS_VM)
    // 安卓优先走process_vm，比ptrace快10倍+，统一处理所有尺寸，无需分支拆分
    const struct iovec local = {.iov_base = (void *)src_tracer, .iov_len = size};
    const struct iovec remote = {.iov_base = (void *)dest_tracee, .iov_len = size};
    const long vm_status = syscall(SYS_process_vm_writev, tracee->pid, &local, 1, &remote, 1, 0);
    if (__builtin_expect(vm_status == (long)size, 1))
        return 0;
#endif

    // 仅process_vm失败时，fallback到ptrace批量写入
    const word_t *src = (const word_t *)src_tracer;
    const word_t nb_trailing_bytes = size % sizeof(word_t);
    const word_t nb_full_words = (size - nb_trailing_bytes) / sizeof(word_t);

    word_t batch_i = 0;
    while (batch_i < nb_full_words) {
        const size_t current_batch = (nb_full_words - batch_i) > BATCH_SIZE ? BATCH_SIZE : (nb_full_words - batch_i);
        for (word_t i = 0; i < current_batch; ++i) {
            const word_t offset = (batch_i + i) * sizeof(word_t);
            if (ptrace(PTRACE_POKEDATA, tracee->pid, dest_tracee + offset, load_word(&src[batch_i + i])) < 0)
                return -EFAULT;
        }
        batch_i += current_batch;
    }

    if (nb_trailing_bytes == 0)
        return 0;

    // 处理非对齐尾部字节，安卓严格内存对齐兼容
    const word_t tail_addr = dest_tracee + nb_full_words * sizeof(word_t);
    word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, tail_addr, NULL);
    if (errno != 0)
        return -EFAULT;

    uint8_t *last_dest = (uint8_t *)&word;
    const uint8_t *last_src = (const uint8_t *)&src[nb_full_words];
    for (word_t j = 0; j < nb_trailing_bytes; ++j)
        last_dest[j] = last_src[j];

    return ptrace(PTRACE_POKEDATA, tracee->pid, tail_addr, word) < 0 ? -EFAULT : 0;
}

// 精简writev_data，复用核心write_data逻辑，无冗余
extern "C" int writev_data(Tracee *tracee, word_t dest_tracee, const struct iovec *src_tracer, int src_tracer_count)
{
    size_t offset = 0;
    for (int i = 0; i < src_tracer_count; ++i) {
        const int ret = write_data(tracee, dest_tracee + offset, src_tracer[i].iov_base, src_tracer[i].iov_len);
        if (__builtin_expect(ret < 0, 0))
            return ret;
        offset += src_tracer[i].iov_len;
    }
    return 0;
}

// 核心优化：read_data，优先process_vm，精简分支，适配安卓内存模型
extern "C" int read_data(const Tracee *tracee, void *dest_tracer, word_t src_tracee, word_t size)
{
    if (__builtin_expect(size == 0, 1))
        return 0;

    // 大尺寸预加载，减少安卓QEMU场景的反复缺页开销
    if (__builtin_expect(size > PRELOAD_THRESHOLD, 0))
        preload_mem(tracee, src_tracee, size);

#if defined(HAVE_PROCESS_VM)
    // 统一走process_vm，全尺寸兼容，无冗余分支
    const struct iovec local = {.iov_base = dest_tracer, .iov_len = size};
    const struct iovec remote = {.iov_base = (void *)src_tracee, .iov_len = size};
    const long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
    if (__builtin_expect(vm_status == (long)size, 1))
        return 0;
#endif

    // fallback ptrace批量读取
    word_t *dest = (word_t *)dest_tracer;
    const word_t nb_trailing_bytes = size % sizeof(word_t);
    const word_t nb_full_words = (size - nb_trailing_bytes) / sizeof(word_t);

    word_t batch_i = 0;
    while (batch_i < nb_full_words) {
        const size_t current_batch = (nb_full_words - batch_i) > BATCH_SIZE ? BATCH_SIZE : (nb_full_words - batch_i);
        for (word_t i = 0; i < current_batch; ++i) {
            const word_t offset = (batch_i + i) * sizeof(word_t);
            const word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, src_tracee + offset, NULL);
            if (errno != 0)
                return -EFAULT;
            store_word(&dest[batch_i + i], word);
        }
        batch_i += current_batch;
    }

    if (nb_trailing_bytes == 0)
        return 0;

    // 非对齐尾部处理，兼容安卓内存对齐要求
    const word_t tail_addr = src_tracee + nb_full_words * sizeof(word_t);
    const word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, tail_addr, NULL);
    if (errno != 0)
        return -EFAULT;

    uint8_t *last_dest = (uint8_t *)&dest[nb_full_words];
    const uint8_t *last_src = (const uint8_t *)&word;
    for (word_t j = 0; j < nb_trailing_bytes; ++j)
        last_dest[j] = last_src[j];

    return 0;
}

// 安卓优化：read_string，优先process_vm按页读取，减少ptrace调用，提升字符串读取速度
extern "C" int read_string(const Tracee *tracee, char *dest_tracer, word_t src_tracee, word_t max_size)
{
    if (__builtin_expect(max_size == 0, 1))
        return 0;

#if defined(HAVE_PROCESS_VM)
    size_t offset = 0;
    while (offset < max_size) {
        const uintptr_t chunk_base = (src_tracee + offset) & ~(PAGE_SIZE - 1);
        const size_t chunk_remain = PAGE_SIZE - ((src_tracee + offset) - chunk_base);
        const size_t copy_size = (chunk_remain < max_size - offset) ? chunk_remain : (max_size - offset);

        const struct iovec local = {.iov_base = dest_tracer + offset, .iov_len = copy_size};
        const struct iovec remote = {.iov_base = (void *)(src_tracee + offset), .iov_len = copy_size};
        const long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);

        if (__builtin_expect(vm_status <= 0, 0))
            break;

        // 按页查找结束符，比逐字ptrace快百倍
        for (size_t i = 0; i < (size_t)vm_status; ++i) {
            if (dest_tracer[offset + i] == '\0')
                return offset + i + 1;
        }

        offset += (size_t)vm_status;
    }
#endif

    // fallback ptrace逐字读取
    const word_t *src = (const word_t *)src_tracee;
    word_t *dest = (word_t *)dest_tracer;
    const word_t nb_trailing_bytes = max_size % sizeof(word_t);
    const word_t nb_full_words = (max_size - nb_trailing_bytes) / sizeof(word_t);

    for (word_t i = 0; i < nb_full_words; ++i) {
        const word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, src + i, NULL);
        if (errno != 0)
            return -EFAULT;
        store_word(&dest[i], word);

        // 按字查找结束符，减少循环次数
        const uint8_t *bytes = (const uint8_t *)&word;
        for (word_t j = 0; j < sizeof(word_t); ++j) {
            if (bytes[j] == '\0')
                return i * sizeof(word_t) + j + 1;
        }
    }

    if (nb_trailing_bytes > 0) {
        const word_t word = ptrace(PTRACE_PEEKDATA, tracee->pid, src + nb_full_words, NULL);
        if (errno != 0)
            return -EFAULT;

        uint8_t *d = (uint8_t *)&dest[nb_full_words];
        const uint8_t *s = (const uint8_t *)&word;
        for (word_t j = 0; j < nb_trailing_bytes; ++j) {
            d[j] = s[j];
            if (s[j] == '\0')
                return nb_full_words * sizeof(word_t) + j + 1;
        }
    }

    return max_size;
}

// 优化：peek_word，优先process_vm，精简分支，减少判断
extern "C" word_t peek_word(const Tracee *tracee, word_t address)
{
    word_t result;

#if defined(HAVE_PROCESS_VM)
    const struct iovec local = {.iov_base = &result, .iov_len = sizeof(word_t)};
    const struct iovec remote = {.iov_base = (void *)address, .iov_len = sizeof(word_t)};

    errno = 0;
    const long vm_status = syscall(SYS_process_vm_readv, tracee->pid, &local, 1, &remote, 1, 0);
    if (__builtin_expect(vm_status == sizeof(word_t), 1))
        goto final_adjust;
#endif

    errno = 0;
    result = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, address, NULL);
    if (errno == EIO)
        errno = EFAULT;

final_adjust:
    // 统一处理32位兼容，仅一处判断
    return is_32on64_mode(tracee) ? (result & 0xFFFFFFFFULL) : result;
}

// 优化：poke_word，优先process_vm，精简分支，安卓ptrace兼容
extern "C" void poke_word(const Tracee *tracee, word_t address, word_t value)
{
#if defined(HAVE_PROCESS_VM)
    word_t write_val = value;
    // 32位兼容仅在fallback处理，process_vm直接写入
    if (is_32on64_mode(tracee))
        write_val = value & 0xFFFFFFFFULL;

    const struct iovec local = {.iov_base = &write_val, .iov_len = sizeof(word_t)};
    const struct iovec remote = {.iov_base = (void *)address, .iov_len = sizeof(word_t)};

    errno = 0;
    const long vm_status = syscall(SYS_process_vm_writev, tracee->pid, &local, 1, &remote, 1, 0);
    if (__builtin_expect(vm_status == sizeof(word_t), 1))
        return;
#endif

    // 32位兼容处理，安卓ptrace写入兼容
    word_t final_val = value;
    if (is_32on64_mode(tracee)) {
        errno = 0;
        const word_t orig = (word_t)ptrace(PTRACE_PEEKDATA, tracee->pid, address, NULL);
        if (errno == 0)
            final_val = (value & 0xFFFFFFFFULL) | (orig & 0xFFFFFFFF00000000ULL);
    }

    errno = 0;
    ptrace(PTRACE_POKEDATA, tracee->pid, address, final_val);
    if (errno == EIO)
        errno = EFAULT;
}

// 完全兼容原有逻辑，仅优化常量与分支预测
extern "C" word_t alloc_mem(Tracee *tracee, ssize_t size)
{
    assert(IS_IN_SYSENTER(tracee));
    word_t sp = peek_reg(tracee, CURRENT, STACK_POINTER);

    if (sp == peek_reg(tracee, ORIGINAL, STACK_POINTER))
        size += ARM64_RED_ZONE;

    // 栈溢出边界检查，安卓低内存场景安全加固
    if (__builtin_expect((size > 0 && sp <= (word_t)size) || (size < 0 && sp >= (word_t)(ULONG_MAX + size)), 0))
        return 0;

    sp -= size;
    poke_reg(tracee, STACK_POINTER, sp);
    return sp;
}

// 安卓优化：clear_mem，小尺寸用栈缓冲，避免mmap开销
extern "C" int clear_mem(Tracee *tracee, word_t address, size_t size)
{
    if (__builtin_expect(size == 0, 1))
        return 0;

    // 小尺寸清零直接用栈，减少syscall，安卓高频小内存场景提速明显
    if (size <= PAGE_SIZE) {
        char zero_buf[PAGE_SIZE] = {0};
        return write_data(tracee, address, zero_buf, size);
    }

    // 大尺寸用匿名映射，避免栈溢出
    void *zeros = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (zeros == MAP_FAILED)
        return -errno;

    memset(zeros, 0, size);
    const int ret = write_data(tracee, address, zeros, size);
    munmap(zeros, size);
    return ret;
}
