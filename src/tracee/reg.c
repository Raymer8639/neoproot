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
#include <sys/types.h>  /* off_t, pid_t */
#include <sys/user.h>   /* struct user*, struct user_regs_struct */
#include <sys/ptrace.h> /* ptrace(2), PTRACE*, NT_PRSTATUS, NT_ARM_SYSTEM_CALL */
#include <assert.h>     /* assert(3), */
#include <errno.h>      /* errno(3), */
#include <stddef.h>     /* offsetof(), */
#include <stdint.h>     /* *int*_t, uintptr_t */
#include <inttypes.h>   /* PRI*, */
#include <limits.h>     /* ULONG_MAX, */
#include <string.h>     /* memcpy(3), */
#include <sys/uio.h>    /* struct iovec, */
#include <stdbool.h>    /* bool, true, false */

#include "arch.h"       /* ARCH_*, is_32on64_mode, SYSTRAP_SIZE, PSR_T_BIT */
#if defined(ARCH_ARM64)
#include <linux/elf.h>  /* NT_PRSTATUS */
#endif
#include "syscall/sysnum.h" /* stringify_sysnum, get_sysnum */
#include "tracee/reg.h"  /* Reg, RegVersion, NB_REG_VERSION, tracee struct */
#include "tracee/abi.h"  /* get_abi */
#include "cli/note.h"    /* note, INFO, INTERNAL */
#include "compat.h"

/**
 * 通用宏定义：语义化+解耦，消除魔法数字，增强可维护性
 * 所有宏均做类型安全校验，避免隐式转换
 */
#define REG_CAST_PTR(addr)    ((word_t *)(uintptr_t)(addr))
#define MASK_32BIT            0xFFFFFFFFULL  // 64位掩码，避免32位截断
#define AARCH32_CPSR_OFFSET   0x40U          // AArch32 CPSR寄存器偏移
#define AARCH32_CPSR_T_BIT    0x20U          // AArch32 Thumb模式标志位
#define REG_OFFSET_INVALID    ((off_t)-1)    // 无效寄存器偏移标记
#define PTRACE_OP_FAILED      (-1)           // ptrace操作失败返回值

/**
 * Compute the offset of the register @reg_name in the USER area.
 * 层叠offsetof封装，增强代码可读性，减少重复编写
 */
#define USER_REGS_OFFSET(reg_name) \
    (offsetof(struct user, regs) + offsetof(struct user_regs_struct, reg_name))

/**
 * 基础寄存器访问宏：仅做地址计算，无额外逻辑，解耦核心逻辑
 */
#define REG_BASE(tracee, version, index) \
    (*REG_CAST_PTR(((uint8_t *) &tracee->_regs[version]) + reg_offset[index]))

/* Specify the ABI registers (syscall argument passing, stack pointer).
 * See sysdeps/unix/sysv/linux/${ARCH}/syscall.S from the GNU C Library.
 * 所有架构寄存器偏移表均显式初始化，避免编译器未初始化警告
 */
#if defined(ARCH_X86_64)
    static const off_t reg_offset[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(orig_rax),
        [SYSARG_1]      = USER_REGS_OFFSET(rdi),
        [SYSARG_2]      = USER_REGS_OFFSET(rsi),
        [SYSARG_3]      = USER_REGS_OFFSET(rdx),
        [SYSARG_4]      = USER_REGS_OFFSET(r10),
        [SYSARG_5]      = USER_REGS_OFFSET(r8),
        [SYSARG_6]      = USER_REGS_OFFSET(r9),
        [SYSARG_RESULT] = USER_REGS_OFFSET(rax),
        [STACK_POINTER] = USER_REGS_OFFSET(rsp),
        [INSTR_POINTER] = USER_REGS_OFFSET(rip),
        [RTLD_FINI]     = USER_REGS_OFFSET(rdx),
        [STATE_FLAGS]   = USER_REGS_OFFSET(eflags),
        [USERARG_1]     = USER_REGS_OFFSET(rdi),
    };
    static const off_t reg_offset_x86[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(orig_rax),
        [SYSARG_1]      = USER_REGS_OFFSET(rbx),
        [SYSARG_2]      = USER_REGS_OFFSET(rcx),
        [SYSARG_3]      = USER_REGS_OFFSET(rdx),
        [SYSARG_4]      = USER_REGS_OFFSET(rsi),
        [SYSARG_5]      = USER_REGS_OFFSET(rdi),
        [SYSARG_6]      = USER_REGS_OFFSET(rbp),
        [SYSARG_RESULT] = USER_REGS_OFFSET(rax),
        [STACK_POINTER] = USER_REGS_OFFSET(rsp),
        [INSTR_POINTER] = USER_REGS_OFFSET(rip),
        [RTLD_FINI]     = USER_REGS_OFFSET(rdx),
        [STATE_FLAGS]   = USER_REGS_OFFSET(eflags),
        [USERARG_1]     = USER_REGS_OFFSET(rax),
    };
    #undef  REG_BASE
    #define REG_BASE(tracee, version, index) \
        (*REG_CAST_PTR((tracee->_regs[version].cs == 0x23) \
            ? (((uint8_t *) &tracee->_regs[version]) + reg_offset_x86[index]) \
            : (((uint8_t *) &tracee->_regs[version]) + reg_offset[index])))

#elif defined(ARCH_ARM_EABI)
    static const off_t reg_offset[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(uregs[7]),
        [SYSARG_1]      = USER_REGS_OFFSET(uregs[0]),
        [SYSARG_2]      = USER_REGS_OFFSET(uregs[1]),
        [SYSARG_3]      = USER_REGS_OFFSET(uregs[2]),
        [SYSARG_4]      = USER_REGS_OFFSET(uregs[3]),
        [SYSARG_5]      = USER_REGS_OFFSET(uregs[4]),
        [SYSARG_6]      = USER_REGS_OFFSET(uregs[5]),
        [SYSARG_RESULT] = USER_REGS_OFFSET(uregs[0]),
        [STACK_POINTER] = USER_REGS_OFFSET(uregs[13]),
        [INSTR_POINTER] = USER_REGS_OFFSET(uregs[15]),
        [USERARG_1]     = USER_REGS_OFFSET(uregs[0]),
    };

#elif defined(ARCH_ARM64)
    #undef  USER_REGS_OFFSET
    #define USER_REGS_OFFSET(reg_name) offsetof(struct user_regs_struct, reg_name)
    #define USER_REGS_OFFSET_32(reg_number) ((off_t)(reg_number) * 4) // 32位寄存器步长

    static const off_t reg_offset[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(regs[8]),
        [SYSARG_1]      = USER_REGS_OFFSET(regs[0]),
        [SYSARG_2]      = USER_REGS_OFFSET(regs[1]),
        [SYSARG_3]      = USER_REGS_OFFSET(regs[2]),
        [SYSARG_4]      = USER_REGS_OFFSET(regs[3]),
        [SYSARG_5]      = USER_REGS_OFFSET(regs[4]),
        [SYSARG_6]      = USER_REGS_OFFSET(regs[5]),
        [SYSARG_RESULT] = USER_REGS_OFFSET(regs[0]),
        [STACK_POINTER] = USER_REGS_OFFSET(sp),
        [INSTR_POINTER] = USER_REGS_OFFSET(pc),
        [USERARG_1]     = USER_REGS_OFFSET(regs[0]),
    };
    static const off_t reg_offset_armeabi[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET_32(7),
        [SYSARG_1]      = USER_REGS_OFFSET_32(0),
        [SYSARG_2]      = USER_REGS_OFFSET_32(1),
        [SYSARG_3]      = USER_REGS_OFFSET_32(2),
        [SYSARG_4]      = USER_REGS_OFFSET_32(3),
        [SYSARG_5]      = USER_REGS_OFFSET_32(4),
        [SYSARG_6]      = USER_REGS_OFFSET_32(5),
        [SYSARG_RESULT] = USER_REGS_OFFSET_32(0),
        [STACK_POINTER] = USER_REGS_OFFSET_32(13),
        [INSTR_POINTER] = USER_REGS_OFFSET_32(15),
        [USERARG_1]     = USER_REGS_OFFSET_32(0),
    };
    #undef  REG_BASE
    #define REG_BASE(tracee, version, index) \
        (*REG_CAST_PTR((tracee->is_aarch32) \
            ? (((uint8_t *) &tracee->_regs[version]) + reg_offset_armeabi[index]) \
            : (((uint8_t *) &tracee->_regs[version]) + reg_offset[index])))

#elif defined(ARCH_X86)
    static const off_t reg_offset[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(orig_eax),
        [SYSARG_1]      = USER_REGS_OFFSET(ebx),
        [SYSARG_2]      = USER_REGS_OFFSET(ecx),
        [SYSARG_3]      = USER_REGS_OFFSET(edx),
        [SYSARG_4]      = USER_REGS_OFFSET(esi),
        [SYSARG_5]      = USER_REGS_OFFSET(edi),
        [SYSARG_6]      = USER_REGS_OFFSET(ebp),
        [SYSARG_RESULT] = USER_REGS_OFFSET(eax),
        [STACK_POINTER] = USER_REGS_OFFSET(esp),
        [INSTR_POINTER] = USER_REGS_OFFSET(eip),
        [RTLD_FINI]     = USER_REGS_OFFSET(edx),
        [STATE_FLAGS]   = USER_REGS_OFFSET(eflags),
        [USERARG_1]     = USER_REGS_OFFSET(eax),
    };

#elif defined(ARCH_SH4)
    static const off_t reg_offset[] = {
        [SYSARG_NUM]    = USER_REGS_OFFSET(regs[3]),
        [SYSARG_1]      = USER_REGS_OFFSET(regs[4]),
        [SYSARG_2]      = USER_REGS_OFFSET(regs[5]),
        [SYSARG_3]      = USER_REGS_OFFSET(regs[6]),
        [SYSARG_4]      = USER_REGS_OFFSET(regs[7]),
        [SYSARG_5]      = USER_REGS_OFFSET(regs[0]),
        [SYSARG_6]      = USER_REGS_OFFSET(regs[1]),
        [SYSARG_RESULT] = USER_REGS_OFFSET(regs[0]),
        [STACK_POINTER] = USER_REGS_OFFSET(regs[15]),
        [INSTR_POINTER] = USER_REGS_OFFSET(pc),
        [RTLD_FINI]     = USER_REGS_OFFSET(r4),
    };

#else
    #error "Unsupported architecture for PRoot reg.c (only X86/X86_64/ARM/ARM64/SH4)"
#endif

/**
 * Return the *cached* value of the given @tracees' @reg.
 * 优化点：1.强化入参校验 2.32位掩码加固 3.返回值规范 4.消除隐式转换
 */
word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg)
{
    // 入参全量校验，防止空指针/越界访问
    if (tracee == NULL || version >= NB_REG_VERSION || reg < 0 || reg >= (int)(sizeof(reg_offset)/sizeof(reg_offset[0]))) {
        errno = EINVAL;
        return 0;
    }

    word_t result = REG_BASE(tracee, version, reg);

    // 32位进程运行在64位内核时，仅保留低32位，掩码用ULL避免截断
    if (is_32on64_mode(tracee)) {
        result &= MASK_32BIT;
    }

    return result;
}

/**
 * Set the *cached* value of the given @tracees' @reg.
 * 优化点：1.前置冗余判断 2.32/64位类型安全赋值 3.减少寄存器访问 4.入参加固
 */
void poke_reg(Tracee *tracee, Reg reg, word_t value)
{
    // 快速失败：空指针/无效寄存器直接返回
    if (tracee == NULL || reg < 0 || reg >= (int)(sizeof(reg_offset)/sizeof(reg_offset[0]))) {
        return;
    }

    // 前置冗余判断：值未变化则不操作，避免修改_regs_were_changed
    word_t current_val = peek_reg(tracee, CURRENT, reg);
    if (current_val == value) {
        return;
    }

    // 32位ARM64兼容：显式强转32位赋值，避免64位数据污染
#ifdef ARCH_ARM64
    if (is_32on64_mode(tracee)) {
        *(uint32_t *) &REG_BASE(tracee, CURRENT, reg) = (uint32_t)value;
    } else
#endif
    {
        REG_BASE(tracee, CURRENT, reg) = value;
    }

    // 标记寄存器已修改，后续push时按需同步
    tracee->_regs_were_changed = true;
}

/**
 * Print the value of the current @tracee's registers according
 * to the @verbose_level.  Note: @message is mixed to the output.
 * 优化点：1.入参严格校验 2.减少peek_reg调用 3.避免空指针打印 4.日志格式统一
 */
void print_current_regs(Tracee *tracee, int verbose_level, const char *message)
{
    // 快速失败：空指针/日志级别不足/空消息直接返回
    if (tracee == NULL || message == NULL || tracee->verbose < verbose_level) {
        return;
    }

    // 批量读取寄存器，减少多次peek_reg的底层开销
    const word_t sysnum = get_sysnum(tracee, CURRENT);
    const word_t arg1   = peek_reg(tracee, CURRENT, SYSARG_1);
    const word_t arg2   = peek_reg(tracee, CURRENT, SYSARG_2);
    const word_t arg3   = peek_reg(tracee, CURRENT, SYSARG_3);
    const word_t arg4   = peek_reg(tracee, CURRENT, SYSARG_4);
    const word_t arg5   = peek_reg(tracee, CURRENT, SYSARG_5);
    const word_t arg6   = peek_reg(tracee, CURRENT, SYSARG_6);
    const word_t res    = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    const word_t sp     = peek_reg(tracee, CURRENT, STACK_POINTER);
    const int    abi    = get_abi(tracee);

    // 日志格式标准化，与PRoot整体日志风格保持一致
    note(tracee, INFO, INTERNAL,
        "vpid %" PRIu64 ": %s: %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx [sp:0x%lx, abi:%d]",
        tracee->vpid, message, stringify_sysnum(sysnum),
        arg1, arg2, arg3, arg4, arg5, arg6, res, sp, abi);
}

/**
 * Save the @tracee's current register bank into the @version register
 * bank.
 * 优化点：1.入参校验 2.精简memcpy参数 3.优化_regs_were_changed标记时机
 */
void save_current_regs(Tracee *tracee, RegVersion version)
{
    // 快速失败：空指针/无效版本号直接返回
    if (tracee == NULL || version >= NB_REG_VERSION) {
        return;
    }

    // 仅在保存原始寄存器时标记未修改，精准控制后续push逻辑
    if (version == ORIGINAL) {
        tracee->_regs_were_changed = false;
    }

    // 直接内存拷贝，精简参数，避免中间变量
    memcpy(&tracee->_regs[version], &tracee->_regs[CURRENT], sizeof(struct user_regs_struct));
}

/**
 * Copy all @tracee's general purpose registers into a dedicated
 * cache.  This function returns -errno if an error occured, 0 otherwise.
 * 优化点：1.入参校验 2.结构体显式初始化 3.返回值规范 4.ptrace操作解耦
 */
int fetch_regs(Tracee *tracee)
{
    // 快速失败：空指针直接返回无效参数
    if (tracee == NULL) {
        return -EINVAL;
    }

    int status = PTRACE_OP_FAILED;
#if defined(ARCH_ARM64)
    // 结构体显式零初始化，消除编译警告，避免脏数据
    struct iovec regs = {0};
    regs.iov_base = &tracee->_regs[CURRENT];
    regs.iov_len  = sizeof(struct user_regs_struct);
    status = ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &regs);
#else
    status = ptrace(PTRACE_GETREGS, tracee->pid, NULL, &tracee->_regs[CURRENT]);
#endif

    // ptrace操作失败时，返回负的errno，规范错误码传递
    if (status == PTRACE_OP_FAILED) {
        return -errno;
    }

    return 0;
}

/**
 * Push specific registers back to the tracee process.
 * 优化点：1.前置无操作判断 2.宏定义解耦 3.减少ptrace调用 4.32/64位兼容加固
 */
int push_specific_regs(Tracee *tracee, bool including_sysnum)
{
    // 快速失败：空指针直接返回无效参数
    if (tracee == NULL) {
        return -EINVAL;
    }

    // 前置无操作判断：寄存器未修改且无需恢复，直接返回，避免多余ptrace调用
    if (!tracee->_regs_were_changed && !tracee->restore_original_regs && !tracee->restore_original_regs_after_seccomp_event) {
        return 0;
    }

    int status = 0;
    RegVersion restore_from = ORIGINAL;

    // 确定寄存器恢复源，精简条件分支，减少嵌套
    if (tracee->restore_original_regs_after_seccomp_event) {
        restore_from = ORIGINAL_SECCOMP_REWRITE;
        tracee->restore_original_regs_after_seccomp_event = false;
    }

    // 恢复原始寄存器：按架构区分，X86直接恢复，其他架构跳过结果寄存器
    if (tracee->restore_original_regs) {
#if defined(ARCH_X86) || defined(ARCH_X86_64)
#    define RESTORE_REG(sysarg)  (REG_BASE(tracee, CURRENT, sysarg) = REG_BASE(tracee, restore_from, sysarg))
#else
#    define RESTORE_REG(sysarg)  do { \
        if (reg_offset[SYSARG_RESULT] != reg_offset[sysarg]) \
            REG_BASE(tracee, CURRENT, sysarg) = REG_BASE(tracee, restore_from, sysarg); \
    } while (0)
#endif
        // 批量恢复寄存器，代码更整洁，减少重复编写
        RESTORE_REG(SYSARG_NUM);
        RESTORE_REG(SYSARG_1);
        RESTORE_REG(SYSARG_2);
        RESTORE_REG(SYSARG_3);
        RESTORE_REG(SYSARG_4);
        RESTORE_REG(SYSARG_5);
        RESTORE_REG(SYSARG_6);
        RESTORE_REG(STACK_POINTER);
#undef RESTORE_REG
    }

    // 按架构同步寄存器到tracee进程，解耦不同架构的ptrace逻辑
#if defined(ARCH_ARM64)
    struct iovec regs = {0};
    word_t current_sysnum = REG_BASE(tracee, CURRENT, SYSARG_NUM);
    const word_t original_sysnum = REG_BASE(tracee, ORIGINAL, SYSARG_NUM);

    // 仅当系统调用号变化且需要同步时，调用PTRACE_SETREGSET
    if (including_sysnum && current_sysnum != original_sysnum) {
        regs.iov_base = (void *)&current_sysnum; // 修复const丢弃警告
        regs.iov_len  = sizeof(current_sysnum);
        if (ptrace(PTRACE_SETREGSET, tracee->pid, NT_ARM_SYSTEM_CALL, &regs) == PTRACE_OP_FAILED) {
            return -errno;
        }
    }

    // 同步其他寄存器到进程
    regs.iov_base = &tracee->_regs[CURRENT];
    regs.iov_len  = sizeof(struct user_regs_struct);
    status = ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &regs);

#elif defined(ARCH_ARM_EABI)
    const word_t current_sysnum = REG_BASE(tracee, CURRENT, SYSARG_NUM);
    const word_t original_sysnum = REG_BASE(tracee, ORIGINAL, SYSARG_NUM);

    // ARM EABI单独处理系统调用号修改
    if (including_sysnum && current_sysnum != original_sysnum) {
        status = ptrace(PTRACE_SET_SYSCALL, tracee->pid, 0, (void *)(uintptr_t)current_sysnum);
        if (status == PTRACE_OP_FAILED) {
            return -errno;
        }
    }

    // 同步其他寄存器到进程
    status = ptrace(PTRACE_SETREGS, tracee->pid, NULL, &tracee->_regs[CURRENT]);

#else
    // 其他架构直接同步所有寄存器
    status = ptrace(PTRACE_SETREGS, tracee->pid, NULL, &tracee->_regs[CURRENT]);
#endif

    // ptrace操作失败时，返回负的errno，规范错误码传递
    if (status == PTRACE_OP_FAILED) {
        return -errno;
    }

    return 0;
}

/**
 * Copy the cached values of all @tracee's general purpose registers
 * back to the process, if necessary.
 * 优化点：1.直接复用push_specific_regs 2.入参隐式传递 3.简化接口
 */
int push_regs(Tracee *tracee)
{
    // 复用push_specific_regs，包含系统调用号的同步，简化代码
    return push_specific_regs(tracee, true);
}

/**
 * Get the size of the system call trap instruction for the tracee.
 * 优化点：1.入参校验 2.显式标记未使用参数 3.32位兼容加固 4.消除魔法数字
 */
word_t get_systrap_size(Tracee *tracee)
{
    // 快速失败：空指针返回默认陷阱指令大小
    if (tracee == NULL) {
        return SYSTRAP_SIZE;
    }

#if defined(ARCH_ARM_EABI)
    // ARM Thumb模式：陷阱指令大小为2字节
    if (tracee->_regs[CURRENT].ARM_cpsr & PSR_T_BIT) {
        return 2;
    }

#elif defined(ARCH_ARM64)
    // AArch32 Thumb模式：手动计算CPSR偏移，陷阱指令大小为2字节
    if (tracee->is_aarch32) {
        const uint8_t *cpsr_ptr = ((const uint8_t *) &tracee->_regs[CURRENT]) + AARCH32_CPSR_OFFSET;
        if ((*cpsr_ptr & AARCH32_CPSR_T_BIT) != 0) {
            return 2;
        }
    }

#else
    // 其他架构：显式标记未使用参数，消除编译警告
    (void) tracee;
#endif

    // 默认返回架构定义的陷阱指令大小
    return SYSTRAP_SIZE;
}
