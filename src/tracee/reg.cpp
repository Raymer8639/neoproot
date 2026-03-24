// 消C99设计器初始化警告，适配Clang++
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-designator"

#include <cstddef>
#include <cstdint>
#include <cinttypes>
#include <climits>
#include <cstring>
#include <cassert>
#include <cerrno>

#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

// 强制定义NT_PRSTATUS，解决Android NDK头文件缺失
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#if defined(ARCH_ARM64)
#include <linux/elf.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "arch.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "cli/note.h"
#include "compat.h"

#ifdef __cplusplus
}
#endif

/**
 * 寄存器取值宏：自动切换AArch32/ARM64偏移表
 */
#define REG(tracee, version, index)					\
	(*(word_t*) (tracee->is_aarch32					\
		? (((uint8_t *) &tracee->_regs[version]) + reg_offset_armeabi[index]) \
		: (((uint8_t *) &tracee->_regs[version]) + reg_offset[index])))

/* 仅保留ARM64架构，彻底删除所有x86相关定义 */
#if defined(ARCH_ARM64)
    // ARM64原生模式寄存器偏移（符合ARM64 ABI：x0-x5传参，x8存系统调用号）
    #define USER_REGS_OFFSET(reg_name) offsetof(struct user_regs_struct, reg_name)
    // AArch32兼容模式寄存器偏移（符合ARM EABI：r0-r5传参，r7存系统调用号）
    #define USER_REGS_OFFSET_32(reg_number) ((reg_number) * 4)
    
    // ARM64原生模式寄存器偏移表
    static off_t reg_offset[] = {
	[SYSARG_NUM]    = USER_REGS_OFFSET(regs[8]),   // 系统调用号 x8
	[SYSARG_1]      = USER_REGS_OFFSET(regs[0]),   // 参数1 x0
	[SYSARG_2]      = USER_REGS_OFFSET(regs[1]),   // 参数2 x1
	[SYSARG_3]      = USER_REGS_OFFSET(regs[2]),   // 参数3 x2
	[SYSARG_4]      = USER_REGS_OFFSET(regs[3]),   // 参数4 x3
	[SYSARG_5]      = USER_REGS_OFFSET(regs[4]),   // 参数5 x4
	[SYSARG_6]      = USER_REGS_OFFSET(regs[5]),   // 参数6 x5
	[SYSARG_RESULT] = USER_REGS_OFFSET(regs[0]),   // 结果 x0
	[STACK_POINTER] = USER_REGS_OFFSET(sp),        // 栈指针 sp
	[INSTR_POINTER] = USER_REGS_OFFSET(pc),        // 指令指针 pc
	[USERARG_1]     = USER_REGS_OFFSET(regs[0]),   // 用户参数1 x0
    };
    
    // AArch32兼容模式寄存器偏移表
    static off_t reg_offset_armeabi[] = {
	[SYSARG_NUM]    = USER_REGS_OFFSET_32(7),      // 系统调用号 r7
	[SYSARG_1]      = USER_REGS_OFFSET_32(0),      // 参数1 r0
	[SYSARG_2]      = USER_REGS_OFFSET_32(1),      // 参数2 r1
	[SYSARG_3]      = USER_REGS_OFFSET_32(2),      // 参数3 r2
	[SYSARG_4]      = USER_REGS_OFFSET_32(3),      // 参数4 r3
	[SYSARG_5]      = USER_REGS_OFFSET_32(4),      // 参数5 r4
	[SYSARG_6]      = USER_REGS_OFFSET_32(5),      // 参数6 r5
	[SYSARG_RESULT] = USER_REGS_OFFSET_32(0),      // 结果 r0
	[STACK_POINTER] = USER_REGS_OFFSET_32(13),     // 栈指针 sp (r13)
	[INSTR_POINTER] = USER_REGS_OFFSET_32(15),     // 指令指针 pc (r15)
	[USERARG_1]     = USER_REGS_OFFSET_32(0),      // 用户参数1 r0
    };
#else
    #error "Only ARM64 architecture is supported"
#endif

// 关闭Clang警告屏蔽
#pragma clang diagnostic pop

/**
 * 从缓存读取寄存器值（AArch32模式屏蔽高位32位）
 */
extern "C" word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg)
{
	assert(version < NB_REG_VERSION);
	word_t result = REG(tracee, version, reg);
	
	// AArch32/32位模式下强制屏蔽高位，确保32位程序兼容性
#if defined(ARCH_ARM64)
	if (is_32on64_mode(tracee)) {
		result &= 0xFFFFFFFFULL;
	}
#endif
	return result;
}

/**
 * 写入寄存器缓存值（AArch32模式仅更新低32位）
 */
extern "C" void poke_reg(Tracee *tracee, Reg reg, word_t value)
{
	word_t current_value = REG(tracee, CURRENT, reg);
	if (current_value == value)
		return;

#ifdef ARCH_ARM64
	// AArch32模式：保留高32位，仅更新低32位
	if (is_32on64_mode(tracee)) {
		const uint32_t new_low = static_cast<uint32_t>(value);
		const uint32_t current_high = static_cast<uint32_t>(current_value >> 32);
		REG(tracee, CURRENT, reg) = (static_cast<word_t>(current_high) << 32) | new_low;
	} else {
		// ARM64原生模式：直接写入64位值
		REG(tracee, CURRENT, reg) = value;
	}
#endif

	tracee->_regs_were_changed = true;
}

/**
 * 打印当前寄存器状态（调试用）
 */
extern "C" void print_current_regs(Tracee *tracee, int verbose_level, const char *message)
{
	if (tracee->verbose < verbose_level || message == nullptr)
		return;

	note(tracee, INFO, INTERNAL,
		"vpid %" PRIu64 ": %s: %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx [0x%lx, %d]",
		tracee->vpid, message,
		stringify_sysnum(get_sysnum(tracee, CURRENT)),
		peek_reg(tracee, CURRENT, SYSARG_1), peek_reg(tracee, CURRENT, SYSARG_2),
		peek_reg(tracee, CURRENT, SYSARG_3), peek_reg(tracee, CURRENT, SYSARG_4),
		peek_reg(tracee, CURRENT, SYSARG_5), peek_reg(tracee, CURRENT, SYSARG_6),
		peek_reg(tracee, CURRENT, SYSARG_RESULT),
		peek_reg(tracee, CURRENT, STACK_POINTER),
		get_abi(tracee));
}

/**
 * 保存当前寄存器组到指定版本缓存（ORIGINAL/ORIGINAL_SECCOMP_REWRITE/CURRENT）
 */
extern "C" void save_current_regs(Tracee *tracee, RegVersion version)
{
	if (version == ORIGINAL)
		tracee->_regs_were_changed = false;

	memcpy(&tracee->_regs[version], &tracee->_regs[CURRENT], sizeof(tracee->_regs[CURRENT]));
}

/**
 * 从内核读取寄存器值到缓存（ARM64高效实现：PTRACE_GETREGSET）
 */
extern "C" int fetch_regs(Tracee *tracee)
{
	int status = -1;
#if defined(ARCH_ARM64)
	struct iovec regs = {
		.iov_base = &tracee->_regs[CURRENT],
		.iov_len = sizeof(tracee->_regs[CURRENT])
	};
	// 核心接口：获取PRSTATUS状态（通用寄存器）
	status = static_cast<int>(ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &regs));
	
	// AArch32兼容模式容错：部分安卓内核需二次调用确保成功
	if (status < 0 && tracee->is_aarch32) {
		status = static_cast<int>(ptrace(PTRACE_GETREGSET, tracee->pid, NT_PRSTATUS, &regs));
	}
#endif
	return (status < 0) ? -errno : 0;
}

/**
 * 写入寄存器缓存到内核（支持是否恢复系统调用号）
 */
extern "C" int push_specific_regs(Tracee *tracee, bool including_sysnum)
{
	// 无变更时直接返回，避免无效系统调用
	if (!tracee->_regs_were_changed
			&& !(tracee->restore_original_regs && tracee->restore_original_regs_after_seccomp_event)) {
		return 0;
	}

	int status = 0;
	// 恢复原始寄存器（用于SECComp重写后恢复）
	if (tracee->restore_original_regs) {
		RegVersion restore_from = ORIGINAL;
		if (tracee->restore_original_regs_after_seccomp_event) {
			restore_from = ORIGINAL_SECCOMP_REWRITE;
			tracee->restore_original_regs_after_seccomp_event = false;
		}
		// 恢复核心寄存器（仅ARM64，无x86冗余）
#    define RESTORE(sysarg) (void) (reg_offset[SYSARG_RESULT] != reg_offset[sysarg] && \
				(REG(tracee, CURRENT, sysarg) = REG(tracee, restore_from, sysarg)))
		RESTORE(SYSARG_NUM);
		RESTORE(SYSARG_1);
		RESTORE(SYSARG_2);
		RESTORE(SYSARG_3);
		RESTORE(SYSARG_4);
		RESTORE(SYSARG_5);
		RESTORE(SYSARG_6);
		RESTORE(STACK_POINTER);
#undef RESTORE
	}

#if defined(ARCH_ARM64)
	// 写入所有通用寄存器到内核
	struct iovec regs = {
		.iov_base = &tracee->_regs[CURRENT],
		.iov_len = sizeof(tracee->_regs[CURRENT])
	};
	
	// 单独处理系统调用号（ARM64特有：NT_ARM_SYSTEM_CALL寄存器段）
	if (including_sysnum) {
		const word_t current_sysnum = REG(tracee, CURRENT, SYSARG_NUM);
		if (current_sysnum != REG(tracee, ORIGINAL, SYSARG_NUM)) {
			struct iovec syscall_regs = {
				.iov_base = const_cast<word_t*>(&current_sysnum),
				.iov_len = sizeof(current_sysnum)
			};
			status = static_cast<int>(ptrace(PTRACE_SETREGSET, tracee->pid, NT_ARM_SYSTEM_CALL, &syscall_regs));
			if (status < 0) {
				return -errno;
			}
		}
	}
	
	// 写入核心寄存器组
	status = static_cast<int>(ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &regs));
	
	// AArch32兼容模式容错
	if (status < 0 && tracee->is_aarch32) {
		status = static_cast<int>(ptrace(PTRACE_SETREGSET, tracee->pid, NT_PRSTATUS, &regs));
	}
#endif

	return (status < 0) ? -errno : 0;
}

/**
 * 写入所有寄存器缓存到内核（默认包含系统调用号）
 */
extern "C" int push_regs(Tracee *tracee)
{
	return push_specific_regs(tracee, true);
}

/**
 * 获取系统调用陷阱指令长度（适配Thumb模式）
 */
extern "C" word_t get_systrap_size(Tracee *tracee)
{
#if defined(ARCH_ARM64)
	// AArch32 Thumb模式：陷阱指令为2字节（SWI指令）
	if (tracee->is_aarch32 && (((unsigned char *) &tracee->_regs[CURRENT])[0x40] & 0x20) != 0) {
		return 2;
	}
#endif
	// ARM64原生模式：陷阱指令为4字节（SVC指令）
	return SYSTRAP_SIZE;
}
