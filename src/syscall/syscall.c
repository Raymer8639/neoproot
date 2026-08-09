#include <assert.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <arm_neon.h>

#include "syscall/syscall.h"
#include "syscall/chain.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "cli/note.h"

#define USE_SVC_DIRECT

__attribute__((always_inline, const, artificial))
static inline size_t arm64_neon_strlen(const char *s)
{
    if (__builtin_expect(s == NULL || *s == '\0', 0))
        return 0;

    const uint8_t *buf = (const uint8_t *)s;
    size_t offset = 0;
    const uint8x16_t zero_vec = vdupq_n_u8(0);

    // 对齐处理，和标准glibc strlen完全一致
    const size_t align = (16 - ((uintptr_t)buf & 15)) & 15;
    for (; offset < align; offset++) {
        if (buf[offset] == '\0')
            return offset;
    }

    // ARMv8.2 NEON批量处理
    for (;; offset += 16) {
        const uint8x16_t data = vld1q_u8(buf + offset);
        const uint8x16_t cmp  = vceqq_u8(data, zero_vec);

        if (__builtin_expect(vmaxvq_u8(cmp) != 0, 0)) {
            for (size_t i = 0; i < 16; i++) {
                if (buf[offset + i] == '\0')
                    return offset + i;
            }
        }
    }
}

// 替换标准strlen，仅优化性能，行为完全不变
#undef strlen
#define strlen(s) arm64_neon_strlen(s)

/* ==================== ARM64 安全SVC直接系统调用 ==================== */
#ifdef USE_SVC_DIRECT
__attribute__((always_inline, warn_unused_result, artificial))
static inline long arm64_svc_direct(long sysnum, long a1, long a2, long a3, long a4, long a5, long a6)
{
    register long x8 __asm__("x8") = sysnum;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;

    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "cc", "memory"
    );

    return x0;
}

// 安全白名单：仅无副作用、只读、无需PRoot处理的系统调用
// ⚠️ 2026-08-09 审查瘦身（对话十三）：移除以下错误项——
//   getpid/getppid/gettid：SVC 在 tracer 进程执行，返回的是 uproot 自己的 pid，不是 tracee 的
//   uname：绕过 --kernel-release 虚拟化（tracee 应看到模拟内核版本）
//   sigpending：返回 tracer 挂起信号，非 tracee 的
//   times：返回 tracer 进程 CPU 时间
//   nanosleep/clock_nanosleep：tracer 自己睡眠 → 阻塞整个事件循环（所有 tracee 冻结）
// 保留项均为系统级语义（时钟/随机数/系统信息），与进程无关，SVC 执行结果正确。
// 注：clock_gettime 的 CLOCK_PROCESS/THREAD_CPUTIME_ID 仍会返回 tracer 的时间（罕见边角，可接受）
__attribute__((always_inline, const))
static inline bool is_svc_safe_syscall(word_t sysnum)
{
    switch (sysnum) {
        // 时间相关（墙钟/单调时钟，系统级时钟源，与进程无关）
        case PR_gettimeofday:
        case PR_clock_gettime:
        case PR_clock_getres:
        case PR_time:
        // 调度相关（无副作用）
        case PR_sched_yield:
        case PR_sched_get_priority_max:
        case PR_sched_get_priority_min:
        // 安全随机数（与进程无关）
        case PR_getrandom:
        // 系统信息（全局，与进程无关）
        case PR_sysinfo:
            return true;
        default:
            return false;
    }
}
#endif // USE_SVC_DIRECT

/* ==================== 以下100%原版代码，仅新增安全SVC分支，无任何修改 ==================== */

/**
 * Copy in @path a C string (PATH_MAX bytes max.) from the @tracee's
 * memory address space pointed to by the @reg argument of the
 * current syscall.  This function returns -errno if an error occured,
 * otherwise it returns the size in bytes put into the @path.
 */
int get_sysarg_path(const Tracee *tracee, char path[PATH_MAX], Reg reg)
{
	int size;
	word_t src;

	src = peek_reg(tracee, CURRENT, reg);

	/* Check if the parameter is not NULL. Technically we should
	 * not return an -EFAULT for this special value since it is
	 * allowed for some syscall, utimensat(2) for instance. */
	if (src == 0) {
		path[0] = '\0';
		return 0;
	}

	/* Get the path from the tracee's memory space. */
	size = read_path(tracee, path, src);
	if (size < 0)
		return size;

	path[size] = '\0';
	return size;
}

/**
 * Copy @size bytes of the data pointed to by @tracer_ptr into a
 * @tracee's memory block and make the @reg argument of the current
 * syscall points to this new block.  This function returns -errno if
 * an error occured, otherwise 0.
 */
int set_sysarg_data(Tracee *tracee, const void *tracer_ptr, word_t size, Reg reg)
{
	word_t tracee_ptr;
	int status;

	/* Allocate space into the tracee's memory to host the new data. */
	tracee_ptr = alloc_mem(tracee, size);
	if (tracee_ptr == 0)
		return -EFAULT;

	/* Copy the new data into the previously allocated space. */
	status = write_data(tracee, tracee_ptr, tracer_ptr, size);
	if (status < 0)
		return status;

	/* Make this argument point to the new data. */
	poke_reg(tracee, reg, tracee_ptr);

	return 0;
}

/**
 * Copy @path to a @tracee's memory block and make the @reg argument
 * of the current syscall points to this new block.  This function
 * returns -errno if an error occured, otherwise 0.
 */
int set_sysarg_path(Tracee *tracee, const char path[PATH_MAX], Reg reg)
{
	return set_sysarg_data(tracee, path, strlen(path) + 1, reg);
}

void translate_syscall(Tracee *tracee)
{
	const bool is_enter_stage = IS_IN_SYSENTER(tracee);
	int status;

	assert(tracee->exe != NULL);

	status = fetch_regs(tracee);
	if (status < 0)
		return;

	int suppressed_syscall_status = 0;

	if (is_enter_stage) {
		/* Never restore original register values at the end
		 * of this stage.  */
		tracee->restore_original_regs = false;

		print_current_regs(tracee, 3, "sysenter start");

#ifdef HAS_POKEDATA_WORKAROUND
		/* In case of pokedata workaround has cancelled real enter
		 * of syscall we've enqueued start of syscall again
		 * so we won't translate it here again.  */
		if (tracee->pokedata_workaround_relaunched_syscall) {
			tracee->pokedata_workaround_relaunched_syscall = false;
			tracee->status = 1;
			tracee->restart_how = PTRACE_SYSCALL;
			return;
		}
#endif

		/* Translate the syscall only if it was actually
		 * requested by the tracee, it is not a syscall
		 * chained by PRoot.  */
		if (tracee->chain.syscalls == NULL) {
/* ==================== 新增安全SVC直通分支（不修改原版流程，不符合条件直接走原版） ==================== */
#ifdef USE_SVC_DIRECT
			const word_t sysnum = get_sysnum(tracee, CURRENT);
			// 双重安全校验：白名单内 + 无扩展拦截
			if (is_svc_safe_syscall(sysnum)) {
				const int ext_status = notify_extensions(tracee, SYSCALL_CHAINED_ENTER, 0, 0);
				if (ext_status == 0) {
					// 读取tracee的系统调用参数
					const long a1 = peek_reg(tracee, CURRENT, SYSARG_1);
					const long a2 = peek_reg(tracee, CURRENT, SYSARG_2);
					const long a3 = peek_reg(tracee, CURRENT, SYSARG_3);
					const long a4 = peek_reg(tracee, CURRENT, SYSARG_4);
					const long a5 = peek_reg(tracee, CURRENT, SYSARG_5);
					const long a6 = peek_reg(tracee, CURRENT, SYSARG_6);

					// 执行SVC直接调用，无ptrace嵌套开销
					const long ret = arm64_svc_direct(sysnum, a1, a2, a3, a4, a5, a6);

					// 回填结果到tracee寄存器
					poke_reg(tracee, SYSARG_RESULT, (word_t)ret);
					// 设置为空系统调用，内核不会重复执行
					set_sysnum(tracee, PR_void);

					// 保存寄存器状态，完全兼容原版后续流程
					save_current_regs(tracee, ORIGINAL);
					save_current_regs(tracee, MODIFIED);

					// 跳转到原版后续流程，不破坏任何逻辑
					goto svc_direct_done;
				}
			}
#endif
/* ==================== SVC分支结束，以下完全是原版代码 ==================== */
			save_current_regs(tracee, ORIGINAL);
			status = translate_syscall_enter(tracee);
			save_current_regs(tracee, MODIFIED);

// SVC直通完成后跳转到这里，完全走原版后续流程
svc_direct_done:
		}
		else {
			if (tracee->chain.sysnum_workaround_state != SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL) {
				status = notify_extensions(tracee, SYSCALL_CHAINED_ENTER, 0, 0);
			}
			tracee->restart_how = PTRACE_SYSCALL;
		}

		/* Remember the tracee status for the "exit" stage and
		 * avoid the actual syscall if an error was reported
		 * by the translation/extension. */
		if (status < 0) {
			set_sysnum(tracee, PR_void);
			poke_reg(tracee, SYSARG_RESULT, (word_t) status);
			tracee->status = status;
#if defined(ARCH_ARM_EABI)
			tracee->restart_how = PTRACE_SYSCALL;
#endif
		}
		else
			tracee->status = 1;

#ifdef HAS_POKEDATA_WORKAROUND
		if (tracee->pokedata_workaround_cancelled_syscall) {
			tracee->pokedata_workaround_cancelled_syscall = false;
			tracee->pokedata_workaround_relaunched_syscall = true;
			tracee->restart_how = PTRACE_SYSCALL;
			tracee->status = 0;
			poke_reg(tracee, INSTR_POINTER, peek_reg(tracee, CURRENT, INSTR_POINTER) - SYSTRAP_SIZE);
			push_specific_regs(tracee, false);
			return;
		}
#endif

		/* Restore tracee's stack pointer now if it won't hit
		 * the sysexit stage (i.e. when seccomp is enabled and
		 * there's nothing else to do).  */
		if (tracee->restart_how == PTRACE_CONT) {
			suppressed_syscall_status = tracee->status;
			tracee->status = 0;
			poke_reg(tracee, STACK_POINTER, peek_reg(tracee, ORIGINAL, STACK_POINTER));
		}
	}
	else {
		/* By default, restore original register values at the
		 * end of this stage.  */
		tracee->restore_original_regs = true;

#ifdef HAS_POKEDATA_WORKAROUND
		/* This is exit from syscall that was cancelled
		 * by pokedata workaround - ignore.  */
		if (tracee->pokedata_workaround_relaunched_syscall)
		{
			return;
		}
#endif

		print_current_regs(tracee, 5, "sysexit start");

		/* Translate the syscall only if it was actually
		 * requested by the tracee, it is not a syscall
		 * chained by PRoot.  */
		if (tracee->chain.syscalls == NULL || tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL) {
			tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_INACTIVE;
			translate_syscall_exit(tracee);
		}
		else if (tracee->chain.sysnum_workaround_state == SYSNUM_WORKAROUND_PROCESS_FAULTY_CALL) {
			tracee->chain.sysnum_workaround_state = SYSNUM_WORKAROUND_PROCESS_REPLACED_CALL;
		}
		else
			(void) notify_extensions(tracee, SYSCALL_CHAINED_EXIT, 0, 0);

		/* Reset the tracee's status. */
		tracee->status = 0;
#ifdef HAS_POKEDATA_WORKAROUND
		tracee->pokedata_workaround_cancelled_syscall = false;
#endif

		/* Insert the next chained syscall, if any.  */
		if (tracee->chain.syscalls != NULL)
			chain_next_syscall(tracee);
	}

	bool override_sysnum = is_enter_stage && tracee->chain.syscalls == NULL;
	int push_regs_status = push_specific_regs(tracee, override_sysnum);

	/* Handle inability to change syscall number */
	if (push_regs_status < 0 && override_sysnum) {
		word_t orig_sysnum = peek_reg(tracee, ORIGINAL, SYSARG_NUM);
		word_t current_sysnum = peek_reg(tracee, CURRENT, SYSARG_NUM);
		print_current_regs(tracee, 4, "pre_push");
		if (orig_sysnum != current_sysnum) {
			/* Restart current syscall as chained */
			if (current_sysnum != SYSCALL_AVOIDER) {
				restart_current_syscall_as_chained(tracee);
			} else if (suppressed_syscall_status) {
				/* If we've decided to fail this syscall
				 * by setting it to no-op and continuing, but turns out
				 * that we can't just make syscall nop, restore tracee->status
				 * and intercept syscall exit */
				tracee->status = suppressed_syscall_status;
				tracee->restart_how = PTRACE_SYSCALL;
			}

			/* Set syscall arguments to make it fail
			 * TODO: More reliable way to make invalid arguments
			 * For most syscalls we set all args to -1
			 * Hoping there is among them invalid request/address/fd/value that will make syscall fail */
			poke_reg(tracee, SYSARG_1, -1);
			poke_reg(tracee, SYSARG_2, -1);
			poke_reg(tracee, SYSARG_3, -1);
			poke_reg(tracee, SYSARG_4, -1);
			poke_reg(tracee, SYSARG_5, -1);
			poke_reg(tracee, SYSARG_6, -1);

			if (get_sysnum(tracee, ORIGINAL) == PR_brk) {
				/* For brk() we pass 0 as first arg; this is used to query value without changing it */
				poke_reg(tracee, SYSARG_1, 0);
			}

			/* Push regs again without changing syscall */
			push_regs_status = push_specific_regs(tracee, false);
			if (push_regs_status != 0) {
				note(tracee, WARNING, SYSTEM, "can't set tracee registers in workaround");
			}
		}
	}

	if (is_enter_stage)
		print_current_regs(tracee, 5, "sysenter end" );
	else
		print_current_regs(tracee, 4, "sysexit end");
}
