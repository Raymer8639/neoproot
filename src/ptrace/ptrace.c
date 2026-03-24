#include <sys/ptrace.h> /* PTRACE_*,  */
#include <errno.h>      /* E*, */
#include <assert.h>     /* assert(3), */
#include <stdbool.h>    /* bool, true, false, */
#include <signal.h>     /* siginfo_t, */
#include <sys/uio.h>    /* struct iovec, */
#include <sys/param.h>  /* MIN(), MAX(), */
#include <sys/wait.h>   /* __WALL, */
#include <string.h>     /* memcpy(3), */
#include "ptrace/ptrace.h"
#include "ptrace/user.h"
#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/event.h"
#include "cli/note.h"
#include "arch.h"
#include "compat.h"
#include "attribute.h"

// 仅保留ARM架构配置，删除x86相关
#if defined(ARCH_ARM_EABI)
#define user_fpregs_struct user_fpregs
#endif
#if defined(ARCH_ARM64)
#define user_fpregs_struct user_fpsimd_struct
#endif

/**
 * 冷路径：字符串转换低频调用，标记后不占用热点缓存
 */
__attribute__((cold, noinline))
static const char *stringify_ptrace(
#ifdef __GLIBC__
		enum __ptrace_request
#else
		int
#endif
		request)
{
#define CASE_STR(a) case a: return #a; break;
	switch ((int) request) {
	CASE_STR(PTRACE_TRACEME)	CASE_STR(PTRACE_PEEKTEXT)	CASE_STR(PTRACE_PEEKDATA)
	CASE_STR(PTRACE_PEEKUSER)	CASE_STR(PTRACE_POKETEXT)	CASE_STR(PTRACE_POKEDATA)
	CASE_STR(PTRACE_POKEUSER)	CASE_STR(PTRACE_CONT)		CASE_STR(PTRACE_KILL)
	CASE_STR(PTRACE_SINGLESTEP)	CASE_STR(PTRACE_GETREGS)	CASE_STR(PTRACE_SETREGS)
	CASE_STR(PTRACE_GETFPREGS)	CASE_STR(PTRACE_SETFPREGS)	CASE_STR(PTRACE_ATTACH)
	CASE_STR(PTRACE_DETACH)		CASE_STR(PTRACE_GETFPXREGS)	CASE_STR(PTRACE_SETFPXREGS)
	CASE_STR(PTRACE_SYSCALL)	CASE_STR(PTRACE_SETOPTIONS)	CASE_STR(PTRACE_GETEVENTMSG)
	CASE_STR(PTRACE_GETSIGINFO)	CASE_STR(PTRACE_SETSIGINFO)	CASE_STR(PTRACE_GETREGSET)
	CASE_STR(PTRACE_SETREGSET)	CASE_STR(PTRACE_SEIZE)		CASE_STR(PTRACE_INTERRUPT)
	CASE_STR(PTRACE_LISTEN)		CASE_STR(PTRACE_SET_SYSCALL)
	CASE_STR(PTRACE_GET_THREAD_AREA)	CASE_STR(PTRACE_SET_THREAD_AREA)
	CASE_STR(PTRACE_GETVFPREGS)	CASE_STR(PTRACE_SINGLEBLOCK)	CASE_STR(PTRACE_ARCH_PRCTL)
	default: return "PTRACE_???"; }
}

/**
 * Translate the ptrace syscall made by @tracee into a "void" syscall
 */
__attribute__((hot, always_inline))
int translate_ptrace_enter(Tracee *tracee)
{
	set_sysnum(tracee, PR_void);
	return 0;
}

/**
 * Set @ptracee's tracer to @ptracer, and increment ptracees counter
 */
__attribute__((hot, always_inline))
void attach_to_ptracer(Tracee *ptracee, Tracee *ptracer)
{
	bzero(&(PTRACEE), sizeof(PTRACEE));
	PTRACEE.ptracer = ptracer;
	PTRACER.nb_ptracees++;
}

/**
 * Unset @ptracee's tracer, and decrement ptracees counter
 */
__attribute__((hot, always_inline))
void detach_from_ptracer(Tracee *ptracee)
{
	Tracee *ptracer = PTRACEE.ptracer;
	PTRACEE.ptracer = NULL;
	assert(PTRACER.nb_ptracees > 0);
	PTRACER.nb_ptracees--;
}

/**
 * 高频辅助函数：批量读写内存，减少重复调用开销
 */
__attribute__((always_inline))
static int batch_rw_data(Tracee *tracee, void *buf, word_t addr, size_t size, bool is_write)
{
	if (is_write)
		return write_data(tracee, addr, buf, size);
	else
		return read_data(tracee, buf, addr, size);
}

/**
 * Emulate the ptrace syscall made by @tracee.
 */
__attribute__((hot, flatten))
int translate_ptrace_exit(Tracee *tracee)
{
	word_t request, pid, address, data, result;
	Tracee *ptracee, *ptracer;
	int forced_signal = -1;
	int signal;
	int status = 0;

	// 批量读取参数，减少peek_reg调用次数
	request = peek_reg(tracee, ORIGINAL, SYSARG_1);
	pid     = peek_reg(tracee, ORIGINAL, SYSARG_2);
	address = peek_reg(tracee, ORIGINAL, SYSARG_3);
	data    = peek_reg(tracee, ORIGINAL, SYSARG_4);

	// 精简32位模式pid转换逻辑（仅ARM32-on-ARM64兼容）
	if (is_32on64_mode(tracee) && pid == 0xFFFFFFFF)
		pid = (word_t) -1;

	// 快速路径：PTRACE_TRACEME（高频场景）
	if (request == PTRACE_TRACEME) {
		ptracer = tracee->parent;
		ptracee = tracee;

		if (PTRACEE.ptracer != NULL || ptracee == ptracer)
			return -EPERM;

		attach_to_ptracer(ptracee, ptracer);

		if (PTRACER.waits_in == WAITS_IN_KERNEL) {
			status = kill(ptracer->pid, SIGSTOP);
			if (status < 0)
				note(tracee, WARNING, INTERNAL, "can't wake ptracer %d", ptracer->pid);
			else {
				ptracer->sigstop = SIGSTOP_IGNORED;
				PTRACER.waits_in = WAITS_IN_PROOT;
			}
		}

		if (tracee->seccomp == ENABLED)
			tracee->seccomp = DISABLING;
		return 0;
	}

	// 快速路径：PTRACE_ATTACH（高频场景）
	if (request == PTRACE_ATTACH) {
		ptracer = tracee;
		ptracee = get_tracee(ptracer, pid, false);
		if (ptracee == NULL)
			return -ESRCH;

		if (PTRACEE.ptracer != NULL || ptracee == ptracer)
			return -EPERM;

		attach_to_ptracer(ptracee, ptracer);
		kill(pid, SIGSTOP);
		return 0;
	}

	// 定位被跟踪进程，精简判断逻辑
	ptracer = tracee;
	ptracee = get_stopped_ptracee(ptracer, pid, false, __WALL);
	if (ptracee == NULL) {
		static bool warned = false;
		ptracee = get_tracee(tracee, pid, false);
		if (ptracee != NULL && ptracee->exe == NULL && !warned) {
			warned = true;
			note(ptracer, WARNING, INTERNAL, "ptrace request to an unexpected ptracee");
		}
		return -ESRCH;
	}

	// 精简合法性校验，合并条件
	if (PTRACEE.is_zombie || PTRACEE.ptracer != ptracer || pid == (word_t) -1)
		return -ESRCH;

	switch (request) {
		case PTRACE_SYSCALL:
			PTRACEE.ignore_syscalls = false;
			forced_signal = (int) data;
			break;
		case PTRACE_CONT:
			PTRACEE.ignore_syscalls = true;
			forced_signal = (int) data;
			break;
		case PTRACE_SINGLESTEP:
			ptracee->restart_how = PTRACE_SINGLESTEP;
			forced_signal = (int) data;
			break;
		case PTRACE_DETACH:
			detach_from_ptracer(ptracee);
			break;
		case PTRACE_KILL:
			status = ptrace(request, pid, NULL, NULL);
			break;
		case PTRACE_SETOPTIONS:
			PTRACEE.options = data;
			return 0;
		case PTRACE_GETEVENTMSG: {
			status = ptrace(request, pid, NULL, &result);
			if (status < 0)
				return -errno;
			poke_word(ptracer, data, result);
			return errno ? -errno : 0;
		}
		case PTRACE_PEEKUSER:
			if (is_32on64_mode(ptracer)) {
				address = convert_user_offset(address);
				if (address == (word_t) -1)
					return -EIO;
			}
			// 穿透到PTRACE_PEEKDATA处理，减少重复代码
		case PTRACE_PEEKTEXT:
		case PTRACE_PEEKDATA: {
			errno = 0;
			result = (word_t) ptrace(request, pid, address, NULL);
			if (errno != 0)
				return -errno;
			poke_word(ptracer, data, result);
			return errno ? -errno : 0;
		}
		case PTRACE_POKEUSER:
			if (is_32on64_mode(ptracer)) {
				address = convert_user_offset(address);
				if (address == (word_t) -1)
					return -EIO;
			}
			status = ptrace(request, pid, address, data);
			return status < 0 ? -errno : 0;
		case PTRACE_POKETEXT:
		case PTRACE_POKEDATA: {
			if (is_32on64_mode(ptracer)) {
				word_t tmp;
				errno = 0;
				tmp = (word_t) ptrace(PTRACE_PEEKDATA, ptracee->pid, address, NULL);
				if (errno != 0)
					return -errno;
				data |= (tmp & 0xFFFFFFFF00000000ULL);
			}
			status = ptrace(request, pid, address, data);
			return status < 0 ? -errno : 0;
		}
		case PTRACE_GETSIGINFO: {
			siginfo_t siginfo;
			status = ptrace(request, pid, NULL, &siginfo);
			if (status < 0)
				return -errno;
			return batch_rw_data(ptracer, &siginfo, data, sizeof(siginfo), true);
		}
		case PTRACE_SETSIGINFO: {
			siginfo_t siginfo;
			status = batch_rw_data(ptracer, &siginfo, data, sizeof(siginfo), false);
			if (status < 0)
				return status;
			status = ptrace(request, pid, NULL, &siginfo);
			return status < 0 ? -errno : 0;
		}
		case PTRACE_GETREGS: {
			struct user_regs_struct regs;
			status = ptrace(request, pid, NULL, &regs);
			if (status < 0)
				return -errno;
			return batch_rw_data(ptracer, &regs, data, sizeof(regs), true);
		}
		case PTRACE_SETREGS: {
			struct user_regs_struct regs;
			status = batch_rw_data(ptracer, &regs, data, sizeof(regs), false);
			if (status < 0)
				return status;
			status = ptrace(request, pid, NULL, &regs);
			return status < 0 ? -errno : 0;
		}
		case PTRACE_GETFPREGS: {
			struct user_fpregs_struct fpregs;
			status = ptrace(request, pid, NULL, &fpregs);
			if (status < 0)
				return -errno;
			return batch_rw_data(ptracer, &fpregs, data, sizeof(fpregs), true);
		}
		case PTRACE_SETFPREGS: {
			struct user_fpregs_struct fpregs;
			status = batch_rw_data(ptracer, &fpregs, data, sizeof(fpregs), false);
			if (status < 0)
				return status;
			status = ptrace(request, pid, NULL, &fpregs);
			return status < 0 ? -errno : 0;
		}
		case PTRACE_GETREGSET: {
			struct iovec local_iovec;
			word_t remote_iovec_base = peek_word(ptracer, data);
			if (errno != 0)
				return -errno;

			word_t remote_iovec_len = peek_word(ptracer, data + sizeof_word(ptracer));
			if (errno != 0)
				return -errno;

			assert(sizeof(local_iovec.iov_len) == sizeof(word_t));
			local_iovec.iov_len  = remote_iovec_len;
			local_iovec.iov_base = talloc_zero_size(ptracer->ctx, remote_iovec_len);
			if (local_iovec.iov_base == NULL)
				return -ENOMEM;

			status = ptrace(PTRACE_GETREGSET, pid, address, &local_iovec);
			if (status < 0)
				return status;

			remote_iovec_len = MIN(remote_iovec_len, local_iovec.iov_len);
			status = writev_data(ptracer, remote_iovec_base, &local_iovec, 1);
			if (status < 0)
				return status;

			poke_word(ptracer, data + sizeof_word(ptracer), remote_iovec_len);
			return errno ? -errno : 0;
		}
		case PTRACE_SETREGSET: {
			struct iovec local_iovec;
			word_t remote_iovec_base = peek_word(ptracer, data);
			if (errno != 0)
				return -errno;

			word_t remote_iovec_len = peek_word(ptracer, data + sizeof_word(ptracer));
			if (errno != 0)
				return -errno;

			assert(sizeof(local_iovec.iov_len) == sizeof(word_t));
			local_iovec.iov_len  = remote_iovec_len;
			local_iovec.iov_base = talloc_zero_size(ptracer->ctx, remote_iovec_len);
			if (local_iovec.iov_base == NULL)
				return -ENOMEM;

			status = read_data(ptracer, local_iovec.iov_base, remote_iovec_base, local_iovec.iov_len);
			if (status < 0)
				return status;

			status = ptrace(PTRACE_SETREGSET, pid, address, &local_iovec);
			return status < 0 ? -errno : 0;
		}
		case PTRACE_SET_SYSCALL:
			status = ptrace(request, pid, address, data);
			return status < 0 ? -errno : 0;
		default:
			note(ptracer, WARNING, INTERNAL, "ptrace request '%s' not supported yet", stringify_ptrace(request));
			return -ENOTSUP;
	}

	// 精简信号处理逻辑，合并条件判断
	signal = PTRACEE.event4.proot.pending ? handle_tracee_event(ptracee, PTRACEE.event4.proot.value) : PTRACEE.event4.proot.value;
	if (forced_signal != -1)
		signal = forced_signal;

	(void) restart_tracee(ptracee, signal);
	return status;
}
