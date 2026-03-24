#include <stdint.h>
#include <stdlib.h>
#include <linux/version.h>
#include <assert.h>
#include <sys/utsname.h>
#include <string.h>
#include <talloc.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <linux/auxvec.h>
#include <linux/futex.h>
#include <sys/param.h>

#include "extension/extension.h"
#include "syscall/seccomp.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "tracee/mem.h"
#include "execve/auxv.h"
#include "cli/note.h"
#include "arch.h"
#include "attribute.h"
#include "compat.h"

#define MAX_ARG_SHIFT 2

/* 系统调用修改规则结构体 */
typedef struct {
	int expected_release;
	word_t new_sysarg_num;
	struct {
		Reg sysarg;
		size_t nb_args;
		int offset;
	} shifts[MAX_ARG_SHIFT];
} Modif;

#define NONE {{0, 0, 0}}

/* 兼容性配置结构体 */
typedef struct {
	int actual_release;
	int virtual_release;
	struct utsname utsname;
	word_t hwcap;
} Config;

/**
 * 判断是否需要做内核兼容性适配
 * @param config 兼容性配置
 * @param expected_release 系统调用要求的最低内核版本
 * @return true-需要适配，false-无需适配
 */
static bool needs_kompat(const Config *config, int expected_release)
{
	if (config == NULL)
		return false;
	return (expected_release > config->actual_release
		&& expected_release <= config->virtual_release);
}

/**
 * 按规则修改当前系统调用，实现新旧接口降级
 * @param tracee 进程追踪句柄
 * @param config 兼容性配置
 * @param modif 系统调用修改规则
 * @return true-已修改，false-未修改
 */
static bool modify_syscall(Tracee *tracee, const Config *config, const Modif *modif)
{
	if (tracee == NULL || config == NULL || modif == NULL)
		return false;

	if (!needs_kompat(config, modif->expected_release))
		return false;

	/* 校验目标系统调用在当前架构是否支持 */
	word_t sysnum = detranslate_sysnum(get_abi(tracee), modif->new_sysarg_num);
	if (sysnum == SYSCALL_AVOIDER)
		return false;

	/* 替换系统调用号 */
	set_sysnum(tracee, modif->new_sysarg_num);

	/* 按规则调整系统调用参数位置 */
	for (size_t i = 0; i < MAX_ARG_SHIFT; i++) {
		Reg sysarg     = modif->shifts[i].sysarg;
		size_t nb_args = modif->shifts[i].nb_args;
		int offset     = modif->shifts[i].offset;

		for (size_t j = 0; j < nb_args; j++) {
			word_t arg = peek_reg(tracee, CURRENT, sysarg + j);
			poke_reg(tracee, sysarg + j + offset, arg);
		}
	}

	return true;
}

/**
 * 解析内核版本字符串，转换为KERNEL_VERSION格式的数值
 * @param release 内核版本字符串（如"2.6.32"）
 * @return 内核版本数值
 */
static int parse_kernel_release(const char *release)
{
	if (release == NULL)
		return 0;

	unsigned long major = 0, minor = 0, revision = 0;
	char *cursor = (char *)release;

	major = strtoul(cursor, &cursor, 10);
	if (*cursor == '.') {
		cursor++;
		minor = strtoul(cursor, &cursor, 10);
	}
	if (*cursor == '.') {
		cursor++;
		revision = strtoul(cursor, &cursor, 10);
	}

	return KERNEL_VERSION(major, minor, revision);
}

/**
 * 移除当前内核不支持的文件描述符标志位
 * @param tracee 进程追踪句柄
 * @param config 兼容性配置
 * @param discarded_flags 需要移除的标志位
 * @param expected_release 标志位要求的最低内核版本
 * @param sysarg 存储标志位的参数寄存器
 */
static void discard_fd_flags(Tracee *tracee, const Config *config,
			int discarded_flags, int expected_release, Reg sysarg)
{
	if (tracee == NULL || config == NULL)
		return;

	if (!needs_kompat(config, expected_release))
		return;

	word_t flags = peek_reg(tracee, CURRENT, sysarg);
	poke_reg(tracee, sysarg, flags & ~discarded_flags);
}

/**
 * 系统调用进入阶段处理：新系统调用降级为老内核兼容的调用
 * @param tracee 进程追踪句柄
 * @param config 兼容性配置
 * @return 0-成功，非0-错误码
 */
static int handle_sysenter_end(Tracee *tracee, Config *config)
{
	if (tracee == NULL || config == NULL)
		return 0;

	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_accept4: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,28),
			.new_sysarg_num   = PR_accept,
			.shifts		  = NONE
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_dup3: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,27),
			.new_sysarg_num   = PR_dup2,
			.shifts		  = NONE
		};
		/* dup3要求oldfd!=newfd，否则返回EINVAL */
		if (peek_reg(tracee, CURRENT, SYSARG_1) == peek_reg(tracee, CURRENT, SYSARG_2))
			return -EINVAL;
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_epoll_create1: {
		bool modified;
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,27),
			.new_sysarg_num   = PR_epoll_create,
			.shifts		  = NONE
		};
		modified = modify_syscall(tracee, config, &modif);
		if (modified)
			poke_reg(tracee, SYSARG_1, 1);
		return 0;
	}
	case PR_epoll_pwait: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,19),
			.new_sysarg_num   = PR_epoll_wait,
			.shifts		  = NONE
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_eventfd2: {
		bool modified;
		word_t flags;
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,27),
			.new_sysarg_num   = PR_eventfd,
			.shifts		  = NONE
		};
		modified = modify_syscall(tracee, config, &modif);
		if (modified) {
			flags = peek_reg(tracee, CURRENT, SYSARG_2);
			if ((flags & EFD_SEMAPHORE) != 0)
				return -EINVAL;
		}
		return 0;
	}
	case PR_faccessat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_access,
			.shifts	= { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 2,
					.offset  = -1 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_fchmodat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_chmod,
			.shifts	= { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 2,
					.offset  = -1 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_fchownat: {
		word_t flags;
		Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.shifts	= { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 3,
					.offset  = -1 }
			}
		};
		flags = peek_reg(tracee, CURRENT, SYSARG_5);
		modif.new_sysarg_num = ((flags & AT_SYMLINK_NOFOLLOW) != 0
					? PR_lchown
					: PR_chown);
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_fcntl: {
		word_t command;
		if (!needs_kompat(config, KERNEL_VERSION(2,6,24)))
			return 0;
		command = peek_reg(tracee, ORIGINAL, SYSARG_2);
		if (command == F_DUPFD_CLOEXEC)
			poke_reg(tracee, SYSARG_2, F_DUPFD);
		return 0;
	}
	case PR_newfstatat:
	case PR_fstatat64: {
		word_t flags;
		Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 2,
					.offset  = -1 }
			}
		};
		flags = peek_reg(tracee, CURRENT, SYSARG_4);
		if ((flags & ~(
						AT_SYMLINK_NOFOLLOW|
						AT_NO_AUTOMOUNT|
						AT_EMPTY_PATH|
						0x6000
					)) != 0)
			return -EINVAL;
#ifdef __ANDROID__
		modif.new_sysarg_num = ((flags & AT_SYMLINK_NOFOLLOW) != 0) ? PR_lstat64 : PR_stat64;
#else
		if ((flags & AT_SYMLINK_NOFOLLOW) != 0)
			modif.new_sysarg_num = (get_abi(tracee) != ABI_2 ? PR_lstat : PR_lstat64);
		else
			modif.new_sysarg_num = (get_abi(tracee) != ABI_2 ? PR_stat : PR_stat64);
#endif
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_futex: {
		word_t operation;
		static bool warned = false;
		if (!needs_kompat(config, KERNEL_VERSION(2,6,22)) || config->actual_release == 0)
			return 0;
		operation = peek_reg(tracee, CURRENT, SYSARG_2);
		if ((operation & FUTEX_PRIVATE_FLAG) == 0)
			return 0;
		if (!warned) {
			warned = true;
			note(tracee, WARNING, USER,
				"kompat: this kernel doesn't support private futexes "
				"and proot-scicat can't emulate them. Expect some troubles...");
		}
		poke_reg(tracee, SYSARG_2, operation & ~FUTEX_PRIVATE_FLAG);
		return 0;
	}
	case PR_futimesat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_utimes,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 2,
					.offset  = -1 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_inotify_init1: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,27),
			.new_sysarg_num   = PR_inotify_init,
			.shifts		  = NONE
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_linkat: {
		word_t flags;
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_link,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 1,
					.offset  = -1 },
				    [1] = {
					.sysarg  = SYSARG_4,
					.nb_args = 1,
					.offset  = -2 }
			}
		};
		flags = peek_reg(tracee, CURRENT, SYSARG_5);
		if ((flags & ~AT_SYMLINK_FOLLOW) != 0)
			return -EINVAL;
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_mkdirat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_mkdir,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 2,
					.offset  = -1 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_mknodat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_mknod,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 3,
					.offset  = -1 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_openat: {
		bool modified;
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_open,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 3,
					.offset  = -1 }
			}
		};
		modified = modify_syscall(tracee, config, &modif);
		discard_fd_flags(tracee, config, O_CLOEXEC, KERNEL_VERSION(2,6,23),
				modified ? SYSARG_2 : SYSARG_3);
		return 0;
	}
	case PR_open:
		discard_fd_flags(tracee, config, O_CLOEXEC, KERNEL_VERSION(2,6,23), SYSARG_2);
		return 0;
	case PR_pipe2: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,27),
			.new_sysarg_num   = PR_pipe,
			.shifts		  = NONE
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_pselect6: {
		Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.shifts		  = NONE
		};
#ifdef __ANDROID__
		modif.new_sysarg_num = PR__newselect;
#else
		modif.new_sysarg_num = (get_abi(tracee) != ABI_2 ? PR_select : PR__newselect);
#endif
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_readlinkat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_readlink,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 3,
					.offset  = -1}
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_renameat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_rename,
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 1,
					.offset  =-1 },
				    [1] = {
					    .sysarg  = SYSARG_4,
					    .nb_args = 1,
					    .offset  = -2 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_signalfd4: {
		bool modified;
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,27),
			.new_sysarg_num   = PR_signalfd,
			.shifts		  = NONE
		};
		modified = modify_syscall(tracee, config, &modif);
		if (modified)
			poke_reg(tracee, SYSARG_4, 0);
		return 0;
	}
	case PR_socket:
	case PR_socketpair:
	case PR_timerfd_create:
		discard_fd_flags(tracee, config, O_CLOEXEC | O_NONBLOCK,
				KERNEL_VERSION(2,6,27), SYSARG_2);
		return 0;
	case PR_symlinkat: {
		const Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.new_sysarg_num   = PR_symlink,
			.shifts = { [0] = {
					.sysarg  = SYSARG_3,
					.nb_args = 1,
					.offset  = -1 }
			}
		};
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	case PR_unlinkat: {
		word_t flags;
		Modif modif = {
			.expected_release = KERNEL_VERSION(2,6,16),
			.shifts = { [0] = {
					.sysarg  = SYSARG_2,
					.nb_args = 1,
					.offset  = -1
				}
			}
		};
		flags = peek_reg(tracee, CURRENT, SYSARG_3);
		modif.new_sysarg_num = ((flags & AT_REMOVEDIR) != 0
					? PR_rmdir
					: PR_unlink);
		modify_syscall(tracee, config, &modif);
		return 0;
	}
	default:
		return 0;
	}
}

/**
 * 调整ELF辅助向量，提升兼容性，屏蔽内核敏感信息
 * @param tracee 进程追踪句柄
 * @param config 兼容性配置
 */
static void adjust_elf_auxv(Tracee *tracee, Config *config)
{
	if (tracee == NULL || config == NULL)
		return;

	ElfAuxVector *vectors = NULL;
	ElfAuxVector *vector = NULL;
	word_t vectors_address = get_elf_aux_vectors_address(tracee);

	if (vectors_address == 0)
		return;

	vectors = fetch_elf_aux_vectors(tracee, vectors_address);
	if (vectors == NULL)
		return;

	/* 遍历并调整辅助向量 */
	for (vector = vectors; vector->type != AT_NULL; vector++) {
		switch (vector->type) {
		/* 移除AT_SYSINFO相关向量，避免程序直接读取内核信息绕过uname钩子 */
		case AT_SYSINFO_EHDR:
		case AT_SYSINFO:
			vector->type  = AT_IGNORE;
			vector->value = 0;
			break;
		/* 覆盖硬件能力位 */
		case AT_HWCAP:
			if (config->hwcap != (word_t) -1)
				vector->value = config->hwcap;
			break;
		case AT_RANDOM:
			/* 非强制模式下不处理 */
			if (config->actual_release != 0)
				goto end;
			break;
		default:
			break;
		}
	}

	/* 老内核需要补充AT_RANDOM向量 */
	if (!needs_kompat(config, KERNEL_VERSION(2,6,29)))
		goto end;

	int status = add_elf_aux_vector(&vectors, AT_RANDOM, vectors_address);
	if (status < 0)
		goto end;

	/* 新增向量需要调整栈布局，为新向量腾出空间 */
	word_t stack_pointer = peek_reg(tracee, CURRENT, STACK_POINTER);
	size_t size = vectors_address - stack_pointer;
	void *argv_envp = talloc_size(tracee->ctx, size);

	if (argv_envp == NULL)
		goto end;

	status = read_data(tracee, argv_envp, stack_pointer, size);
	if (status < 0)
		goto end;

	/* 栈向下增长，预留新向量空间 */
	stack_pointer   -= 2 * sizeof_word(tracee);
	vectors_address -= 2 * sizeof_word(tracee);

	/* 更新栈指针，先更新再写数据，避免页错误 */
	poke_reg(tracee, STACK_POINTER, stack_pointer);
	write_data(tracee, stack_pointer, argv_envp, size);

end:
	push_elf_aux_vectors(tracee, vectors, vectors_address);
}

/**
 * 链式调用fcntl，模拟老内核不支持的文件描述符标志
 * @param tracee 进程追踪句柄
 * @param fd 目标文件描述符
 * @param sysarg 存储原始标志位的参数寄存器
 * @param emulated_flags 需要模拟的标志位
 */
static void emulate_fd_flags(Tracee *tracee, word_t fd, Reg sysarg, int emulated_flags)
{
	if (tracee == NULL || fd < 0)
		return;

	word_t flags = peek_reg(tracee, ORIGINAL, sysarg);
	if (flags == 0)
		return;

	/* 模拟O_CLOEXEC标志 */
	if ((emulated_flags & flags & O_CLOEXEC) != 0)
		register_chained_syscall(tracee, PR_fcntl, fd, F_SETFD, FD_CLOEXEC, 0, 0, 0);

	/* 模拟O_NONBLOCK标志 */
	if ((emulated_flags & flags & O_NONBLOCK) != 0)
		register_chained_syscall(tracee, PR_fcntl, fd, F_SETFL, O_NONBLOCK, 0, 0, 0);

	/* 强制链式调用最终结果为原系统调用的返回值 */
	force_chain_final_result(tracee, peek_reg(tracee, CURRENT, SYSARG_RESULT));
}

/**
 * 系统调用退出阶段处理：修正返回值、模拟标志位、覆盖uname结果
 * @param tracee 进程追踪句柄
 * @param config 兼容性配置
 * @return 0-成功，非0-错误码
 */
static int handle_sysexit_end(Tracee *tracee, Config *config)
{
	if (tracee == NULL || config == NULL)
		return 0;

	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	word_t sysnum = get_sysnum(tracee, ORIGINAL);
	int status = (int)result;

	/* 内核返回错误，不做处理 */
	if (status < 0)
		return 0;

	switch (sysnum) {
	case PR_uname: {
		word_t address = peek_reg(tracee, ORIGINAL, SYSARG_1);
		/* 覆盖uname返回的内核信息，实现版本伪装 */
		status = write_data(tracee, address, &config->utsname, sizeof(config->utsname));
		if (status < 0)
			return status;
		return 0;
	}
	case PR_setdomainname:
	case PR_sethostname: {
		word_t address = peek_reg(tracee, ORIGINAL, SYSARG_1);
		word_t length = peek_reg(tracee, ORIGINAL, SYSARG_2);
		char *name = (sysnum == PR_setdomainname)
			? config->utsname.domainname
			: config->utsname.nodename;

		if (length > sizeof(config->utsname.domainname) - 1)
			return -EINVAL;

		status = read_data(tracee, name, address, length);
		if (status < 0)
			return status;
		name[length] = '\0';
		return 0;
	}
	case PR_accept4:
		if (get_sysnum(tracee, MODIFIED) == PR_accept)
			emulate_fd_flags(tracee, result, SYSARG_4, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_dup3:
		if (get_sysnum(tracee, MODIFIED) == PR_dup2)
			emulate_fd_flags(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2),
					SYSARG_3, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_epoll_create1:
		if (get_sysnum(tracee, MODIFIED) == PR_epoll_create)
			emulate_fd_flags(tracee, result, SYSARG_1, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_eventfd2:
		if (get_sysnum(tracee, MODIFIED) == PR_eventfd)
			emulate_fd_flags(tracee, result, SYSARG_2, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_fcntl: {
		word_t command;
		if (!needs_kompat(config, KERNEL_VERSION(2,6,24)))
			return 0;
		command = peek_reg(tracee, ORIGINAL, SYSARG_2);
		if (command != F_DUPFD_CLOEXEC)
			return 0;
		/* 模拟F_DUPFD_CLOEXEC的CLOEXEC标志 */
		register_chained_syscall(tracee, PR_fcntl, result, F_SETFD, FD_CLOEXEC, 0, 0, 0);
		force_chain_final_result(tracee, peek_reg(tracee, CURRENT, SYSARG_RESULT));
		return 0;
	}
	case PR_inotify_init1:
		if (get_sysnum(tracee, MODIFIED) == PR_inotify_init)
			emulate_fd_flags(tracee, result, SYSARG_1, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_open:
		if (needs_kompat(config, KERNEL_VERSION(2,6,23)))
			emulate_fd_flags(tracee, result, SYSARG_2, O_CLOEXEC);
		return 0;
	case PR_openat:
		if (needs_kompat(config, KERNEL_VERSION(2,6,23)))
			emulate_fd_flags(tracee, result, SYSARG_3, O_CLOEXEC);
		return 0;
	case PR_pipe2: {
		int fds[2];
		if (get_sysnum(tracee, MODIFIED) != PR_pipe)
			return 0;
		status = read_data(tracee, fds, peek_reg(tracee, MODIFIED, SYSARG_1), sizeof(fds));
		if (status < 0)
			return 0;
		emulate_fd_flags(tracee, fds[0], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
		emulate_fd_flags(tracee, fds[1], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
		return 0;
	}
	case PR_signalfd4:
		if (get_sysnum(tracee, MODIFIED) == PR_signalfd)
			emulate_fd_flags(tracee, result, SYSARG_4, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_socket:
	case PR_timerfd_create:
		if (needs_kompat(config, KERNEL_VERSION(2,6,27)))
			emulate_fd_flags(tracee, result, SYSARG_2, O_CLOEXEC | O_NONBLOCK);
		return 0;
	case PR_socketpair: {
		int fds[2];
		if (!needs_kompat(config, KERNEL_VERSION(2,6,27)))
			return 0;
		status = read_data(tracee, fds, peek_reg(tracee, MODIFIED, SYSARG_4), sizeof(fds));
		if (status < 0)
			return 0;
		emulate_fd_flags(tracee, fds[0], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
		emulate_fd_flags(tracee, fds[1], SYSARG_2, O_CLOEXEC | O_NONBLOCK);
		return 0;
	}
	default:
		return 0;
	}
}

/**
 * 解析utsname配置，初始化内核版本伪装信息
 * @param config 兼容性配置
 * @param string 用户传入的版本/utsname配置字符串
 * @return 0-成功，-1-解析失败
 */
static int parse_utsname(Config *config, const char *string)
{
	if (config == NULL || string == NULL)
		return -1;

	struct utsname utsname;
	int status = uname(&utsname);

	/* 强制适配模式 */
	if (status < 0 || getenv("PROOT_FORCE_KOMPAT") != NULL)
		config->actual_release = 0;
	else
		config->actual_release = parse_kernel_release(utsname.release);

	/* 处理复杂格式的完整utsname配置（\sysname\nodename\release\version\machine\domainname\hwcap\） */
	if (string[0] == '\\') {
		const char *start;
		const char *end;
		char *end2;

		end = string;
#define PARSE(field) do {						\
			size_t length;					\
			start = end + 1;				\
			end   = strchr(start, '\\');			\
			if (end == NULL) {				\
				note(NULL, ERROR, USER,			\
					"can't find %s field in utsname config", #field);	\
				return -1;				\
			}						\
			length = end - start;				\
			length = MIN(length, sizeof(config->utsname.field) - 1); \
			strncpy(config->utsname.field, start, length);	\
			config->utsname.field[length] = '\0';		\
		} while(0)

		PARSE(sysname);
		PARSE(nodename);
		PARSE(release);
		PARSE(version);
		PARSE(machine);
		PARSE(domainname);
#undef PARSE

		/* 解析hwcap字段（十六进制） */
		errno = 0;
		config->hwcap = strtol(end + 1, &end2, 16);
		if (errno != 0 || end2[0] != '\\') {
			note(NULL, ERROR, USER, "can't parse hwcap field in utsname config");
			return -1;
		}
	}
	/* 简单格式：仅内核版本号 */
	else {
		memcpy(&config->utsname, &utsname, sizeof(config->utsname));
		size_t length = MIN(strlen(string), sizeof(config->utsname.release) - 1);
		strncpy(config->utsname.release, string, length);
		config->utsname.release[length] = '\0';
		config->hwcap = (word_t) -1;
	}

	config->virtual_release = parse_kernel_release(config->utsname.release);
	return 0;
}

/* 注册需要处理的系统调用列表 */
static FilteredSysnum filtered_sysnums[] = {
	{ PR_accept4,		FILTER_SYSEXIT },
	{ PR_dup3,		FILTER_SYSEXIT },
	{ PR_epoll_create1,	FILTER_SYSEXIT },
	{ PR_epoll_pwait, 	0 },
	{ PR_eventfd2, 		FILTER_SYSEXIT },
	{ PR_execve, 		FILTER_SYSEXIT },
	{ PR_faccessat, 	0 },
	{ PR_fchmodat, 		0 },
	{ PR_fchownat, 		0 },
	{ PR_fcntl, 		FILTER_SYSEXIT },
	{ PR_fstatat64, 	0 },
	{ PR_futimesat, 	0 },
	{ PR_futex, 		0 },
	{ PR_inotify_init1, 	FILTER_SYSEXIT },
	{ PR_linkat, 		0 },
	{ PR_mkdirat, 		0 },
	{ PR_mknodat, 		0 },
	{ PR_newfstatat, 	0 },
	{ PR_open, 		FILTER_SYSEXIT },
	{ PR_openat, 		FILTER_SYSEXIT },
	{ PR_pipe2, 		FILTER_SYSEXIT },
	{ PR_pselect6, 		0 },
	{ PR_readlinkat, 	0 },
	{ PR_renameat, 		0 },
	{ PR_setdomainname,	FILTER_SYSEXIT },
	{ PR_sethostname,	FILTER_SYSEXIT },
	{ PR_signalfd4, 	FILTER_SYSEXIT },
	{ PR_socket,		FILTER_SYSEXIT },
	{ PR_socketpair,	FILTER_SYSEXIT },
	{ PR_symlinkat, 	0 },
	{ PR_timerfd_create,	FILTER_SYSEXIT },
	{ PR_uname, 		FILTER_SYSEXIT },
	{ PR_unlinkat, 		0 },
	FILTERED_SYSNUM_END,
};

/**
 * kompat扩展核心回调函数，处理各类生命周期与系统调用事件
 * @param extension 扩展句柄
 * @param event 触发的事件类型
 * @param data1 事件附加数据1
 * @param data2 事件附加数据2
 * @return 0-成功，非0-错误码
 */
int kompat_callback(Extension *extension, ExtensionEvent event,
		intptr_t data1, intptr_t data2 UNUSED)
{
	if (extension == NULL)
		return -EINVAL;

	int status;
	switch (event) {
	case INITIALIZATION: {
		Config *config;
		extension->config = talloc_zero(extension, Config);
		if (extension->config == NULL)
			return -1;

		config = extension->config;
		status = parse_utsname(config, (const char *) data1);
		if (status < 0)
			return -1;

		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		/* 前置步骤已报错，不做处理 */
		if ((int) data1 < 0)
			return 0;
		return handle_sysenter_end(tracee, config);
	}

	case SYSCALL_EXIT_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		return handle_sysexit_end(tracee, config);
	}

	case SYSCALL_EXIT_START: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		word_t sysnum = get_sysnum(tracee, ORIGINAL);

		/* execve成功后，调整ELF辅助向量，必须在loader写入栈之前执行 */
		if ((int) result >= 0 && sysnum == PR_execve)
			adjust_elf_auxv(tracee, config);
		return 0;
	}

	default:
		return 0;
	}
}
