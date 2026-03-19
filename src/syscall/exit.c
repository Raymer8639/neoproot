/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2026 scicat
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <sys/utsname.h>
#include <linux/net.h>
#include <linux/ioctl.h>
#include <string.h>

#include "cli/note.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/socket.h"
#include "syscall/chain.h"
#include "syscall/heap.h"
#include "syscall/rlimit.h"
#include "execve/execve.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "tracee/seccomp.h"
#include "tracee/statx.h"
#include "path/path.h"
#include "ptrace/ptrace.h"
#include "ptrace/wait.h"
#include "extension/extension.h"
#include "arch.h"

void translate_syscall_exit(Tracee *tracee)
{
	word_t sysnum, result;
	int status = 0;

	status = notify_extensions(tracee, SYSCALL_EXIT_START, 0, 0);
	if (status < 0) {
		poke_reg(tracee, SYSARG_RESULT, (word_t)status);
		goto exit_end;
	}
	if (status > 0)
		return;

	if (tracee->status < 0) {
		poke_reg(tracee, SYSARG_RESULT, (word_t)tracee->status);
		goto exit_end;
	}

	sysnum = get_sysnum(tracee, ORIGINAL);
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);

	if (peek_reg(tracee, MODIFIED, SYSARG_NUM) ==
#if defined(ARCH_ARM64)
		(is_32on64_mode(tracee) ? (SYSCALL_AVOIDER & 0xFFFFFFFF) : SYSCALL_AVOIDER)
#else
		SYSCALL_AVOIDER
#endif
		&& sysnum != peek_reg(tracee, MODIFIED, SYSARG_NUM))
	{
		poke_reg(tracee, SYSARG_RESULT, peek_reg(tracee, MODIFIED, SYSARG_RESULT));
	}

	switch (sysnum) {
	case PR_brk:
		translate_brk_exit(tracee);
		break;

	case PR_getcwd: {
		char path[PATH_MAX];
		size_t size, new_len;
		word_t out_addr;

		size = (size_t)peek_reg(tracee, ORIGINAL, SYSARG_2);
		if (size == 0) {
			status = -EINVAL;
			break;
		}

		status = translate_path(tracee, path, AT_FDCWD, ".", false);
		if (status < 0)
			break;

		new_len = strlen(tracee->fs->cwd) + 1;
		if (size < new_len) {
			status = -ERANGE;
			break;
		}

		out_addr = peek_reg(tracee, ORIGINAL, SYSARG_1);
		status = write_data(tracee, out_addr, tracee->fs->cwd, new_len);
		if (status < 0)
			break;

		status = (int)new_len;
		break;
	}

	case PR_accept:
	case PR_accept4:
		if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0)
			break;
	case PR_getsockname:
	case PR_getpeername: {
		word_t sockaddr, addrlen, maxlen;

		if ((int)result < 0)
			break;

		sockaddr = peek_reg(tracee, ORIGINAL, SYSARG_2);
		addrlen  = peek_reg(tracee, MODIFIED, SYSARG_3);
		maxlen   = peek_reg(tracee, MODIFIED, SYSARG_6);

		status = translate_socketcall_exit(tracee, sockaddr, addrlen, maxlen);
		break;
	}

	case PR_socketcall: {
		word_t args_addr, call, sockaddr, addrlen;
		int sub_status = 0;

		args_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
		call      = peek_reg(tracee, ORIGINAL, SYSARG_1);

		switch (call) {
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME:
			if ((int)result >= 0)
				sub_status = 1;
			break;
		case SYS_BIND:
		case SYS_CONNECT: {
			word_t a2 = peek_reg(tracee, MODIFIED, SYSARG_5);
			word_t a3 = peek_reg(tracee, MODIFIED, SYSARG_6);
			poke_word(tracee, args_addr + 1*sizeof_word(tracee), a2);
			poke_word(tracee, args_addr + 2*sizeof_word(tracee), a3);
			if (errno != 0)
				sub_status = -errno;
			break;
		}
		default:
			break;
		}

		if (sub_status != 1) {
			status = sub_status;
			break;
		}

		sockaddr = peek_word(tracee, args_addr + 1*sizeof_word(tracee));
		addrlen  = peek_word(tracee, args_addr + 2*sizeof_word(tracee));
		if (errno != 0) {
			status = -errno;
			break;
		}

		status = translate_socketcall_exit(tracee, sockaddr, addrlen,
			peek_reg(tracee, MODIFIED, SYSARG_6));
		break;
	}

	case PR_fchdir:
	case PR_chdir:
		status = 0;
		break;

	case PR_rename:
	case PR_renameat: {
		char old_path[PATH_MAX], new_path[PATH_MAX];
		ssize_t old_len, new_len;
		Comparison cmp;
		Reg rold, rnew;
		char *tmp;

		if ((int)result < 0)
			break;

		rold = (sysnum == PR_rename) ? SYSARG_1 : SYSARG_2;
		rnew = (sysnum == PR_rename) ? SYSARG_2 : SYSARG_4;

		status = read_path(tracee, old_path, peek_reg(tracee, MODIFIED, rold));
		if (status < 0) break;
		status = detranslate_path(tracee, old_path, NULL);
		if (status < 0) break;
		old_len = (status > 0) ? status - 1 : (ssize_t)strlen(old_path);

		cmp = compare_paths(old_path, tracee->fs->cwd);
		if (cmp != PATH1_IS_PREFIX && cmp != PATHS_ARE_EQUAL) {
			status = 0;
			break;
		}

		status = read_path(tracee, new_path, peek_reg(tracee, MODIFIED, rnew));
		if (status < 0) break;
		status = detranslate_path(tracee, new_path, NULL);
		if (status < 0) break;
		new_len = (status > 0) ? status - 1 : (ssize_t)strlen(new_path);

		if (strlen(tracee->fs->cwd) >= PATH_MAX) {
			status = 0;
			break;
		}
		strcpy(old_path, tracee->fs->cwd);

		substitute_path_prefix(old_path, (size_t)old_len, new_path, (size_t)new_len);
		tmp = talloc_strdup(tracee->fs, old_path);
		if (!tmp) {
			status = -ENOMEM;
			break;
		}

		TALLOC_FREE(tracee->fs->cwd);
		tracee->fs->cwd = tmp;
		status = 0;
		break;
	}

	case PR_readlink:
	case PR_readlinkat: {
		char ref[PATH_MAX], dest[PATH_MAX];
		size_t old_len, max_len, new_len;
		word_t in_addr, out_addr;

		if ((int)result < 0)
			break;

		old_len = result;
		if (sysnum == PR_readlink) {
			out_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
			max_len  = peek_reg(tracee, ORIGINAL, SYSARG_3);
			in_addr  = peek_reg(tracee, MODIFIED, SYSARG_1);
		} else {
			out_addr = peek_reg(tracee, ORIGINAL, SYSARG_3);
			max_len  = peek_reg(tracee, ORIGINAL, SYSARG_4);
			in_addr  = peek_reg(tracee, MODIFIED, SYSARG_2);
		}

		if (max_len > PATH_MAX) max_len = PATH_MAX;
		if (max_len == 0) { status = -EINVAL; break; }

		status = read_data(tracee, dest, out_addr, old_len);
		if (status < 0) break;
		dest[old_len] = '\0';

		status = read_path(tracee, ref, in_addr);
		if (status < 0) break;

		if (status == 1) {
			word_t fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
			if (sysnum == PR_readlink || fd < 0) { status = -EBADF; break; }
			status = readlink_proc_pid_fd(tracee->pid, fd, ref);
			if (status < 0) break;
		}

		status = detranslate_path(tracee, dest, ref);
		if (status <= 0) break;

		if ((size_t)status < max_len)
			new_len = (size_t)status - 1;
		else
			new_len = max_len;

		status = write_data(tracee, out_addr, dest, new_len);
		if (status < 0) break;

		status = (int)new_len;
		break;
	}

	case PR_execve:
	case PR_execveat:
		translate_execve_exit(tracee);
		break;

	case PR_ptrace:
		status = translate_ptrace_exit(tracee);
		break;

	case PR_wait4:
	case PR_waitpid:
		if (tracee->as_ptracer.waits_in == WAITS_IN_PROOT)
			status = translate_wait_exit(tracee);
		break;

	case PR_setrlimit:
	case PR_prlimit64:
		if ((int)result >= 0)
			status = translate_setrlimit_exit(tracee, sysnum == PR_prlimit64);
		break;

	case PR_utime:
		if ((int)result == -ENOSYS)
			fix_and_restart_enosys_syscall(tracee);
		break;

	case PR_statfs:
	case PR_statfs64: {
		char shm[PATH_MAX], path[PATH_MAX];
		Comparison cmp;
		word_t buf;

		if (result != 0) break;
		if (translate_path(tracee, shm, AT_FDCWD, "/dev/shm", true) < 0) break;
		if (read_path(tracee, path, peek_reg(tracee, MODIFIED, SYSARG_1)) < 0) break;

		cmp = compare_paths(shm, path);
		if (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX) {
			buf = peek_reg(tracee, ORIGINAL, (sysnum == PR_statfs64) ? SYSARG_3 : SYSARG_2);
			write_data(tracee, buf, "\x94\x19\x02\x01", 4);
		}
		break;
	}

	case PR_statx:
		status = handle_statx_syscall(tracee, false);
		break;

	case PR_ioctl:
		if (peek_reg(tracee, ORIGINAL, SYSARG_2) == _IOW(0x94, 9, int) &&
		    (int)result == -EACCES)
		{
			poke_reg(tracee, SYSARG_RESULT, -EOPNOTSUPP);
		}
		break;

	default:
		break;
	}

	if (status != 0)
		poke_reg(tracee, SYSARG_RESULT, (word_t)status);

exit_end:
	notify_extensions(tracee, SYSCALL_EXIT_END, 0, 0);
}
