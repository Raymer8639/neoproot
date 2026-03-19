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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <sys/ptrace.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <talloc.h>
#include <string.h>

#include "ptrace/wait.h"
#include "ptrace/ptrace.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/event.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "attribute.h"

int translate_wait_enter(Tracee *ptracer)
{
	PTRACER.waits_in = WAITS_IN_KERNEL;

	if (PTRACER.nb_ptracees == 0)
		return 0;

	pid_t pid = (pid_t)peek_reg(ptracer, ORIGINAL, SYSARG_1);
	if (pid != -1) {
		Tracee *ptracee = get_tracee(ptracer, pid, false);
		if (!ptracee || PTRACEE.ptracer != ptracer)
			return 0;
	}

	set_sysnum(ptracer, PR_void);
	PTRACER.waits_in = WAITS_IN_PROOT;
	return 0;
}

static int update_wait_status(Tracee *ptracer, Tracee *ptracee)
{
	if (PTRACEE.ptracer == ptracee->parent &&
	    (WIFEXITED(PTRACEE.event4.ptracer.value) || WIFSIGNALED(PTRACEE.event4.ptracer.value)))
	{
		restart_original_syscall(ptracer);
		detach_from_ptracer(ptracee);
		if (PTRACEE.is_zombie)
			TALLOC_FREE(ptracee);
		return 0;
	}

	word_t addr = peek_reg(ptracer, ORIGINAL, SYSARG_2);
	if (addr != 0) {
		poke_int32(ptracer, addr, PTRACEE.event4.ptracer.value);
		if (errno != 0)
			return -errno;
	}

	PTRACEE.event4.ptracer.pending = false;
	int pid = ptracee->pid;

	if (PTRACEE.is_zombie) {
		detach_from_ptracer(ptracee);
		TALLOC_FREE(ptracee);
	}

	return pid;
}

int translate_wait_exit(Tracee *ptracer)
{
	assert(PTRACER.waits_in == WAITS_IN_PROOT);
	PTRACER.waits_in = DOESNT_WAIT;

	pid_t pid = (pid_t)peek_reg(ptracer, ORIGINAL, SYSARG_1);
	word_t options = peek_reg(ptracer, ORIGINAL, SYSARG_3);

	Tracee *ptracee = get_stopped_ptracee(ptracer, pid, true, options);
	if (!ptracee) {
		if (PTRACER.nb_ptracees == 0)
			return -ECHILD;

		if (options & WNOHANG)
			return has_ptracees(ptracer, pid, options) ? 0 : -ECHILD;

		PTRACER.wait_pid = pid;
		PTRACER.wait_options = options;
		return 0;
	}

	int status = update_wait_status(ptracer, ptracee);
	if (status < 0)
		return status;

	return status;
}

bool handle_ptracee_event(Tracee *ptracee, int event)
{
	Tracee *ptracer = PTRACEE.ptracer;
	if (!ptracer)
		return false;

	bool keep_stopped = true;
	PTRACEE.event4.proot.value = event;
	PTRACEE.event4.proot.pending = true;

	bool handled_by_proot_first = false;
	bool suppressible = false;

	if (WIFSTOPPED(event)) {
		int code = (event >> 8) & 0xffff;

		switch (code) {
			case SIGTRAP | 0x80:
				if (PTRACEE.ignore_syscalls || PTRACEE.ignore_loader_syscalls)
					return false;
				if (!(PTRACEE.options & PTRACE_O_TRACESYSGOOD))
					event &= ~(0x80 << 8);
				handled_by_proot_first = IS_IN_SYSEXIT(ptracee);
				break;

			case SIGTRAP | (PTRACE_EVENT_FORK << 8):
			case SIGTRAP | (PTRACE_EVENT_VFORK << 8):
			case SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8):
			case SIGTRAP | (PTRACE_EVENT_CLONE << 8):
			case SIGTRAP | (PTRACE_EVENT_EXIT << 8):
			case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
				PTRACEE.tracing_started = true;
				handled_by_proot_first = true;
				break;

			case SIGTRAP | (PTRACE_EVENT_SECCOMP2 << 8):
			case SIGTRAP | (PTRACE_EVENT_SECCOMP << 8):
				return false;

			case SIGSYS:
				handled_by_proot_first = true;
				suppressible = true;
				break;

			default:
				PTRACEE.tracing_started = true;
				break;
		}
	} else if (WIFEXITED(event) || WIFSIGNALED(event)) {
		PTRACEE.tracing_started = true;
		keep_stopped = false;
	}

	if (!PTRACEE.tracing_started)
		return false;

	if (handled_by_proot_first) {
		int sig = handle_tracee_event(ptracee, PTRACEE.event4.proot.value);
		PTRACEE.event4.proot.value = sig;

		if (suppressible && sig == 0) {
			if (seccomp_event_happens_after_enter_sigtrap()) {
				if (PTRACEE.ignore_syscalls) {
					restart_tracee(ptracee, 0);
					return true;
				}

				if (PTRACEE.options & PTRACE_O_TRACESYSGOOD)
					event = (SIGTRAP | 0x80) << 8 | 0x7f;
				else
					event = SIGTRAP << 8 | 0x7f;
			} else {
				restart_tracee(ptracee, 0);
				return true;
			}
		}
	}

	PTRACEE.event4.ptracer.value = event;
	PTRACEE.event4.ptracer.pending = true;
	kill(ptracer->pid, SIGCHLD);

	if ((PTRACER.wait_pid == -1 || PTRACER.wait_pid == ptracee->pid) &&
	    EXPECTED_WAIT_CLONE(PTRACER.wait_options, ptracee))
	{
		int status = update_wait_status(ptracer, ptracee);
		if (status == 0)
			chain_next_syscall(ptracer);
		else
			poke_reg(ptracer, SYSARG_RESULT, (word_t)status);

		push_regs(ptracer);
		PTRACER.wait_pid = 0;
		restart_tracee(ptracer, 0);
		return keep_stopped;
	}

	return keep_stopped;
}
