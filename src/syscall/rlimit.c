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

#include <stdbool.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "cli/note.h"

int translate_setrlimit_exit(const Tracee *tracee, bool is_prlimit)
{
	struct rlimit64 proot_stack;
	word_t resource;
	word_t address;
	rlim_t tracee_stack_limit;
	Reg sysarg;
	int status;

	sysarg = (is_prlimit ? SYSARG_2 : SYSARG_1);

	resource = peek_reg(tracee, ORIGINAL, sysarg);
	address  = peek_reg(tracee, ORIGINAL, sysarg + 1);

	/* Not the resource we're looking for?  */
	if (resource != RLIMIT_STACK)
		return 0;

	/* Retrieve new tracee's stack limit.  */
	if (is_prlimit) {
		/* Not the prlimit usage we're looking for?  */
		if (address == 0)
			return 0;

		tracee_stack_limit = peek_uint64(tracee, address);
	}
	else {
		tracee_stack_limit = (rlim_t)peek_word(tracee, address);

		/* Convert this special value from 32-bit to 64-bit,
		 * if needed.  */
		if (is_32on64_mode(tracee) && tracee_stack_limit == (rlim_t)0xFFFFFFFF)
			tracee_stack_limit = RLIM_INFINITY;
	}
	if (errno != 0)
		return -errno;

	/* Get current PRoot's stack limit.  */
	status = prlimit64(0, RLIMIT_STACK, NULL, &proot_stack);
	if (status < 0) {
		VERBOSE(tracee, 1, "can't get stack limit.");
		return 0; /* Not fatal.  */
	}

	/* No need to increase current PRoot's stack limit?  */
	if (proot_stack.rlim_cur >= tracee_stack_limit)
		return 0;

	proot_stack.rlim_cur = tracee_stack_limit;

	/* Increase current PRoot's stack limit.  */
	status = prlimit64(0, RLIMIT_STACK, &proot_stack, NULL);
	if (status < 0) {
		VERBOSE(tracee, 1, "can't set stack limit.");
		return 0;
	}

	VERBOSE(tracee, 1, "stack soft limit increased to %llu bytes",
		(unsigned long long)proot_stack.rlim_cur);

	return 0;
}
