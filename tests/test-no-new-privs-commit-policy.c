/* Pure-source unit test: when may a guest's PR_SET_NO_NEW_PRIVS be recorded?
 *
 * neoproot sets the *real* no_new_privs flag before the guest program runs
 * (its seccomp filter requires it) and answers PR_GET_NO_NEW_PRIVS from the
 * guest's own intent instead.  Committing that intent at syscall entry was
 * wrong: a seccomp filter the guest installed itself can make the real SET
 * fail with EPERM, and a tool that refuses to run once no_new_privs is set
 * (sudo-rs and friends) would then be lied to.
 *
 * This file links only src/syscall/compat_policy.h: no ptrace, no seccomp, no
 * tracee.  It runs inside the PRoot container, where running a nested neoproot
 * is forbidden, and it keeps the removed enter-side rule as the reference the
 * shipped predicate has to disagree with -- reverting the fix fails here.
 *
 * Exit status 0 = pass, 1 = fail. */

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>

#include "syscall/compat_policy.h"

struct commit_case {
	const char *name;
	unsigned long option;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
	Sysnum modified;
	word_t result;
	bool seen_execve;
	/* What the shipped predicate must answer. */
	bool expected;
};

/* How many cases the removed rule got wrong.  Each one is a case where
 * syscall entry cannot know the outcome. */
#define DISCRIMINATING_CASES 4

/* The rule that used to live in src/syscall/enter.c: record the guest's intent
 * as soon as the request looks legal, before the kernel ran the syscall. */
static bool enter_time_commit(const struct commit_case *test)
{
	return test->option == PR_SET_NO_NEW_PRIVS
		&& test->seen_execve
		&& valid_no_new_privs_request(test->option, test->arg2, test->arg3,
					      test->arg4, test->arg5);
}

static bool exit_time_commit(const struct commit_case *test)
{
	return no_new_privs_set_committed(test->option, test->arg2, test->arg3,
					  test->arg4, test->arg5, test->modified,
					  test->result, test->seen_execve);
}

int main(void)
{
	const struct commit_case tests[] = {
		/* The regression: the guest's own filter denies the SET with
		 * EPERM.  The kernel never accepted it, so the guest-visible
		 * state must stay 0 -- the old rule reported 1. */
		{ "guest filter denied the SET (EPERM)", PR_SET_NO_NEW_PRIVS, 1,
		  0, 0, 0, PR_prctl, (word_t) -EPERM, true, false },
		/* The only case that may commit: kernel returned 0. */
		{ "kernel accepted the SET", PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0,
		  PR_prctl, 0, true, true },
		/* Invalid arguments are the kernel's EINVAL, not our state. */
		{ "argument 1 is not 1 (EINVAL)", PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0,
		  PR_prctl, (word_t) -EINVAL, true, false },
		{ "trailing argument is not 0 (EINVAL)", PR_SET_NO_NEW_PRIVS, 1, 0,
		  1, 0, PR_prctl, (word_t) -EINVAL, true, false },
		/* neoproot's own pre-execve SET is not the guest's intent. */
		{ "loader's SET before the initial execve", PR_SET_NO_NEW_PRIVS, 1,
		  0, 0, 0, PR_prctl, 0, false, false },
		/* A syscall PRoot voided or rewrote never reached the kernel, so a
		 * 0 in the result register is not evidence of anything. */
		{ "flagged in enter, syscall voided (PR_void)", PR_SET_NO_NEW_PRIVS,
		  1, 0, 0, 0, PR_void, 0, true, false },
		{ "flagged in enter, syscall rewritten (PR_read)",
		  PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, PR_read, 0, true, false },
		{ "flagged in enter, syscall cancelled (-ENOSYS)",
		  PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, PR_prctl, (word_t) -ENOSYS, true,
		  false },
		/* Everything else is an ordinary prctl: answered by the kernel. */
		{ "GET answered in enter (PR_void)", PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0,
		  PR_void, 0, true, false },
		{ "ordinary prctl (PR_SET_DUMPABLE)", PR_SET_DUMPABLE, 0, 0, 0, 0,
		  PR_prctl, 0, true, false },
	};
	const size_t count = sizeof(tests) / sizeof(tests[0]);
	size_t i;
	int failures = 0;
	int discriminated = 0;

	for (i = 0; i < count; i++) {
		const struct commit_case *test = &tests[i];
		const bool shipped = exit_time_commit(test);
		const bool old_rule = enter_time_commit(test);

		if (shipped != test->expected) {
			fprintf(stderr, "FAIL %s: exit-time commit = %d, expected %d\n",
				test->name, (int) shipped, (int) test->expected);
			failures++;
		}
		if (old_rule != shipped) {
			discriminated++;
			printf("differs %s: enter-time commit = %d, exit-time commit = %d\n",
			       test->name, (int) old_rule, (int) shipped);
		}
	}

	if (discriminated != DISCRIMINATING_CASES) {
		fprintf(stderr, "FAIL: %d discriminating cases, expected %d\n",
			discriminated, DISCRIMINATING_CASES);
		failures++;
	}

	/* The bug, spelled out: a denied SET must not become guest intent. */
	if (!enter_time_commit(&tests[0]) || exit_time_commit(&tests[0])) {
		fprintf(stderr, "FAIL: denied SET is not discriminating anymore\n");
		failures++;
	}

	/* Same sequence through both rules: GET, denied SET, GET. */
	{
		bool old_state = false;
		bool new_state = false;

		old_state |= enter_time_commit(&tests[0]);
		new_state |= exit_time_commit(&tests[0]);
		if (!old_state || new_state) {
			fprintf(stderr,
				"FAIL: after a denied SET the old rule reports %d and the"
				" shipped one %d\n", (int) old_state, (int) new_state);
			failures++;
		}
	}

	if (failures != 0)
		return 1;

	printf("PASS no_new_privs commit policy (%zu cases, %d discriminating)\n",
	       count, discriminated);
	return 0;
}
