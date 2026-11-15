/* no_new_privs virtual-state commit regression: guest-side probe.
 *
 * neoproot sets the *real* PR_SET_NO_NEW_PRIVS before the guest program runs
 * (its seccomp filter requires it) and answers PR_GET_NO_NEW_PRIVS from the
 * guest's own intent instead.  That intent may only be recorded once the
 * kernel really accepted the SET: a seccomp filter the guest installed itself
 * can fail it with EPERM, and a tool that refuses to run once no_new_privs is
 * set (sudo-rs and friends) must not see a flag it never managed to set.
 *
 * Usage: probe [--require-filter] [--after-exec]
 *   --require-filter  exit 125 instead of skipping when PR_SET_SECCOMP is not
 *                     permitted here (no CAP_SYS_ADMIN and the real flag is 0)
 *   --after-exec      internal: the post-execve half of the same probe
 *
 * Exit status: 0 all cases passed, 1 a case failed, 125 skipped (no filter).
 * Nothing here looks at /proc, so no extra bindings are needed. */

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#ifdef __NR_prctl
#define PROBE_NR_PRCTL __NR_prctl
#else
#define PROBE_NR_PRCTL 167 /* arm64 */
#endif

static bool require_filter;
static const char *self;

static void failed(const char *name, const char *detail, long got, long want)
{
	fprintf(stderr, "FAIL %s: %s (got %ld, want %ld)\n", name, detail, got, want);
	exit(1);
}

static void passed(const char *name, const char *detail)
{
	printf("ok %s: %s\n", name, detail);
	fflush(stdout);
}

/* PR_GET_NO_NEW_PRIVS as the guest sees it: neoproot answers from the guest's
 * own intent, not from the real flag it set for its seccomp filter. */
static long guest_get(const char *name)
{
	errno = 0;
	long value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (value < 0) {
		fprintf(stderr, "FAIL %s: PR_GET_NO_NEW_PRIVS: %s\n", name,
			strerror(errno));
		exit(1);
	}
	return value;
}

/* Fail PR_SET_NO_NEW_PRIVS with EPERM, allow everything else.  This is the
 * guest filter the whole regression is about. */
static int install_deny_filter(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROBE_NR_PRCTL, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_NO_NEW_PRIVS, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog program = {
		.len = sizeof filter / sizeof *filter,
		.filter = filter,
	};

	errno = 0;
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

/* Trap instead of failing the SET: the kernel cancels the syscall and raises
 * SIGSYS, which neoproot answers with -ENOSYS.  On kernels that hand the
 * tracer the seccomp event before the syscall-entry stop, neoproot reaches its
 * exit handler through the synthetic sysexit a SIGSYS produces -- where the
 * result register still holds the syscall's first argument instead of a
 * return value. */
static int install_trap_filter(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROBE_NR_PRCTL, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_NO_NEW_PRIVS, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog program = {
		.len = sizeof filter / sizeof *filter,
		.filter = filter,
	};

	errno = 0;
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static char trapped_set_verdict(void)
{
	if (install_trap_filter() < 0)
		return 's';
	/* The request is refused either by neoproot's SIGSYS handler or by
	 * the kernel; the errno itself is not the point here. */
	(void) prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	errno = 0;
	long value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (value < 0)
		return 'e';
	return value == 0 ? '0' : '1';
}

/* Deny the SET, then report what the guest still sees: '0' or '1' is the
 * answer to PR_GET_NO_NEW_PRIVS afterwards, 's' means this host does not
 * permit the filter, 'e' means the SET did not fail with EPERM. */
static char denied_set_verdict(void)
{
	if (install_deny_filter() < 0)
		return 's';

	errno = 0;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != -1 || errno != EPERM)
		return 'e';

	errno = 0;
	long value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (value < 0)
		return 'e';
	return value == 0 ? '0' : '1';
}

/* Run @verdict_fn in a child -- so the filter it installs cannot follow the
 * probe into the next case -- and hand its single-character verdict back
 * through a pipe.  Returns false when the child produced no verdict at all,
 * which a signal the tracer did not swallow can cause. */
static bool spawn_verdict(char (*verdict_fn)(void), bool force_all_stop,
			  char *verdict)
{
	int fds[2];
	ssize_t got;
	pid_t child;
	int attempt;

	if (pipe(fds) < 0) {
		perror("pipe");
		exit(1);
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		exit(1);
	}
	if (child == 0) {
		close(fds[0]);
		if (force_all_stop) {
			pid_t grandchild;
			int status;

			(void) ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			grandchild = fork();
			if (grandchild == 0) {
				char own = verdict_fn();

				if (write(fds[1], &own, 1) != 1)
					_exit(1);
				_exit(0);
			}
			/* The tracer side of that nested ptrace is neoproot
			 * itself; the verdict arrives through the pipe. */
			if (grandchild > 0)
				while (waitpid(grandchild, &status, 0) < 0 &&
				       errno == EINTR)
					;
			_exit(0);
		}
		*verdict = verdict_fn();
		if (write(fds[1], verdict, 1) != 1)
			_exit(1);
		_exit(0);
	}
	close(fds[1]);
	got = read(fds[0], verdict, 1);
	close(fds[0]);
	/* A forced-all-stop child can be killed by the tracer emulation, so only
	 * reap what has already gone. */
	for (attempt = 0; attempt < 200; attempt++) {
		if (waitpid(child, NULL, WNOHANG) != 0)
			break;
		usleep(1000);
	}
	return got == 1;
}

/* A SET the guest's own filter denies with EPERM.
 *
 * @force_all_stop asks neoproot to trace this subtree with plain ptrace stops
 * again, the way a guest debugger does with ptrace(PTRACE_TRACEME).  Without
 * it the kernel never delivers neoproot's SECCOMP_RET_TRACE stop for the SET:
 * ERRNO is a stricter action than TRACE, so the guest's own filter wins over
 * neoproot's and the syscall is decided before the tracer is asked.  With it
 * the SET reaches neoproot's enter and exit handlers and the exit-side commit
 * condition is what decides the answer. */
static void denied_set_case(const char *name, bool force_all_stop, long want)
{
	char verdict = 0;

	if (!spawn_verdict(denied_set_verdict, force_all_stop, &verdict)) {
		fprintf(stderr, "FAIL %s: no verdict from the child\n", name);
		exit(1);
	}
	if (verdict == 's') {
		if (require_filter) {
			fprintf(stderr, "SKIP %s: PR_SET_SECCOMP is not permitted here\n",
				name);
			exit(125);
		}
		printf("skip %s: PR_SET_SECCOMP is not permitted here\n", name);
		return;
	}
	if (verdict == 'e')
		failed(name, "the injected SET did not fail with EPERM", 0, 1);
	if (verdict - '0' != want)
		failed(name, "PR_GET_NO_NEW_PRIVS after the denied SET",
		       verdict - '0', want);
	passed(name, "denied SET (EPERM) left the guest-visible state unchanged");
}

/* A SET the guest's own filter traps: the kernel cancels the syscall and raises
 * SIGSYS instead of returning, so no commit may happen either. */
static void trapped_set_case(const char *name, long want)
{
	char verdict = 0;

	if (!spawn_verdict(trapped_set_verdict, false, &verdict)) {
		printf("skip %s: the child did not survive the trap\n", name);
		return;
	}
	if (verdict == 's') {
		if (require_filter) {
			fprintf(stderr, "SKIP %s: PR_SET_SECCOMP is not permitted here\n",
				name);
			exit(125);
		}
		printf("skip %s: PR_SET_SECCOMP is not permitted here\n", name);
		return;
	}
	if (verdict == 'e')
		failed(name, "PR_GET_NO_NEW_PRIVS after the trapped SET", -1, want);
	if (verdict - '0' != want)
		failed(name, "PR_GET_NO_NEW_PRIVS after the trapped SET",
		       verdict - '0', want);
	passed(name, "trapped SET left the guest-visible state unchanged");
}

/* fork, ask the child what it sees, and compare with @want. */
static void child_answers(const char *name, long want)
{
	int fds[2];
	char answer = 0;
	ssize_t got;
	pid_t child;
	int status = 0;

	if (pipe(fds) < 0) {
		perror("pipe");
		exit(1);
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		exit(1);
	}
	if (child == 0) {
		long value;

		close(fds[0]);
		errno = 0;
		value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
		answer = value < 0 ? 'e' : (value == 0 ? '0' : '1');
		if (write(fds[1], &answer, 1) != 1)
			_exit(1);
		_exit(0);
	}
	close(fds[1]);
	got = read(fds[0], &answer, 1);
	close(fds[0]);
	while (waitpid(child, &status, 0) < 0 && errno == EINTR)
		;
	if (got != 1)
		failed(name, "no answer from the child", 0, want);
	if (answer == 'e')
		failed(name, "PR_GET_NO_NEW_PRIVS in the child", -1, want);
	if (answer - '0' != want)
		failed(name, "PR_GET_NO_NEW_PRIVS in the child", answer - '0', want);
	passed(name, "child inherited the guest-visible state");
}

static void check_set_cases(void)
{
	long value;

	/* Illegal arguments stay the kernel's EINVAL and change nothing. */
	errno = 0;
	if (prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) != -1 || errno != EINVAL)
		failed("invalid-arg2", "PR_SET_NO_NEW_PRIVS(0, 0, 0, 0)",
		       errno, EINVAL);
	errno = 0;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 1, 0) != -1 || errno != EINVAL)
		failed("invalid-arg4", "PR_SET_NO_NEW_PRIVS(1, 0, 1, 0)",
		       errno, EINVAL);
	value = guest_get("invalid-args");
	if (value != 0)
		failed("invalid-args", "PR_GET_NO_NEW_PRIVS after EINVAL", value, 0);
	passed("invalid-args", "EINVAL did not change the state");

	/* A SET the kernel refuses never happened: denied by a filter the guest
	 * installed, trapped by one, and -- the case this fix is about -- denied
	 * while neoproot watches the enter side through plain ptrace stops. */
	trapped_set_case("trapped-set", 0);
	denied_set_case("denied-set", false, 0);
	denied_set_case("denied-set-allstop", true, 0);

	/* A SET the kernel accepts is the guest's intent. */
	errno = 0;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		failed("set-accepted", "PR_SET_NO_NEW_PRIVS(1, 0, 0, 0)",
		       errno, 0);
	value = guest_get("set-accepted");
	if (value != 1)
		failed("set-accepted", "PR_GET_NO_NEW_PRIVS after accepted SET",
		       value, 1);
	passed("set-accepted", "accepted SET makes the guest answer 1");
	child_answers("fork-inherit-1", 1);
}

int main(int argc, char **argv)
{
	bool after_exec = false;
	int i;

	self = argv[0];
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--require-filter") == 0)
			require_filter = true;
		else if (strcmp(argv[i], "--after-exec") == 0)
			after_exec = true;
		else {
			fprintf(stderr, "usage: %s [--require-filter] [--after-exec]\n",
				argv[0]);
			return 2;
		}
	}

	if (after_exec) {
		long value = guest_get("exec");
		if (value != 1)
			failed("exec", "PR_GET_NO_NEW_PRIVS after execve", value, 1);
		passed("exec", "guest intent survived execve");

		/* execve must not reset the state either: a SET the kernel
		 * refuses is still not a reason to change it. */
		denied_set_case("exec-denied-set", true, 1);
		printf("PASS no_new_privs commit regression (after execve)\n");
		return 0;
	}

	/* A fresh guest has no intention of its own, whatever neoproot had to
	 * set for its seccomp filter. */
	{
		long value = guest_get("initial");
		if (value != 0)
			failed("initial", "PR_GET_NO_NEW_PRIVS before any SET",
			       value, 0);
		passed("initial", "fresh guest answers 0");
	}

	/* Ordinary prctl options are still the kernel's business. */
	{
		char name[17] = {0};
		long value;

		if (prctl(PR_GET_NAME, name) != 0)
			failed("ordinary-prctl", "PR_GET_NAME", errno, 0);
		value = guest_get("ordinary-prctl");
		if (value != 0)
			failed("ordinary-prctl", "PR_GET_NO_NEW_PRIVS changed", value,
			       0);
		passed("ordinary-prctl", "other prctl options pass through");
	}

	child_answers("fork-inherit-0", 0);
	check_set_cases();

	/* execve keeps the answer: the second half of the probe runs after it. */
	{
		char *exec_argv[4];
		int n = 0;

		exec_argv[n++] = (char *) self;
		exec_argv[n++] = (char *) "--after-exec";
		if (require_filter)
			exec_argv[n++] = (char *) "--require-filter";
		exec_argv[n] = NULL;
		execv(self, exec_argv);
		fprintf(stderr, "FAIL exec: execv(%s): %s\n", self, strerror(errno));
		return 1;
	}
}
