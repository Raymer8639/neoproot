#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void child_error(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	vdprintf(STDERR_FILENO, format, arguments);
	va_end(arguments);
}

static int wait_for_exit(pid_t child, int *exit_status)
{
	const struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000 };
	int status;
	int retries;

	for (retries = 0; retries < 500; retries++) {
		pid_t result = waitpid(child, &status, WNOHANG);

		if (result < 0) {
			perror("waitpid");
			return -1;
		}
		if (result == 0) {
			nanosleep(&pause, NULL);
			continue;
		}
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			*exit_status = status;
			return 0;
		}
		if (!WIFSTOPPED(status)) {
			fprintf(stderr, "unexpected traced child state\n");
			return -1;
		}
		if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
			perror("ptrace PTRACE_CONT");
			return -1;
		}
	}

	fprintf(stderr, "neoproot did not exit while already traced\n");
	if (kill(child, SIGKILL) < 0 && errno != ESRCH)
		perror("kill traced child");
	if (waitpid(child, &status, 0) < 0 && errno != ECHILD)
		perror("waitpid killed child");
	return -1;
}

int main(int argc, char *argv[])
{
	char output[2048] = "";
	int pipe_fds[2];
	int status;
	pid_t child;
	ssize_t length;

	if (argc != 2) {
		fprintf(stderr, "usage: %s /path/to/neoproot\n", argv[0]);
		return 2;
	}
	if (pipe(pipe_fds) < 0) {
		perror("pipe");
		return 1;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		close(pipe_fds[0]);
		if (dup2(pipe_fds[1], STDERR_FILENO) < 0)
			_exit(127);
		close(pipe_fds[1]);
		unsetenv("PROOT_UNSET_DONE");
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			child_error("ptrace PTRACE_TRACEME: %s\n", strerror(errno));
			_exit(127);
		}
		raise(SIGSTOP);
		execl(argv[1], argv[1], "--version", (char *)NULL);
		child_error("exec neoproot: %s\n", strerror(errno));
		_exit(127);
	}

	close(pipe_fds[1]);
	if (wait_for_exit(child, &status) < 0) {
		close(pipe_fds[0]);
		return 1;
	}
	length = read(pipe_fds[0], output, sizeof(output) - 1);
	close(pipe_fds[0]);
	if (length < 0) {
		perror("read child stderr");
		return 1;
	}
	output[length] = 0;

	if (!WIFEXITED(status) || WEXITSTATUS(status) == 0) {
		fprintf(stderr, "neoproot accepted an existing ptrace tracer\n");
		return 1;
	}
	if (strstr(output, "refusing to start while already traced") == NULL
		|| strstr(output, "Termux host") == NULL) {
		fprintf(stderr, "neoproot rejected ptrace without the nested-PRoot guidance:\n%s", output);
		return 1;
	}

	return 0;
}
