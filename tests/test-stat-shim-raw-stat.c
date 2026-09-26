/*
 * Raw stat syscall probe for the --stat-shim regression.
 *
 * --stat-shim removes newfstatat/statx from the seccomp filter so the preload
 * shim can issue them in-process.  A caller that reaches the kernel without
 * going through the shim's wrappers (Go's runtime, or simply syscall(2) while
 * the shim library is absent) used to be allowed straight through, so the host
 * kernel resolved guest paths in the host namespace and returned wrong
 * results.  gh reported this as "unable to find git executable in PATH".
 *
 * This program calls syscall(SYS_newfstatat) directly; the test runs it with
 * --stat-shim pointing at a non-existent library, so no interposer is active
 * and every call is the untagged raw path the fix must route through the
 * tracer's USER_NOTIF channel.
 *
 * Both probe paths exist only inside the guest namespace, so an untranslated
 * call returns ENOENT while a translated call succeeds.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

static int raw_stat(const char *path)
{
	struct stat st;
	long r;

	errno = 0;
#ifdef SYS_newfstatat
	r = syscall(SYS_newfstatat, AT_FDCWD, path, &st, 0);
#else
	r = syscall(SYS_fstatat64, AT_FDCWD, path, &st, 0);
#endif
	return r == 0 ? 0 : (errno != 0 ? errno : -1);
}

int main(void)
{
	int err;

	/* Absolute guest path that is a bind the host namespace does not have. */
	err = raw_stat("/rawstat-bound");
	if (err != 0) {
		fprintf(stderr, "raw newfstatat(abs guest path) failed: %d\n", err);
		return 1;
	}

	/* Relative name at AT_FDCWD: the guest cwd is virtual. */
	if (chdir("/rawstat-dir") != 0) {
		fprintf(stderr, "chdir guest dir failed: %d\n", errno);
		return 2;
	}
	err = raw_stat("inside");
	if (err != 0) {
		fprintf(stderr, "raw newfstatat(relative guest name) failed: %d\n", err);
		return 3;
	}

	puts("raw stat syscall passed");
	return 0;
}
