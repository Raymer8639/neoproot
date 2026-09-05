/* faccessat2(2) fallback regression
 *
 * glibc 2.33+ implements [ -x path ] with faccessat2(..., AT_EACCESS).
 * Android/PRoot-Distro kernels often lack that syscall.  If PRoot
 * forwards it unchanged, the first missing-path check returns ENOSYS
 * or ENOENT in x0; the next check then uses that value as dirfd and
 * fails with ENETDOWN even though the file is executable.
 *
 * Exit: 0 = ok, otherwise failure. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EACCESS
#define AT_EACCESS 0x200
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

#define PRESENT "/bin/present"
#define MISSING "/bin/jre/sh/java"

static int sys_faccessat2(int dirfd, const char *path, int mode, int flags)
{
	return (int)syscall(__NR_faccessat2, dirfd, path, mode, flags);
}

int main(void)
{
	int i;
	int r;
	int saved;

	if (access(PRESENT, X_OK) != 0) {
		fprintf(stderr, "setup: %s is not executable: %s\n",
			PRESENT, strerror(errno));
		return 1;
	}

	r = sys_faccessat2(AT_FDCWD, PRESENT, X_OK, AT_EACCESS);
	saved = errno;
	if (r != 0) {
		fprintf(stderr, "faccessat2(present, AT_EACCESS): %s\n",
			strerror(saved));
		return 1;
	}

	r = sys_faccessat2(AT_FDCWD, MISSING, X_OK, AT_EACCESS);
	saved = errno;
	if (r == 0) {
		fprintf(stderr, "faccessat2(missing) unexpectedly succeeded\n");
		return 1;
	}
	if (saved != ENOENT) {
		fprintf(stderr, "faccessat2(missing): expected ENOENT, got %s\n",
			strerror(saved));
		return 1;
	}

	for (i = 0; i < 64; i++) {
		r = sys_faccessat2(AT_FDCWD, MISSING, X_OK, AT_EACCESS);
		saved = errno;
		if (r == 0 || saved != ENOENT) {
			fprintf(stderr,
				"iter %d missing: r=%d errno=%s\n",
				i, r, strerror(saved));
			return 1;
		}

		r = sys_faccessat2(AT_FDCWD, PRESENT, X_OK, AT_EACCESS);
		saved = errno;
		if (r != 0) {
			fprintf(stderr,
				"iter %d present after missing: %s\n",
				i, strerror(saved));
			return 1;
		}

		if (faccessat(AT_FDCWD, PRESENT, X_OK, 0) != 0) {
			fprintf(stderr, "iter %d faccessat(present): %s\n",
				i, strerror(errno));
			return 1;
		}
	}

	return 0;
}
