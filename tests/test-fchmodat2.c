/* fchmodat2(2) flag-semantics regression for neoproot.
 *
 * The tracer registers fchmodat2 (ARM64 452, Linux 6.6+) and must read the
 * flags argument from the fourth register.  The upstream patch it was ported
 * from reads SYSARG_3, which is *mode*; any mode carrying the 0x100 bit
 * (e.g. 0640, 0600) is then mistaken for AT_SYMLINK_NOFOLLOW and neoproot
 * stops following the final symlink component.  That silently chmods a
 * different inode than the caller asked for.
 *
 * This probe drives the raw syscall through neoproot with guest paths and
 * checks the resulting inode modes:
 *   1. mode with bit 0x100 set, flags=0 -> the named file is changed.
 *   2. symlink to a guest-absolute target, flags=0 -> the target is changed
 *      (the mode must not be misread as "do not follow").
 *   3. relative name at AT_FDCWD -> translated against the virtual cwd.
 *
 * Exit codes: 0 = ok, 125 = skip (kernel lacks fchmodat2), else failure.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif

static int sys_fchmodat2(int dirfd, const char *path, unsigned int mode, int flags)
{
	return (int)syscall(__NR_fchmodat2, dirfd, path, mode, flags);
}

static int mode_of(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return -1;
	return (int)(st.st_mode & 07777);
}

static int fail(const char *what, int got)
{
	fprintf(stderr, "%s (mode=%04o)\n", what, (unsigned)got);
	return 1;
}

int main(void)
{
	int r;
	int m;

	/* Skip cleanly when the kernel or outer seccomp does not expose 452. */
	errno = 0;
	r = sys_fchmodat2(AT_FDCWD, "/fc2-target", 0644, 0);
	if (r != 0 && (errno == ENOSYS || errno == EPERM)) {
		fprintf(stderr, "skip: fchmodat2 unavailable (errno=%d)\n", errno);
		return 125;
	}

	/* 1. flags=0 with a mode that contains bit 0x100 must change the file. */
	r = sys_fchmodat2(AT_FDCWD, "/fc2-target", 0640, 0);
	if (r != 0) {
		fprintf(stderr, "fchmodat2(target, 0640): %s\n", strerror(errno));
		return 1;
	}
	m = mode_of("/fc2-target");
	if (m != 0640)
		return fail("target mode after 0640 (expected 0640)", m);

	/* 2. flags=0 on a symlink follows it; the target must change and the
	 *    symlink itself must not be chmodded.  A misread of mode 0600's
	 *    0x100 bit as AT_SYMLINK_NOFOLLOW breaks this. */
	r = sys_fchmodat2(AT_FDCWD, "/fc2-link", 0600, 0);
	if (r != 0) {
		fprintf(stderr, "fchmodat2(symlink, 0600): %s\n", strerror(errno));
		return 1;
	}
	m = mode_of("/fc2-target");
	if (m != 0600)
		return fail("target mode after symlink chmod (expected 0600)", m);

	/* If AT_SYMLINK_NOFOLLOW is really requested, the kernel must not
	 * change the target.  Linux commonly answers EOPNOTSUPP here; accept
	 * that, but reject a success that changed the target. */
	errno = 0;
	r = sys_fchmodat2(AT_FDCWD, "/fc2-link", 0666, AT_SYMLINK_NOFOLLOW);
	m = mode_of("/fc2-target");
	if (r == 0 && m != 0600) {
		fprintf(stderr,
			"AT_SYMLINK_NOFOLLOW followed the symlink (target mode=%04o)\n",
			(unsigned)m);
		return 1;
	}

	/* 3. relative name at the virtual cwd. */
	if (chdir("/fc2-dir") != 0) {
		fprintf(stderr, "chdir(/fc2-dir): %s\n", strerror(errno));
		return 1;
	}
	r = sys_fchmodat2(AT_FDCWD, "inside", 0644, 0);
	if (r != 0) {
		fprintf(stderr, "fchmodat2(relative): %s\n", strerror(errno));
		return 1;
	}
	m = mode_of("/fc2-dir/inside");
	if (m != 0644)
		return fail("relative target mode (expected 0644)", m);

	puts("fchmodat2 flag semantics passed");
	return 0;
}
