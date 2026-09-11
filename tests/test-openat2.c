/* openat2(2) resolve-flag regression.
 *
 * neoproot lowers openat2 to openat and must emulate how.resolve in
 * userspace: passing the flags to the kernel would reject the translated
 * absolute host path.
 *
 * 退出码：0 = ok，125 = 跳过（openat2 不可用），其余 = 失败。 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01ull
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS 0x02ull
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04ull
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x08ull
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10ull
#endif

struct test_open_how {
	unsigned long long flags;
	unsigned long long mode;
	unsigned long long resolve;
};

static int sys_openat2(int dirfd, const char *path, unsigned long long flags,
		       unsigned long long mode, unsigned long long resolve)
{
	struct test_open_how how = { .flags = flags, .mode = mode, .resolve = resolve };
	return syscall(__NR_openat2, dirfd, path, &how, sizeof(how));
}

static int fail(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	return -1;
}

static int expect_ok(const char *name, int fd)
{
	if (fd < 0)
		return fail(name);
	close(fd);
	return 0;
}

static int expect_errno(const char *name, int fd, int want)
{
	int got = errno;

	if (fd >= 0) {
		close(fd);
		fprintf(stderr, "%s: expected %s, succeeded\n", name, strerror(want));
		return -1;
	}
	if (got != want) {
		fprintf(stderr, "%s: expected %s, got %s\n", name,
			strerror(want), strerror(got));
		return -1;
	}
	return 0;
}

int main(void)
{
	int fd;
	int jail;
	ssize_t n;
	char buf[64] = { 0 };
	const char *payload = "openat2-payload";

	if (mkdir("/tmp", 0755) < 0 && errno != EEXIST)
		return fail("mkdir /tmp");
	if (mkdir("/tmp/jail", 0755) < 0 && errno != EEXIST)
		return fail("mkdir jail");

	fd = open("/tmp/file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return fail("creat /tmp/file");
	if (write(fd, payload, strlen(payload)) != (ssize_t)strlen(payload))
		return fail("write /tmp/file");
	close(fd);

	fd = open("/tmp/jail/inside", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return fail("creat inside");
	if (write(fd, payload, strlen(payload)) != (ssize_t)strlen(payload))
		return fail("write inside");
	close(fd);

	fd = open("/tmp/outside", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return fail("creat outside");
	if (write(fd, "out", 3) != 3)
		return fail("write outside");
	close(fd);

	unlink("/tmp/link");
	if (symlink("file", "/tmp/link") < 0)
		return fail("symlink");

	fd = sys_openat2(AT_FDCWD, "/tmp/file", O_RDONLY, 0, 0);
	if (fd < 0) {
		if (errno == ENOSYS)
			exit(125);
		return fail("openat2 absolute");
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0 || strcmp(buf, payload) != 0) {
		fprintf(stderr, "openat2 read mismatch: '%s'\n", buf);
		return 1;
	}

	if (expect_ok("RESOLVE_NO_SYMLINKS regular",
		      sys_openat2(AT_FDCWD, "/tmp/file", O_RDONLY, 0,
				  RESOLVE_NO_SYMLINKS)) < 0)
		return 1;
	if (expect_errno("RESOLVE_NO_SYMLINKS symlink",
			 sys_openat2(AT_FDCWD, "/tmp/link", O_RDONLY, 0,
				     RESOLVE_NO_SYMLINKS),
			 ELOOP) < 0)
		return 1;

	jail = open("/tmp/jail", O_RDONLY | O_DIRECTORY);
	if (jail < 0)
		return fail("open jail");

	if (expect_ok("RESOLVE_BENEATH relative inside",
		      sys_openat2(jail, "inside", O_RDONLY, 0, RESOLVE_BENEATH)) < 0)
		return 1;
	if (expect_errno("RESOLVE_BENEATH ../outside",
			 sys_openat2(jail, "../outside", O_RDONLY, 0, RESOLVE_BENEATH),
			 EXDEV) < 0)
		return 1;
	if (expect_errno("RESOLVE_BENEATH absolute outside",
			 sys_openat2(jail, "/tmp/outside", O_RDONLY, 0, RESOLVE_BENEATH),
			 EXDEV) < 0)
		return 1;
	if (expect_errno("RESOLVE_BENEATH AT_FDCWD absolute",
			 sys_openat2(AT_FDCWD, "/tmp/file", O_RDONLY, 0, RESOLVE_BENEATH),
			 EXDEV) < 0)
		return 1;

	if (expect_ok("RESOLVE_IN_ROOT absolute under jail",
		      sys_openat2(jail, "/inside", O_RDONLY, 0, RESOLVE_IN_ROOT)) < 0)
		return 1;

	close(jail);
	unlink("/tmp/link");
	printf("openat2: OK\n");
	return 0;
}
