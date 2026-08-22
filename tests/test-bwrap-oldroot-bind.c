#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

static int expect_contents(const char *path, const char *expected)
{
	char actual[64];
	ssize_t length;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		return 1;
	}
	length = read(fd, actual, sizeof(actual) - 1);
	close(fd);
	if (length < 0) {
		perror(path);
		return 1;
	}
	actual[length] = '\0';
	if (strcmp(actual, expected) != 0) {
		fprintf(stderr, "%s has unexpected contents: %s", path, actual);
		return 1;
	}
	return 0;
}

static int expect_missing(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0 && errno == ENOENT)
		return 0;
	if (fd >= 0)
		close(fd);
	fprintf(stderr, "%s remained visible after tmpfs mount\n", path);
	return 1;
}

int main(void)
{
	if (expect_contents("/tmp/source", "original-tmp\n") != 0)
		return 1;

	if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0) {
		perror("mount tmpfs /tmp");
		return 1;
	}
	if (expect_missing("/tmp/source") != 0)
		return 1;

	if (umount("/tmp") < 0) {
		perror("umount /tmp");
		return 1;
	}
	if (expect_contents("/tmp/source", "original-tmp\n") != 0) {
		fprintf(stderr, "covered /tmp binding was not restored after umount\n");
		return 1;
	}

	if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0) {
		perror("second mount tmpfs /tmp");
		return 1;
	}
	if (mkdir("/tmp/oldroot", 0700) < 0) {
		perror("mkdir /tmp/oldroot");
		return 1;
	}
	if (syscall(SYS_pivot_root, "/tmp", "/tmp/oldroot") < 0) {
		perror("pivot_root /tmp /tmp/oldroot");
		return 1;
	}
	return expect_contents("/oldroot/tmp/source", "original-tmp\n");
}
