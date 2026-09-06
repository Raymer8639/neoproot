#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef NEOPROOT_NOTIFY_PLUMBING_SIZE
#define NEOPROOT_NOTIFY_PLUMBING_SIZE 0x4e4f5449LL
#endif

#ifndef NEOPROOT_NOTIFY_SENTINEL
#define NEOPROOT_NOTIFY_SENTINEL "neoproot-notify-sentinel"
#endif

static int do_fstatat(const char *path, struct stat *st)
{
#ifdef __NR_newfstatat
	return syscall(__NR_newfstatat, AT_FDCWD, path, st, 0);
#else
	return fstatat(AT_FDCWD, path, st, 0);
#endif
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "expect-magic";
	struct stat st;
	int fd;
	char buf[8];
	ssize_t n;

	if (strcmp(mode, "expect-real") == 0) {
		if (do_fstatat("marker", &st) != 0) {
			fprintf(stderr, "fstatat(marker) failed: %s\n", strerror(errno));
			return 1;
		}
		if (st.st_size != 5) {
			fprintf(stderr, "expected real size 5, got %lld\n",
				(long long)st.st_size);
			return 1;
		}
	} else {
		if (do_fstatat(NEOPROOT_NOTIFY_SENTINEL, &st) != 0) {
			fprintf(stderr, "fstatat(sentinel) failed: %s\n", strerror(errno));
			return 1;
		}
		if (st.st_size != NEOPROOT_NOTIFY_PLUMBING_SIZE) {
			fprintf(stderr, "expected plumbing size %lld, got %lld\n",
				(long long)NEOPROOT_NOTIFY_PLUMBING_SIZE,
				(long long)st.st_size);
			return 1;
		}
	}

	fd = open("marker", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open(marker) failed: %s\n", strerror(errno));
		return 1;
	}
	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n != 5 || memcmp(buf, "hello", 5) != 0) {
		fprintf(stderr, "TRACE open/read path failed (n=%zd)\n", n);
		return 1;
	}

	printf("seccomp-notify pipe %s ok\n", mode);
	return 0;
}
