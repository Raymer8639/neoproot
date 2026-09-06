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
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

static int do_fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
#ifdef __NR_newfstatat
	return syscall(__NR_newfstatat, dirfd, path, st, flags);
#else
	return fstatat(dirfd, path, st, flags);
#endif
}

static int expect_reg_size(const char *what, const char *path, off_t size)
{
	struct stat st;

	if (do_fstatat(AT_FDCWD, path, &st, 0) != 0) {
		fprintf(stderr, "%s: fstatat(%s) failed: %s\n",
			what, path, strerror(errno));
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "%s: %s not regular (mode=%o)\n",
			what, path, (unsigned)st.st_mode);
		return 1;
	}
	if (st.st_size != size) {
		fprintf(stderr, "%s: %s size %lld, expected %lld\n",
			what, path, (long long)st.st_size, (long long)size);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "expect-real";
	struct stat st;
	int fd;
	char buf[8];
	ssize_t n;

	if (strcmp(mode, "expect-real") == 0) {
		if (expect_reg_size("expect-real", "marker", 5) != 0)
			return 1;
	} else if (strcmp(mode, "expect-translated") == 0) {
		int dirfd;

		if (expect_reg_size("file", "marker", 5) != 0)
			return 1;

		if (do_fstatat(AT_FDCWD, "missing-notify-path", &st, 0) != -1 ||
		    errno != ENOENT) {
			fprintf(stderr, "missing path: expected ENOENT, got %s\n",
				strerror(errno));
			return 1;
		}

		if (do_fstatat(AT_FDCWD, "link-to-marker", &st,
			       AT_SYMLINK_NOFOLLOW) != 0) {
			fprintf(stderr, "lstat(link): %s\n", strerror(errno));
			return 1;
		}
		if (!S_ISLNK(st.st_mode)) {
			fprintf(stderr, "AT_SYMLINK_NOFOLLOW: expected symlink, mode=%o\n",
				(unsigned)st.st_mode);
			return 1;
		}

		if (do_fstatat(AT_FDCWD, "link-to-marker", &st, 0) != 0) {
			fprintf(stderr, "stat(link): %s\n", strerror(errno));
			return 1;
		}
		if (!S_ISREG(st.st_mode) || st.st_size != 5) {
			fprintf(stderr, "followed link: mode=%o size=%lld\n",
				(unsigned)st.st_mode, (long long)st.st_size);
			return 1;
		}

		dirfd = open("subdir", O_RDONLY | O_DIRECTORY);
		if (dirfd < 0) {
			fprintf(stderr, "open(subdir): %s\n", strerror(errno));
			return 1;
		}
		if (do_fstatat(dirfd, "inside", &st, AT_SYMLINK_NOFOLLOW) != 0) {
			fprintf(stderr, "fstatat(dirfd, inside): %s\n", strerror(errno));
			close(dirfd);
			return 1;
		}
		close(dirfd);
		if (!S_ISREG(st.st_mode) || st.st_size != 4) {
			fprintf(stderr, "dirfd+basename: mode=%o size=%lld\n",
				(unsigned)st.st_mode, (long long)st.st_size);
			return 1;
		}
	} else if (strcmp(mode, "expect-l2s") == 0) {
		if (unlink("l2s-b") < 0 && errno != ENOENT) {
			fprintf(stderr, "unlink(l2s-b): %s\n", strerror(errno));
			return 1;
		}
		if (link("l2s-a", "l2s-b") != 0) {
			fprintf(stderr, "link(l2s-a, l2s-b): %s\n", strerror(errno));
			return 1;
		}
		if (do_fstatat(AT_FDCWD, "l2s-a", &st, AT_SYMLINK_NOFOLLOW) != 0) {
			fprintf(stderr, "fstatat(l2s-a): %s\n", strerror(errno));
			return 1;
		}
		if (!S_ISREG(st.st_mode) || st.st_nlink != 2) {
			fprintf(stderr, "l2s-a: expected regular nlink=2, got mode=%o nlink=%lu\n",
				(unsigned)st.st_mode, (unsigned long)st.st_nlink);
			return 1;
		}
		if (do_fstatat(AT_FDCWD, "l2s-b", &st, AT_SYMLINK_NOFOLLOW) != 0) {
			fprintf(stderr, "fstatat(l2s-b): %s\n", strerror(errno));
			return 1;
		}
		if (!S_ISREG(st.st_mode) || st.st_nlink != 2) {
			fprintf(stderr, "l2s-b: expected regular nlink=2, got mode=%o nlink=%lu\n",
				(unsigned)st.st_mode, (unsigned long)st.st_nlink);
			return 1;
		}
	} else {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 1;
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
