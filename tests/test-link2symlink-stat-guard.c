#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int create_file(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);

	if (fd < 0)
		return -1;

	return close(fd);
}

static int check_stat(const char *operation, int status,
		      const struct stat *statl, nlink_t expected_nlink)
{
	if (status < 0) {
		perror(operation);
		return -1;
	}

	if (!S_ISREG(statl->st_mode) || statl->st_nlink != expected_nlink) {
		fprintf(stderr, "%s: expected regular file with nlink=%lu, got mode=%o nlink=%lu\n",
			operation, (unsigned long) expected_nlink,
			(unsigned int) statl->st_mode, (unsigned long) statl->st_nlink);
		return -1;
	}

	return 0;
}

static int check_path_stat(const char *path, nlink_t expected_nlink)
{
	struct stat statl;

	if (check_stat("stat", stat(path, &statl), &statl, expected_nlink) < 0)
		return -1;
	if (check_stat("lstat", lstat(path, &statl), &statl, expected_nlink) < 0)
		return -1;
	return check_stat("fstatat", fstatat(AT_FDCWD, path, &statl,
					      AT_SYMLINK_NOFOLLOW), &statl,
			  expected_nlink);
}

int main(void)
{
	struct stat statl;
	int fd;

	if (mkdir("work", 0700) < 0 || chdir("work") < 0)
		return 1;
	if (create_file("plain") < 0 || create_file("source") < 0 ||
	    link("source", "fake") < 0)
		return 1;

	if (check_path_stat("plain", 1) < 0 || check_path_stat("source", 2) < 0 ||
	    check_path_stat("fake", 2) < 0)
		return 1;

	fd = open("fake", O_RDONLY);
	if (fd < 0)
		return 1;
	if (check_stat("fstat", fstat(fd, &statl), &statl, 2) < 0) {
		close(fd);
		return 1;
	}
	if (close(fd) < 0)
		return 1;

	printf("link2symlink stat guard probe passed\n");
	return 0;
}
