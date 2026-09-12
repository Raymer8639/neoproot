#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const char payload[] = "git-l2s-mmap-payload-0123456789abcdef";

static int create_payload(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0444);
	ssize_t wrote;

	if (fd < 0)
		return -1;
	wrote = write(fd, payload, sizeof(payload) - 1);
	if (close(fd) < 0)
		return -1;
	return wrote == (ssize_t)(sizeof(payload) - 1) ? 0 : -1;
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

static int mmap_relative(const char *path)
{
	struct stat statl;
	int fd;
	void *map;

	if (access(path, R_OK) != 0) {
		perror("access");
		return -1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("open");
		return -1;
	}
	if (check_stat("fstat", fstat(fd, &statl), &statl, 2) < 0) {
		close(fd);
		return -1;
	}
	if (statl.st_size != (off_t)(sizeof(payload) - 1)) {
		fprintf(stderr, "fstat size %ld, expected %zu\n",
			(long) statl.st_size, sizeof(payload) - 1);
		close(fd);
		return -1;
	}

	map = mmap(NULL, (size_t) statl.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "mmap %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	if (memcmp(map, payload, sizeof(payload) - 1) != 0) {
		fprintf(stderr, "mmap contents of %s did not match backing payload\n", path);
		munmap(map, (size_t) statl.st_size);
		close(fd);
		return -1;
	}
	if (munmap(map, (size_t) statl.st_size) < 0 || close(fd) < 0)
		return -1;
	return 0;
}

int main(void)
{
	struct stat statl;

	if (chdir("/") < 0)
		return 1;
	if (mkdir("shared", 0700) < 0 || mkdir("shared/d9", 0700) < 0)
		return 1;
	if (create_payload("shared/d9/source") < 0)
		return 1;
	if (link("shared/d9/source", "shared/d9/linked") < 0) {
		perror("link");
		return 1;
	}

	if (check_stat("lstat source", lstat("shared/d9/source", &statl), &statl, 2) < 0)
		return 1;
	if (check_stat("lstat linked", lstat("shared/d9/linked", &statl), &statl, 2) < 0)
		return 1;

	if (mmap_relative("shared/d9/source") < 0)
		return 1;
	if (mmap_relative("shared/d9/linked") < 0)
		return 1;

	if (check_stat("lstat source after mmap",
		       lstat("shared/d9/source", &statl), &statl, 2) < 0)
		return 1;
	if (check_stat("lstat linked after mmap",
		       lstat("shared/d9/linked", &statl), &statl, 2) < 0)
		return 1;

	printf("link2symlink mmap follow-at-open probe passed\n");
	return 0;
}
