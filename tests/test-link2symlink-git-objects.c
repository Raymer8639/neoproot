#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char payload[] = "git-odb-skip-payload";

static int write_payload(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	ssize_t wrote;

	if (fd < 0)
		return -1;
	wrote = write(fd, payload, sizeof(payload) - 1);
	if (close(fd) < 0)
		return -1;
	return wrote == (ssize_t)(sizeof(payload) - 1) ? 0 : -1;
}

/* Git finalize_object_file: link(tmp, dest), else rename on EPERM/EXDEV. */
static int install_like_git(const char *tmp, const char *dest)
{
	if (link(tmp, dest) == 0) {
		unlink(tmp);
		return 0;
	}
	if (errno == EPERM || errno == EACCES || errno == EXDEV || errno == ENOSYS) {
		if (rename(tmp, dest) == 0)
			return 0;
		perror("rename");
		return -1;
	}
	perror("link");
	return -1;
}

static int expect_host_regular(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0) {
		perror(path);
		return -1;
	}
	if (S_ISLNK(st.st_mode)) {
		fprintf(stderr, "%s: still a symlink after Git-object skip\n", path);
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "%s: expected regular file, mode=%o\n",
			path, (unsigned int)st.st_mode);
		return -1;
	}
	return 0;
}

static int mkdir_p(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == 0 || errno == EEXIST)
		return 0;
	perror(path);
	return -1;
}

int main(void)
{
	if (chdir("/") < 0)
		return 1;
	if (mkdir_p(".git", 0700) < 0 ||
	    mkdir_p(".git/objects", 0700) < 0 ||
	    mkdir_p(".git/objects/01", 0700) < 0 ||
	    mkdir_p(".git/objects/ab", 0700) < 0 ||
	    mkdir_p(".git/objects/pack", 0700) < 0 ||
	    mkdir_p("files", 0700) < 0 ||
	    mkdir_p("files/ab", 0700) < 0 ||
	    mkdir_p("work", 0700) < 0)
		return 1;

	if (write_payload(".git/objects/tmp_obj_sha1") < 0)
		return 1;
	if (install_like_git(".git/objects/tmp_obj_sha1",
			     ".git/objects/01/23456789abcdef0123456789abcdef01234567") < 0)
		return 1;
	if (expect_host_regular(".git/objects/01/23456789abcdef0123456789abcdef01234567") < 0)
		return 1;

	if (write_payload(".git/objects/tmp_obj_sha256") < 0)
		return 1;
	if (install_like_git(".git/objects/tmp_obj_sha256",
			     ".git/objects/ab/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd") < 0)
		return 1;
	if (expect_host_regular(".git/objects/ab/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd") < 0)
		return 1;

	if (write_payload(".git/objects/tmp_pack") < 0)
		return 1;
	if (install_like_git(".git/objects/tmp_pack",
			     ".git/objects/pack/pack-0123456789abcdef0123456789abcdef01234567.pack") < 0)
		return 1;
	if (expect_host_regular(".git/objects/pack/pack-0123456789abcdef0123456789abcdef01234567.pack") < 0)
		return 1;

	if (write_payload("files/ab/source") < 0)
		return 1;
	if (link("files/ab/source",
		 "files/ab/0123456789abcdef0123456789abcdef01234567") < 0) {
		perror("link pnpm-like");
		return 1;
	}

	if (write_payload("work/source") < 0)
		return 1;
	if (link("work/source", "work/fake") < 0) {
		perror("link work");
		return 1;
	}

	printf("link2symlink git-object skip probe passed\n");
	return 0;
}
