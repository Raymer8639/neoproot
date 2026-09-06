#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

static int check_reg(const char *what, const char *path, struct stat *st,
		     nlink_t nlink)
{
	if (!S_ISREG(st->st_mode)) {
		fprintf(stderr, "%s: %s is not a regular file (mode=%o)\n",
			what, path, (unsigned)st->st_mode);
		return -1;
	}
	if (st->st_nlink != nlink) {
		fprintf(stderr, "%s: %s nlink=%lu, expected %lu\n",
			what, path, (unsigned long)st->st_nlink,
			(unsigned long)nlink);
		return -1;
	}
	return 0;
}

static int send_fd(int sock, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[1] = { 0 };
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = buf;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static int recv_fd(int sock)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int fd = -1;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = buf;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	if (recvmsg(sock, &msg, 0) < 0)
		return -1;
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
		return -1;
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	return fd;
}

int main(void)
{
	struct stat st;
	int dirfd;
	int other;
	int i;
	int socks[2];
	int passed;

	if (mkdir("/dir", 0755) < 0 || mkdir("/other", 0755) < 0 ||
	    mkdir("/dir/sub", 0755) < 0) {
		perror("mkdir");
		return 1;
	}
	if (close(open("/dir/a", O_CREAT | O_WRONLY, 0644)) < 0 ||
	    close(open("/dir/b", O_CREAT | O_WRONLY, 0644)) < 0 ||
	    close(open("/dir/c", O_CREAT | O_WRONLY, 0644)) < 0 ||
	    close(open("/other/a", O_CREAT | O_WRONLY, 0600)) < 0 ||
	    close(open("/dir/sub/inside", O_CREAT | O_WRONLY, 0644)) < 0) {
		perror("creat");
		return 1;
	}

	dirfd = open("/dir", O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror("open /dir");
		return 1;
	}
	for (i = 0; i < 8; i++) {
		if (fstatat(dirfd, "a", &st, AT_SYMLINK_NOFOLLOW) < 0) {
			perror("fstatat a");
			return 1;
		}
		if (check_reg("repeat", "/dir/a", &st, 1) < 0)
			return 1;
	}

	if (fstatat(AT_FDCWD, "no-such-relative", &st, AT_SYMLINK_NOFOLLOW) == 0 ||
	    errno != ENOENT) {
		fprintf(stderr, "AT_FDCWD relative should be ENOENT\n");
		return 1;
	}

	other = open("/other", O_RDONLY | O_DIRECTORY);
	if (other < 0) {
		perror("open /other");
		return 1;
	}
	if (dup2(other, dirfd) < 0) {
		perror("dup2");
		return 1;
	}
	close(other);
	if (fstatat(dirfd, "a", &st, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat after dup2");
		return 1;
	}
	if ((st.st_mode & 0777) != 0600) {
		fprintf(stderr, "dup2 did not switch directory (mode=%o)\n",
			(unsigned)st.st_mode);
		return 1;
	}
	close(dirfd);

	dirfd = open("/dir", O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror("reopen /dir");
		return 1;
	}
	close(dirfd);
	dirfd = open("/other", O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror("open /other after close");
		return 1;
	}
	if (fstatat(dirfd, "a", &st, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat reused fd");
		return 1;
	}
	if ((st.st_mode & 0777) != 0600) {
		fprintf(stderr, "reused fd still saw old directory\n");
		return 1;
	}
	close(dirfd);

	dirfd = open("/dir", O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror("open /dir for rename");
		return 1;
	}
	if (rename("/dir", "/dir-moved") < 0) {
		perror("rename");
		return 1;
	}
	if (fstatat(dirfd, "b", &st, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat after rename");
		return 1;
	}
	if (check_reg("rename", "b", &st, 1) < 0)
		return 1;
	close(dirfd);

	if (link("/dir-moved/c", "/dir-moved/c-link") == 0) {
		dirfd = open("/dir-moved", O_RDONLY | O_DIRECTORY);
		if (dirfd < 0) {
			perror("open dir-moved");
			return 1;
		}
		if (fstatat(dirfd, "c-link", &st, AT_SYMLINK_NOFOLLOW) < 0) {
			perror("fstatat l2s");
			return 1;
		}
		if (check_reg("l2s", "c-link", &st, 2) < 0)
			return 1;
		close(dirfd);
	} else if (errno != EPERM) {
		perror("link");
		return 1;
	}

	dirfd = open("/dir-moved", O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror("open for scm");
		return 1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
		perror("socketpair");
		return 1;
	}
	if (send_fd(socks[0], dirfd) < 0 || (passed = recv_fd(socks[1])) < 0) {
		perror("scm rights");
		return 1;
	}
	close(socks[0]);
	close(socks[1]);
	close(dirfd);
	if (fstatat(passed, "a", &st, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat scm fd");
		return 1;
	}
	if (check_reg("scm", "a", &st, 1) < 0)
		return 1;
	close(passed);

	dirfd = open("/data", O_RDONLY | O_DIRECTORY);
	if (dirfd >= 0) {
		if (fstatat(dirfd, "nested", &st, AT_SYMLINK_NOFOLLOW) < 0) {
			perror("fstatat nested bind");
			return 1;
		}
		close(dirfd);
		dirfd = open("/data/nested", O_RDONLY | O_DIRECTORY);
		if (dirfd < 0) {
			perror("open nested");
			return 1;
		}
		if (fstatat(dirfd, "marker", &st, AT_SYMLINK_NOFOLLOW) < 0) {
			perror("fstatat nested marker");
			return 1;
		}
		close(dirfd);
	}

	printf("dirfd fast-path probe passed\n");
	return 0;
}
