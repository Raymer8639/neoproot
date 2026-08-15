/* openat2(2) 支持回归测试（上游 114a7c6 移植适配）
 *
 * 现代 tar/coreutils（如 Fedora 44 的 tar）用 openat2 + RESOLVE_BENEATH
 * 安全解包符号链接。neoproot 必须像 openat() 一样翻译它；否则路径不翻译
 * （逃出 guest rootfs）或被外层 seccomp 拒绝时报 ENOSYS。
 *
 * 退出码：0 = ok，125 = 跳过（openat2 不可用），其余 = 失败。 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x08
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

#define MARKER  "/tmp/openat2_marker"
#define PAYLOAD "openat2-payload"

int main(void)
{
	int fd;
	ssize_t n;
	char buf[64] = { 0 };

	/* 用普通 open() 建标记文件：neoproot 总会翻译它 → 落在 guest rootfs 内 */
	fd = open(MARKER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open(O_CREAT)");
		exit(EXIT_FAILURE);
	}
	if (write(fd, PAYLOAD, strlen(PAYLOAD)) != (ssize_t) strlen(PAYLOAD)) {
		perror("write");
		exit(EXIT_FAILURE);
	}
	close(fd);

	/* 用 openat2 打开同一绝对路径：若不翻译，会按 host 根解析而失败 */
	fd = sys_openat2(AT_FDCWD, MARKER, O_RDONLY, 0, 0);
	if (fd < 0) {
		if (errno == ENOSYS) {
			/* openat2 真不可用：跳过 */
			exit(125);
		}
		fprintf(stderr, "openat2(%s) absolute: %s\n", MARKER, strerror(errno));
		exit(EXIT_FAILURE);
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0 || strcmp(buf, PAYLOAD) != 0) {
		fprintf(stderr, "openat2 read mismatch: '%s' (path not confined to rootfs?)\n", buf);
		exit(EXIT_FAILURE);
	}

	/* RESOLVE_BENEATH + 目录 fd 形式（tar 解包模式） */
	fd = sys_openat2(AT_FDCWD, MARKER, O_RDONLY, 0, RESOLVE_BENEATH);
	if (fd < 0) {
		fprintf(stderr, "openat2(RESOLVE_BENEATH): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0 || strcmp(buf, PAYLOAD) != 0) {
		fprintf(stderr, "openat2 resolve read mismatch: '%s'\n", buf);
		exit(EXIT_FAILURE);
	}

	unlink(MARKER);
	printf("openat2: OK\n");
	return 0;
}
