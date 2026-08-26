#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_statx
#if defined(__aarch64__)
#define __NR_statx 291
#elif defined(__x86_64__)
#define __NR_statx 332
#else
#define __NR_statx (-1)
#endif
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x1000U
#endif

static int install_statx_trap(void)
{
#if __NR_statx < 0
    return -ENOSYS;
#else
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -errno;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0)
        return -errno;
    return 0;
#endif
}

int main(void)
{
    struct statx info = {0};
    int fd;
    int status;

    fd = open("/test-dir", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        perror("open test directory");
        return 1;
    }

    status = install_statx_trap();
    if (status < 0) {
        if (status == -ENOSYS || status == -EINVAL || status == -EPERM) {
            fprintf(stderr, "SKIP: seccomp trap unavailable (%s)\n", strerror(-status));
            close(fd);
            return 125;
        }
        errno = -status;
        perror("install statx seccomp trap");
        close(fd);
        return 1;
    }

#if __NR_statx < 0
    close(fd);
    fprintf(stderr, "SKIP: statx syscall number unavailable\n");
    return 125;
#else
    status = syscall(__NR_statx, fd, "", AT_EMPTY_PATH,
                     STATX_BASIC_STATS | STATX_MNT_ID, &info);
#endif
    close(fd);
    if (status < 0) {
        perror("statx AT_EMPTY_PATH");
        return 1;
    }
    if (!(info.stx_mask & STATX_MNT_ID) || info.stx_mnt_id == 0) {
        fprintf(stderr, "statx mount ID missing: mask=%#x mnt_id=%llu\n",
                info.stx_mask, info.stx_mnt_id);
        return 1;
    }
    if ((info.stx_mode & S_IFMT) != S_IFDIR) {
        fprintf(stderr, "statx mode is not a directory: %#x\n", info.stx_mode);
        return 1;
    }

    puts("statx AT_EMPTY_PATH mount ID: OK");
    return 0;
}
