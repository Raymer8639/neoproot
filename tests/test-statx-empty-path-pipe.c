#define _GNU_SOURCE
#include <linux/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

int main(void)
{
    struct statx st = {0};
    int status = syscall(SYS_statx, STDOUT_FILENO, "", AT_EMPTY_PATH,
                         STATX_BASIC_STATS, &st);
    if (status < 0) {
        dprintf(STDERR_FILENO, "statx empty path failed: errno=%d\n", errno);
        return 1;
    }
    if ((st.stx_mode & S_IFMT) != S_IFIFO)
        return 2;
    return write(STDOUT_FILENO, "1:INDEX\n", 8) == 8 ? 0 : 3;
}
