#include <linux/limits.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include "tracee/mem.h"
#include "extension/fake_id0/utimensat.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 utimensat 系统调用
 * 检查 meta 文件权限，按 utimensat(2) 规则返回错误
 */
int handle_utimensat_enter_end(Tracee *tracee, Reg dirfd_sysarg,
                               Reg path_sysarg, Reg times_sysarg, Config *config)
{
    struct timespec times[2];
    char path[PATH_MAX];
    char meta_path[PATH_MAX];
    mode_t mode;
    uid_t owner;
    gid_t gid;
    int ret;
    int perms;

    // 只处理尝试修改时间的调用
    word_t times_addr = peek_reg(tracee, ORIGINAL, times_sysarg);
    if (times_addr != 0) {
        ret = read_data(tracee, times, times_addr, sizeof(times));
        if (ret < 0)
            return ret;

        // 都不是 UTIME_NOW 则不需要检查
        if (times[0].tv_nsec != UTIME_NOW && times[1].tv_nsec != UTIME_NOW)
            return 0;
    }

    int dirfd = peek_reg(tracee, ORIGINAL, dirfd_sysarg);
    if (dirfd == AT_FDCWD) {
        ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
        if (ret != 0)
            return ret;
    } else {
        ret = get_fd_path(tracee, path, dirfd_sysarg, CURRENT);
        if (ret < 0)
            return ret;
    }

    ret = get_meta_path(path, meta_path);
    if (ret < 0)
        return ret;

    // 必须是文件所有者或 root
    if (read_meta_file(meta_path, &mode, &owner, &gid, config) == 0) {
        if (config->euid != owner && config->euid != 0)
            return -EACCES;
    }

    // 必须有写权限
    perms = get_permissions(meta_path, config, 0);
    if (!(perms & 2))
        return -EACCES;

    return 0;
}
