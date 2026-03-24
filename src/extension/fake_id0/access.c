#include <linux/limits.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "extension/fake_id0/access.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 access / faccessat 系统调用
 * 根据 meta 文件做权限检查，遵循 access(2) 错误码
 */
int handle_access_enter_end(Tracee *tracee, Reg path_sysarg,
                            Reg mode_sysarg, Reg dirfd_sysarg, Config *config)
{
    int mode, mask;
    char path[PATH_MAX];
    char rel_path[PATH_MAX];
    char meta_path[PATH_MAX];
    int ret;

    // 读取用户路径
    ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
    if (ret < 0)
        return ret;
    if (ret == 1)
        return 0;

    // 处理 dirfd 相对路径
    ret = get_fd_path(tracee, rel_path, dirfd_sysarg, CURRENT);
    if (ret < 0)
        return ret;

    // 检查目录访问权限
    ret = check_dir_perms(tracee, 'r', path, rel_path, config);
    if (ret < 0)
        return ret;

    // 获取调用时的 mode
    mode = peek_reg(tracee, ORIGINAL, mode_sysarg);

    // 只检查存在性，不校验权限
    if (mode & F_OK)
        return 0;

    // 获取 meta 文件路径
    ret = get_meta_path(path, meta_path);
    if (ret < 0)
        return ret;

    // 构造需要的权限掩码
    mask = 0;
    if (mode & R_OK) mask |= 4;
    if (mode & W_OK) mask |= 2;
    if (mode & X_OK) mask |= 1;

    // 检查权限
    if ((get_permissions(meta_path, config, 1) & mask) != mask)
        return -EACCES;

    return 0;
}
