#include <linux/limits.h>

#include "extension/fake_id0/symlink.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 symlink / symlinkat
 * 检查目标目录写权限，原路径不需要权限
 */
int handle_symlink_enter_end(Tracee *tracee, Reg oldpath_sysarg,
                             Reg newdirfd_sysarg, Reg newpath_sysarg, Config *config)
{
    char oldpath[PATH_MAX];
    char newpath[PATH_MAX];
    char rel_newpath[PATH_MAX];
    int ret;

    // 读取原路径（仅读取，不检查权限）
    ret = read_sysarg_path(tracee, oldpath, oldpath_sysarg, CURRENT);
    if (ret < 0)
        return ret;

    // 读取目标路径
    ret = read_sysarg_path(tracee, newpath, newpath_sysarg, CURRENT);
    if (ret != 0)
        return ret;

    // 获取目标基目录
    ret = get_fd_path(tracee, rel_newpath, newdirfd_sysarg, CURRENT);
    if (ret < 0)
        return ret;

    // 检查目标目录写权限
    ret = check_dir_perms(tracee, 'w', newpath, rel_newpath, config);
    if (ret < 0)
        return ret;

    return 0;
}
