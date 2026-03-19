#include <linux/limits.h>
#include <unistd.h>

#include "extension/fake_id0/unlink.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 unlink / unlinkat / rmdir
 * 检查目录写权限，并同步删除对应的 meta 文件
 */
int handle_unlink_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg, Config *config)
{
    char path[PATH_MAX];
    char rel_path[PATH_MAX];
    char meta_path[PATH_MAX];
    int ret;

    // 读取要删除的路径
    ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
    if (ret != 0)
        return ret;

    // 获取 meta 文件路径
    ret = get_meta_path(path, meta_path);
    if (ret < 0)
        return ret;

    // 获取所在目录路径
    ret = get_fd_path(tracee, rel_path, fd_sysarg, CURRENT);
    if (ret < 0)
        return ret;

    // 检查目录写权限
    ret = check_dir_perms(tracee, 'w', path, rel_path, config);
    if (ret < 0)
        return ret;

    // 如果 meta 文件存在，一并删除
    if (path_exists(meta_path) == 0)
        unlink(meta_path);

    return 0;
}
