#include <linux/limits.h>

#include "extension/fake_id0/mk.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 mkdir/mkdirat/mknod/mknodat
 * 创建对应的 meta 文件，按标准返回权限错误
 */
int handle_mk_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg,
                         Reg mode_sysarg, Config *config)
{
    char path[PATH_MAX];
    char rel_path[PATH_MAX];
    char meta_path[PATH_MAX];
    mode_t mode;
    int ret;

    // 读取路径
    ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
    if (ret != 0)
        return ret;

    // 文件已存在 → 交给内核处理 EEXIST
    if (path_exists(path) == 0)
        return 0;

    // 构造 meta 路径
    ret = get_meta_path(path, meta_path);
    if (ret < 0)
        return ret;

    // 获取父目录路径
    ret = get_fd_path(tracee, rel_path, fd_sysarg, CURRENT);
    if (ret < 0)
        return ret;

    // 检查目录写权限
    ret = check_dir_perms(tracee, 'w', path, rel_path, config);
    if (ret < 0)
        return ret;

    // 加强权限并写入 meta
    mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
    poke_reg(tracee, mode_sysarg, mode | 0700);

    return write_meta_file(meta_path, mode, config->euid, config->egid, 1, config);
}
