#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>

#include "extension/fake_id0/exec.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 execve 系统调用
 * 根据 meta 文件做权限检查，遵循 execve(2) 错误码
 */
int handle_exec_enter_end(Tracee *tracee, Reg filename_sysarg, Config *config)
{
    char path[PATH_MAX];
    char meta_path[PATH_MAX];
    mode_t mode;
    uid_t uid;
    gid_t gid;
    int perms;
    int status;

    // 读取要执行的文件路径
    status = read_sysarg_path(tracee, path, filename_sysarg, ORIGINAL);
    if (status < 0)
        return status;
    if (status == 1)
        return 0;

    // 获取 meta 文件路径
    status = get_meta_path(path, meta_path);
    if (status < 0)
        return status;

    // 无 meta 文件 → 不处理
    if (path_exists(meta_path) != 0)
        return 0;

    // 检查父目录权限（execve 无 dirfd，相对 / 检查）
    status = check_dir_perms(tracee, 'r', meta_path, "/", config);
    if (status < 0)
        return status;

    // 检查是否有执行权限
    perms = get_permissions(meta_path, config, 0);
    if ((perms & 1) == 0)
        return -EACCES;

    // 读取 meta 信息，处理 suid/sgid
    read_meta_file(meta_path, &mode, &uid, &gid, config);

    // 设置 suid 模拟
    if (mode & S_ISUID) {
        config->ruid = 0;
        config->euid = 0;
        config->suid = 0;
    }

    // 设置 sgid 模拟
    if (mode & S_ISGID) {
        config->rgid = 0;
        config->egid = 0;
        config->sgid = 0;
    }

    // 注释：解释器检查逻辑待实现
    return 0;
}
