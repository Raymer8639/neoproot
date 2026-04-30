#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>

#include "syscall/sysnum.h"
#include "extension/fake_id0/chown.h"
#include "extension/fake_id0/helper_functions.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

#ifndef USERLAND

HOT
int handle_chown_enter_end(Tracee *restrict tracee, Config *restrict config,
                           Reg uid_sysarg, Reg gid_sysarg) {
    uid_t new_uid = (uid_t)peek_reg(tracee, ORIGINAL, uid_sysarg);
    gid_t new_gid = (gid_t)peek_reg(tracee, ORIGINAL, gid_sysarg);

    if (LIKELY(new_uid == config->ruid))
        poke_reg(tracee, uid_sysarg, getuid());
    if (LIKELY(new_gid == config->rgid))
        poke_reg(tracee, gid_sysarg, getgid());

    return 0;
}

#else /* USERLAND */

/**
 * 处理 chown / lchown / fchown / fchownat
 * 重写实现：逻辑清晰、权限检查标准、修复边界 case
 */
HOT
int handle_chown_enter_end(Tracee *restrict tracee, Reg path_sysarg, Reg owner_sysarg,
                           Reg group_sysarg, Reg fd_sysarg, Reg dirfd_sysarg,
                           Config *restrict config) {
    char path[PATH_MAX];
    char rel_path[PATH_MAX];
    char meta_path[PATH_MAX];
    mode_t mode;
    uid_t new_owner, current_owner;
    gid_t new_group, current_group;
    int ret;

    // 1. 获取目标路径（从 path 或 fd）
    if (path_sysarg == IGNORE_SYSARG)
        ret = get_fd_path(tracee, path, fd_sysarg, CURRENT);
    else
        ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);

    if (UNLIKELY(ret < 0))
        return ret;

    // 不在虚拟文件系统内 → 放行原系统调用
    if (LIKELY(ret == 1)) {
        set_sysnum(tracee, PR_getuid);
        return 0;
    }

    // 2. 获取 meta 文件路径
    ret = get_meta_path(path, meta_path);
    if (UNLIKELY(ret < 0))
        return ret;

    // 无 meta 文件 → 不处理
    if (UNLIKELY(path_exists(meta_path) < 0))
        return 0;

    // 3. 检查父目录权限
    ret = get_fd_path(tracee, rel_path, dirfd_sysarg, CURRENT);
    if (UNLIKELY(ret < 0))
        return ret;

    ret = check_dir_perms(tracee, 'w', path, rel_path, config);
    if (UNLIKELY(ret < 0))
        return ret;

    // 4. 读取当前 meta 信息
    read_meta_file(meta_path, &mode, &current_owner, &current_group, config);

    // 5. 解析用户传入的 uid/gid（-1 表示保持不变）
    new_owner = (uid_t)peek_reg(tracee, ORIGINAL, owner_sysarg);
    if ((int)new_owner == -1)
        new_owner = current_owner;

    new_group = (gid_t)peek_reg(tracee, ORIGINAL, group_sysarg);
    if ((int)new_group == -1)
        new_group = current_group;

    // 6. 权限检查（Linux 标准语义）
    if (UNLIKELY(config->euid != 0 && config->euid != current_owner))
        return -EPERM;

    // 7. 写入新的属主到 meta
    if (LIKELY(config->euid == 0)) {
        // root 可以改任何属主
        write_meta_file(meta_path, mode, new_owner, new_group, 0, config);
    } else {
        // 普通用户只能改组，不能改所有者
        write_meta_file(meta_path, mode, current_owner, new_group, 0, config);
        poke_reg(tracee, owner_sysarg, current_owner);
    }

    // 替换成无害系统调用，避免真正执行 chown
    set_sysnum(tracee, PR_getuid);
    return 0;
}

#endif /* USERLAND */