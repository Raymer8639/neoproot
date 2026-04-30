#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>

#include "syscall/sysnum.h"
#include "extension/fake_id0/chmod.h"
#include "extension/fake_id0/helper_functions.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

/**
 * 处理 chmod / fchmod / fchmodat
 * 重写实现：更清晰、更安全、权限检查更标准
 */
HOT
int handle_chmod_enter_end(Tracee *restrict tracee, Reg path_sysarg, Reg mode_sysarg,
                           Reg fd_sysarg, Reg dirfd_sysarg, Config *restrict config)
{
    char path[PATH_MAX];
    char rel_path[PATH_MAX];
    char meta_path[PATH_MAX];
    mode_t new_mode, old_mode;
    uid_t owner;
    gid_t group;
    int ret;

    // 1. 获取要 chmod 的目标路径（path 或 fd）
    if (path_sysarg == IGNORE_SYSARG) {
        // fchmod
        ret = get_fd_path(tracee, path, fd_sysarg, CURRENT);
    } else {
        // chmod / fchmodat
        ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
    }
    if (UNLIKELY(ret < 0))
        return ret;

    // 2. 文件不在虚拟环境内 → 直接放行
    if (LIKELY(ret == 1)) {
        set_sysnum(tracee, PR_getuid);
        return 0;
    }

    // 3. 没有 meta 文件 → 不接管
    ret = get_meta_path(path, meta_path);
    if (UNLIKELY(ret < 0 || path_exists(meta_path) < 0))
        return 0;

    // 4. 检查目录是否可访问
    ret = get_fd_path(tracee, rel_path, dirfd_sysarg, CURRENT);
    if (UNLIKELY(ret < 0))
        return ret;

    ret = check_dir_perms(tracee, 'w', path, rel_path, config);
    if (UNLIKELY(ret < 0))
        return ret;

    // 5. 读取当前 meta 信息，检查是否有权修改
    read_meta_file(meta_path, &old_mode, &owner, &group, config);
    if (UNLIKELY(config->euid != 0 && config->euid != owner))
        return -EPERM;

    // 6. 取新权限并写入 meta
    new_mode = (mode_t)peek_reg(tracee, ORIGINAL, mode_sysarg);
    set_sysnum(tracee, PR_getuid);

    return write_meta_file(meta_path, new_mode, owner, group, 0, config);
}