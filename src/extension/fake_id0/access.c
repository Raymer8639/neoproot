#include <linux/limits.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "extension/fake_id0/access.h"
#include "extension/fake_id0/helper_functions.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

/**
 * 处理 access / faccessat 系统调用
 * 根据 meta 文件做权限检查，遵循 access(2) 错误码
 */
HOT
int handle_access_enter_end(Tracee *restrict tracee, Reg path_sysarg,
                            Reg mode_sysarg, Reg dirfd_sysarg, Config *restrict config)
{
    if (UNLIKELY(!tracee || !config))
        return -EINVAL;

    char path[PATH_MAX];
    int ret = read_sysarg_path(tracee, path, path_sysarg, CURRENT);
    if (UNLIKELY(ret < 0))
        return ret;
    if (LIKELY(ret == 1))  // 路径为空或无效，直接放行
        return 0;

    char rel_path[PATH_MAX];
    ret = get_fd_path(tracee, rel_path, dirfd_sysarg, CURRENT);
    if (UNLIKELY(ret < 0))
        return ret;

    ret = check_dir_perms(tracee, 'r', path, rel_path, config);
    if (UNLIKELY(ret < 0))
        return ret;

    int mode = (int)peek_reg(tracee, ORIGINAL, mode_sysarg);
    if (mode & F_OK)  // 只检查存在性，不校验权限
        return 0;

    char meta_path[PATH_MAX];
    ret = get_meta_path(path, meta_path);
    if (UNLIKELY(ret < 0))
        return ret;

    // 构造权限掩码（R_OK=4, W_OK=2, X_OK=1）
    int mask = 0;
    if (mode & R_OK) mask |= 4;
    if (mode & W_OK) mask |= 2;
    if (mode & X_OK) mask |= 1;

    int perms = get_permissions(meta_path, config, 1);
    if (UNLIKELY((perms & mask) != mask))
        return -EACCES;

    return 0;
}