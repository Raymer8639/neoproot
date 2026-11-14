#include <linux/limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "extension/fake_id0/rename.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 rename / renameat
 * 存在 meta 文件时，同步重命名
 */
int handle_rename_enter_end(Tracee *tracee, Reg oldfd_sysarg, Reg oldpath_sysarg,
	Reg newfd_sysarg, Reg newpath_sysarg, Config *config)
{
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	char rel_oldpath[PATH_MAX];
	char rel_newpath[PATH_MAX];
	int ret;

	// 读取旧路径
	ret = read_sysarg_path(tracee, oldpath, oldpath_sysarg, CURRENT);
	if (ret != 0)
		return ret;

	// 读取新路径
	ret = read_sysarg_path(tracee, newpath, newpath_sysarg, CURRENT);
	if (ret != 0)
		return ret;

	// 获取旧目录基路径
	ret = get_fd_path(tracee, rel_oldpath, oldfd_sysarg, CURRENT);
	if (ret < 0)
		return ret;

	// 获取新目录基路径
	ret = get_fd_path(tracee, rel_newpath, newfd_sysarg, CURRENT);
	if (ret < 0)
		return ret;

	// 检查两边目录写权限
	ret = check_dir_perms(tracee, 'w', oldpath, rel_oldpath, config);
	if (ret < 0)
		return ret;

	ret = check_dir_perms(tracee, 'w', newpath, rel_newpath, config);
	if (ret < 0)
		return ret;

	return 0;
}

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT (1U << 2)
#endif

/* The kernel decides whether a rename happens. Read back its translated paths
 * only after success; failed and same-inode renames leave records untouched. */
int handle_rename_exit_end(Tracee *tracee, Reg oldpath_sysarg, Reg newpath_sysarg,
    Reg flags_sysarg, Config *config)
{
    char oldpath[PATH_MAX], newpath[PATH_MAX], old_meta[PATH_MAX], new_meta[PATH_MAX];
    struct stat st;
    unsigned int flags = flags_sysarg == IGNORE_SYSARG ? 0 :
        peek_reg(tracee, ORIGINAL, flags_sysarg);
    if (tracee->status < 0 || peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)
        return 0;
    if (read_sysarg_path(tracee, oldpath, oldpath_sysarg, MODIFIED) != 0
        || read_sysarg_path(tracee, newpath, newpath_sysarg, MODIFIED) != 0
        || get_meta_path(oldpath, old_meta) < 0 || get_meta_path(newpath, new_meta) < 0
        || strcmp(old_meta, new_meta) == 0)
        return 0;
    if (flags & RENAME_EXCHANGE) {
        bool old_exists = path_exists(old_meta) == 0;
        bool new_exists = path_exists(new_meta) == 0;
        mode_t old_mode, new_mode;
        uid_t old_uid, new_uid;
        gid_t old_gid, new_gid;
        if (old_exists)
            read_meta_file(old_meta, &old_mode, &old_uid, &old_gid, config);
        if (new_exists)
            read_meta_file(new_meta, &new_mode, &new_uid, &new_gid, config);
        if (old_exists)
            write_meta_file(new_meta, old_mode, old_uid, old_gid, false, config);
        else
            remove_meta_file(new_meta);
        if (new_exists)
            write_meta_file(old_meta, new_mode, new_uid, new_gid, false, config);
        else
            remove_meta_file(old_meta);
        return 0;
    }
    if (!(flags & RENAME_WHITEOUT) && lstat(oldpath, &st) == 0)
        return 0;
    if (path_exists(old_meta) == 0)
        (void)rename_meta_file(old_meta, new_meta);
    else
        (void)remove_meta_file(new_meta);
    return 0;
}
