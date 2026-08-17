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
	char meta_path[PATH_MAX];
	mode_t mode;
	uid_t uid;
	gid_t gid;
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

	// 获取旧 meta 路径
	ret = get_meta_path(oldpath, meta_path);
	if (ret < 0)
		return ret;

	// 没有 meta 就直接退出
	if (path_exists(meta_path) != 0)
		return 0;

	// 读取并删除旧 meta
	ret = read_meta_file(meta_path, &mode, &uid, &gid, config);
	if (ret < 0)
		return ret;
	remove_meta_file(meta_path);

	// 写入新 meta
	ret = get_meta_path(newpath, meta_path);
	if (ret < 0)
		return ret;

	return write_meta_file(meta_path, mode, uid, gid, 0, config);
}
