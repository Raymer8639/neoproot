#include <linux/limits.h>

#include "extension/fake_id0/link.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 link / linkat
 * 检查 oldpath 搜索权限 + newpath 目录写权限
 */
int handle_link_enter_end(Tracee *tracee, Reg olddirfd_sysarg, Reg oldpath_sysarg,
	Reg newdirfd_sysarg, Reg newpath_sysarg, Config *config)
{
	char oldpath[PATH_MAX];
	char newpath[PATH_MAX];
	char rel_oldpath[PATH_MAX];
	char rel_newpath[PATH_MAX];
	int ret;

	// 读取源路径
	ret = read_sysarg_path(tracee, oldpath, oldpath_sysarg, ORIGINAL);
	if (ret != 0)
		return ret;

	// 读取目标路径
	ret = read_sysarg_path(tracee, newpath, newpath_sysarg, ORIGINAL);
	if (ret != 0)
		return ret;

	// 获取源目录基路径
	ret = get_fd_path(tracee, rel_oldpath, olddirfd_sysarg, ORIGINAL);
	if (ret < 0)
		return ret;

	// 获取目标目录基路径
	ret = get_fd_path(tracee, rel_newpath, newdirfd_sysarg, ORIGINAL);
	if (ret < 0)
		return ret;

	// 源需要可搜索
	ret = check_dir_perms(tracee, 'r', oldpath, rel_oldpath, config);
	if (ret < 0)
		return ret;

	// 目标需要可写
	ret = check_dir_perms(tracee, 'w', newpath, rel_newpath, config);
	if (ret < 0)
		return ret;

	return 0;
}
