#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "tracee/reg.h"
#include "extension/fake_id0/open.h"
#include "extension/fake_id0/helper_functions.h"

/**
 * 处理 open / openat / creat
 * 创建 meta 文件或检查已有文件权限
 */
int handle_open_enter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg,
	Reg flags_sysarg, Reg mode_sysarg, Config *config)
{
	char orig_path[PATH_MAX];
	char rel_path[PATH_MAX];
	char meta_path[PATH_MAX];
	word_t flags;
	mode_t mode;
	int access_mode;
	int perms;
	int ret;

	// 读取路径
	ret = read_sysarg_path(tracee, orig_path, path_sysarg, CURRENT);
	if (ret != 0)
		return ret;

	// 获取 meta 路径
	ret = get_meta_path(orig_path, meta_path);
	if (ret < 0)
		return ret;

	// 获取 flags（IGNORE_SYSARG 表示 creat）
	if (flags_sysarg != IGNORE_SYSARG)
		flags = peek_reg(tracee, ORIGINAL, flags_sysarg);
	else
		flags = O_CREAT;

	// 无 meta 且不创建 → 直接放行
	if (path_exists(meta_path) != 0 && !(flags & O_CREAT))
		return 0;

	// 获取目录路径
	ret = get_fd_path(tracee, rel_path, fd_sysarg, CURRENT);
	if (ret < 0)
		return ret;

	// 需要创建文件
	if (flags & O_CREAT) {
		// 文件已存在 → 只检查权限
		if (path_exists(orig_path) == 0)
			goto check_perms;

		// 检查目录写权限
		ret = check_dir_perms(tracee, 'w', meta_path, rel_path, config);
		if (ret < 0)
			return ret;

		// 写 meta 文件
		mode = peek_reg(tracee, ORIGINAL, mode_sysarg);
		poke_reg(tracee, mode_sysarg, mode | 0700);
		return write_meta_file(meta_path, mode, config->euid, config->egid, 1, config);
	}

check_perms:
	// 检查目录可访问
	ret = check_dir_perms(tracee, 'r', meta_path, rel_path, config);
	if (ret < 0)
		return ret;

	// 检查访问权限
	perms = get_permissions(meta_path, config, 0);
	access_mode = flags & O_ACCMODE;

	if ((access_mode == O_WRONLY && !(perms & 2)) ||
	    (access_mode == O_RDONLY && !(perms & 4)) ||
	    (access_mode == O_RDWR && ((perms & 6) != 6))) {
		return -EACCES;
	}

	return 0;
}
