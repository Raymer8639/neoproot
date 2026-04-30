#ifndef STATX_H
#define STATX_H

#include <stdbool.h>
#include <linux/stat.h>
#include "tracee/tracee.h"
#include "path/path.h"

/*
 * 传递给扩展的STATX_SYSCALL事件状态结构
 * 完全兼容原有ABI
 */
struct statx_syscall_state {
    /* 被statx的文件的host路径 */
    char host_path[PATH_MAX];

    /* 将要返回给tracee的statx结构
     * 扩展可在此填充额外数据
     * 修改后必须设置 updated_stats = true
     */
    struct statx statx_buf;

    /* 标记statx_buf已被修改，需要写回tracee */
    bool updated_stats;
};

int handle_statx_syscall(Tracee *tracee, bool from_sigsys);

#endif // STATX_H
