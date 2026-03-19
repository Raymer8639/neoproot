/*
 * This file is part of proot-scicat.
 *
 * Copyright (C) 2026 Scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 *
 * Fixes: Caja/Nautilus "This destination is read-only" error on Android
 * Reason: File managers check /proc/<PID>/mountinfo, Android's / is read-only, replace /data with / as root mountpoint
 */

#include "extension/extension.h"
#include "path/path.h"           /* translate_path, compare_paths */
#include "path/temp.h"           /* create_temp_file */
#include "tracee/tracee.h"       /* get_tracee, Tracee */
#include "syscall/sysnum.h"      /* Sysnum, PR_open, PR_openat */
#include <limits.h>              /* INT_MAX, PATH_MAX */
#include <linux/limits.h>        /* PATH_MAX */
#include <string.h>              /* strlen, strcmp, strncmp, memcmp */
#include <stdio.h>               /* FILE, fopen, fclose, fwrite, fseek, SEEK_SET */
#include <stdlib.h>              /* free */
#include <errno.h>               /* errno */

/**
 * 检查并修改 /proc/<PID>/mountinfo 路径，伪造根目录挂载信息
 * @param tracee 进程追踪句柄
 * @param path 已翻译的路径（会被原地修改）
 */
static void mountinfo_check_open_path(Tracee *tracee, char path[PATH_MAX])
{
    if (tracee == NULL || path == NULL)
        return;

    const size_t min_len = 6 + 1 + 1 + 10; // /proc/[1]/mountinfo 最小长度
    const size_t mountinfo_suffix_len = 10;  // "/mountinfo" 长度
    size_t path_len = strlen(path);

    // 快速过滤：路径长度不足 或 不是 /proc/ 开头 或 不是以 /mountinfo 结尾
    if (path_len < min_len || strncmp(path, "/proc/", 6) != 0 ||
        strcmp(path + path_len - mountinfo_suffix_len, "/mountinfo") != 0) {
        return;
    }

    // 解析 PID（/proc/ 之后，/mountinfo 之前的部分）
    char *pid_end = NULL;
    const char *pid_str = path + 6;
    long target_pid = strtol(pid_str, &pid_end, 10);

    // PID 合法性校验：必须是有效数字，且 pid_end 刚好指向 /mountinfo 开头
    if (pid_end != (path + path_len - mountinfo_suffix_len) ||
        target_pid <= 0 || target_pid > INT_MAX) {
        return;
    }

    // 获取目标进程的 tracee 句柄
    Tracee *target_tracee = get_tracee(tracee, (pid_t)target_pid, false);
    if (target_tracee == NULL) {
        return;
    }

    // 翻译目标进程的根路径（宿主侧路径）
    char root_host_path[PATH_MAX] = {0};
    translate_path(target_tracee, root_host_path, AT_FDCWD, "/", true);
    if (strlen(root_host_path) == 0) {
        return;
    }

    // 仅处理根路径在 /data 下的场景（Android 典型场景）
    Comparison path_cmp = compare_paths(root_host_path, "/data");
    if (path_cmp != PATH2_IS_PREFIX && path_cmp != PATHS_ARE_EQUAL) {
        return;
    }

    // 打开真实的 /proc/<PID>/mountinfo
    FILE *real_mountinfo = fopen(path, "r");
    if (real_mountinfo == NULL) {
        return;
    }

    // 创建临时文件存储伪造的 mountinfo
    const char *temp_path = create_temp_file(tracee->ctx, "mountinfo");
    if (temp_path == NULL) {
        fclose(real_mountinfo);
        return;
    }

    FILE *fake_mountinfo = fopen(temp_path, "w");
    if (fake_mountinfo == NULL) {
        fclose(real_mountinfo);
        return;
    }

    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t line_len = 0;
    bool found_data_root = false;

    // 第一遍扫描：找到 /data 对应的根挂载行，替换为 /
    while ((line_len = getline(&line_buf, &line_buf_size, real_mountinfo)) > 0) {
        char *curr_ptr = line_buf;

        // 跳过前 4 列（mount ID, parent ID, major:minor, root）之前的列
        for (int col = 0; col < 4 && (curr_ptr - line_buf) < line_len; col++) {
            curr_ptr = strchr(curr_ptr, ' ');
            if (curr_ptr == NULL) {
                goto skip_line; // 格式异常，跳过该行
            }
            curr_ptr++; // 跳过空格，指向当前列内容
        }

        // 找到 root 列的结束位置（下一个空格）
        char *root_col_end = strchr(curr_ptr, ' ');
        if (root_col_end == NULL) {
            goto skip_line;
        }

        // 匹配 root 列为 /data 的行
        size_t root_col_len = root_col_end - curr_ptr;
        if (root_col_len == 5 && memcmp(curr_ptr, "/data", 5) == 0) {
            // 写入：保留前 4 列 + 替换 root 列为 / + 剩余列
            fwrite(line_buf, curr_ptr - line_buf, 1, fake_mountinfo);
            fputc('/', fake_mountinfo); // 替换 /data 为 /
            fwrite(root_col_end, line_len - (root_col_end - line_buf), 1, fake_mountinfo);
            found_data_root = true;
            break; // 找到后退出第一遍扫描
        }

skip_line:
        continue;
    }

    // 第二遍扫描：添加标准挂载（/dev, /proc, /sys, /tmp）
    if (found_data_root) {
        fseek(real_mountinfo, 0, SEEK_SET); // 重置文件指针到开头
        while ((line_len = getline(&line_buf, &line_buf_size, real_mountinfo)) > 0) {
            char *curr_ptr = line_buf;

            // 跳过前 4 列，定位到 root 列
            for (int col = 0; col < 4 && (curr_ptr - line_buf) < line_len; col++) {
                curr_ptr = strchr(curr_ptr, ' ');
                if (curr_ptr == NULL) {
                    goto skip_line2;
                }
                curr_ptr++;
            }

            // 找到 root 列结束位置
            char *root_col_end = strchr(curr_ptr, ' ');
            if (root_col_end == NULL) {
                goto skip_line2;
            }

            // 匹配需要保留的标准挂载路径
            size_t root_col_len = root_col_end - curr_ptr;
            bool is_standard_mount = false;

            if ((root_col_len == 4 && memcmp(curr_ptr, "/dev", 4) == 0) ||
                (root_col_len >= 5 && memcmp(curr_ptr, "/dev/", 5) == 0) ||
                (root_col_len == 5 && memcmp(curr_ptr, "/proc", 5) == 0) ||
                (root_col_len == 4 && memcmp(curr_ptr, "/sys", 4) == 0) ||
                (root_col_len >= 5 && memcmp(curr_ptr, "/sys/", 5) == 0) ||
                (root_col_len == 4 && memcmp(curr_ptr, "/tmp", 4) == 0)) {
                is_standard_mount = true;
            }

            // 写入标准挂载行
            if (is_standard_mount) {
                fwrite(line_buf, line_len, 1, fake_mountinfo);
            }

skip_line2:
            continue;
        }
    }

    // 资源清理
    free(line_buf);
    fclose(fake_mountinfo);
    fclose(real_mountinfo);

    // 重定向路径到伪造的临时文件
    if (found_data_root) {
        strncpy(path, temp_path, PATH_MAX - 1);
        path[PATH_MAX - 1] = '\0'; // 确保字符串终止
    }
}

/**
 * mountinfo 扩展核心回调函数
 * @param extension 扩展句柄
 * @param event 触发事件
 * @param data1 事件数据1（TRANSLATED_PATH 时为路径缓冲区）
 * @param data2 事件数据2（未使用）
 * @return 0-成功，非0-错误码
 */
int mountinfo_callback(Extension *extension, ExtensionEvent event,
                       intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -EINVAL;

    switch (event) {
    case TRANSLATED_PATH: {
        Tracee *tracee = TRACEE(extension);
        if (tracee == NULL)
            return 0;

        // 仅拦截 open/openat 系统调用的路径翻译
        Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
        if (sysnum == PR_open || sysnum == PR_openat) {
            mountinfo_check_open_path(tracee, (char *)data1);
        }
        return 0;
    }

    default:
        return 0;
    }
}
