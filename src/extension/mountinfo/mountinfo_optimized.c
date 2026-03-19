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
 * Minimal version: Redirect /proc/<PID>/mountinfo to temp file for /data paths
 */

#include "extension/extension.h"
#include "syscall/sysnum.h"      /* Sysnum, PR_open, PR_openat */
#include "tracee/tracee.h"       /* Tracee */
#include <limits.h>              /* INT_MAX, PATH_MAX */
#include <linux/limits.h>        /* PATH_MAX */
#include <string.h>              /* strlen, strncmp, strcmp, strstr */
#include <stdlib.h>              /* strtol, realpath */
#include <stdio.h>               /* snprintf */
#include <unistd.h>              /* realpath */
#include <errno.h>               /* errno */

/**
 * 极简版 mountinfo 回调：拦截 open/openat 对 /proc/<PID>/mountinfo 的访问
 * 检测路径包含 /data 时，重定向到临时文件，解决 Caja/Nautilus 只读错误
 */
int mountinfo_callback(Extension *extension, ExtensionEvent event,
                       intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -EINVAL;

    switch (event) {
    case TRANSLATED_PATH: {
        Tracee *tracee = TRACEE(extension);
        if (tracee == NULL || data1 == 0)
            return 0;

        // 仅处理 open/openat 系统调用
        Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
        if (sysnum != PR_open && sysnum != PR_openat)
            return 0;

        char *path = (char *)data1;
        size_t path_len = strlen(path);
        const size_t mountinfo_suffix_len = 10; // "/mountinfo" 长度

        // 快速过滤：仅匹配 /proc/<PID>/mountinfo 格式路径
        if (path_len <= (6 + 1 + 10) ||          // 最小长度：/proc/1/mountinfo
            strncmp(path, "/proc/", 6) != 0 ||
            strcmp(path + path_len - mountinfo_suffix_len, "/mountinfo") != 0) {
            return 0;
        }

        // 解析 PID（/proc/ 与 /mountinfo 之间的数字）
        char *pid_end = NULL;
        long target_pid = strtol(path + 6, &pid_end, 10);
        if (pid_end != (path + path_len - mountinfo_suffix_len) ||
            target_pid <= 0 || target_pid > INT_MAX) {
            return 0;
        }

        // 解析真实路径，检查是否包含 /data（Android 根目录场景）
        char resolved_path[PATH_MAX] = {0};
        if (realpath(path, resolved_path) == NULL)
            return 0;

        // 包含 /data 时，重定向到 /tmp 下的临时文件
        if (strstr(resolved_path, "/data") != NULL) {
            char temp_path[PATH_MAX];
            // 生成唯一临时文件名：/tmp/mountinfo_<PID>
            snprintf(temp_path, PATH_MAX, "/tmp/mountinfo_%ld", target_pid);
            // 安全拷贝路径，避免缓冲区溢出
            strncpy(path, temp_path, PATH_MAX - 1);
            path[PATH_MAX - 1] = '\0';
        }

        return 0;
    }

    default:
        return 0;
    }
}
