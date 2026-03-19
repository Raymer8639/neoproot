/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot / proot-scicat
 *
 * Copyright (C) 2026 scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the
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
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <talloc.h>

#include "path/binding.h"
#include "path/path.h"
#include "path/temp.h"
#include "cli/note.h"
#include "compat.h"

static int remove_placeholder(char *path) {
    struct stat statl;
    if (lstat(path, &statl) != 0)
        return 0;

    if (S_ISDIR(statl.st_mode))
        rmdir(path);
    else if (statl.st_size == 0)
        unlink(path);

    return 0;
}

static void set_placeholder_destructor(const char *path) {
    TALLOC_CTX *ctx = talloc_new(NULL);
    if (!ctx) return;

    char *copy = talloc_strdup(ctx, path);
    if (copy)
        talloc_set_destructor(copy, remove_placeholder);
}

mode_t build_glue(Tracee *tracee, const char *guest_path, char host_path[PATH_MAX], Finality finality) {
    Comparison cmp;
    bool in_glue;
    mode_t type, mode;
    int status;
    Binding *binding;

    assert(tracee != NULL);
    assert(guest_path != NULL);
    assert(host_path != NULL);
    assert(tracee->glue_type != 0);

    // 创建 glue 根目录
    if (!tracee->glue) {
        tracee->glue = create_temp_directory(NULL, tracee->tool_name);
        if (!tracee->glue) {
            note(tracee, ERROR, INTERNAL, "failed to create glue rootfs");
            return 0;
        }
        talloc_set_name_const(tracee->glue, "$glue");
    }

    // 判断是否在 glue 里面
    cmp = compare_paths(tracee->glue, host_path);
    in_glue = (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX);

    // 确定要创建的文件类型
    if (IS_FINAL(finality)) {
        type = tracee->glue_type;
        mode = in_glue ? 0755 : 0;
    } else {
        type = S_IFDIR;
        mode = 0755;
    }

    // 不污染宿主 rootfs
    if (getenv("PROOT_DONT_POLLUTE_ROOTFS") && !in_glue)
        goto create_glue_binding;

    // 创建目录或节点
    if (S_ISDIR(type))
        status = mkdir(host_path, mode);
    else
        status = mknod(host_path, mode | type, 0);

    // 成功：自动销毁空占位文件
    if (status == 0 && !in_glue)
        set_placeholder_destructor(host_path);

    // 已存在或最终节点，直接返回
    if (status == 0 || errno == EEXIST || IS_FINAL(finality))
        return type;

    // 在 glue 里失败，直接报错
    if (in_glue) {
        note(tracee, WARNING, SYSTEM, "failed to create glue path");
        return 0;
    }

create_glue_binding:
    // 路径过长检查
    if (strlen(tracee->glue) >= PATH_MAX || strlen(guest_path) >= PATH_MAX) {
        note(tracee, WARNING, INTERNAL, "path too long");
        return 0;
    }

    // 创建绑定：guest_path → glue
    binding = insort_binding3(tracee, tracee->glue, tracee->glue, guest_path);
    if (!binding)
        return 0;

    return type;
}
