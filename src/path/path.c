/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2026 scicat
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
 */

#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>

#include "path/path.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/proc.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "build.h"
#include "compat.h"

// 安卓8+兼容配置
#define PROC_PATH_BUF_SIZE 64
#define PATH_SEP '/'
#define PATH_SEP_STR "/"
#ifndef O_PATH
#define O_PATH 010000000
#endif

static inline __attribute__((always_inline)) void safe_strcat(char *dest, size_t *dest_len, const char *src, size_t src_len)
{
    memcpy(dest + *dest_len, src, src_len);
    *dest_len += src_len;
    dest[*dest_len] = '\0';
}

int join_paths(int number_paths, char result[PATH_MAX], ...)
{
    va_list paths;
    size_t result_len = 0;
    int status = 0;

    result[0] = '\0';

    va_start(paths, result);
    for (int i = 0; i < number_paths; i++) {
        const char *path = va_arg(paths, const char *);
        if (__builtin_expect(path == NULL, 0))
            continue;

        const size_t path_len = strlen(path);
        if (__builtin_expect(path_len == 0, 0))
            continue;

        size_t new_len;
        if (result_len > 0 && result[result_len - 1] != PATH_SEP && path[0] != PATH_SEP) {
            new_len = result_len + path_len + 1;
            if (__builtin_expect(new_len + 1 >= PATH_MAX, 0)) {
                status = -ENAMETOOLONG;
                break;
            }
            safe_strcat(result, &result_len, PATH_SEP_STR, 1);
            safe_strcat(result, &result_len, path, path_len);
        }
        else if (result_len > 0 && result[result_len - 1] == PATH_SEP && path[0] == PATH_SEP) {
            new_len = result_len + path_len - 1;
            if (__builtin_expect(new_len + 1 >= PATH_MAX, 0)) {
                status = -ENAMETOOLONG;
                break;
            }
            safe_strcat(result, &result_len, path + 1, path_len - 1);
        }
        else {
            new_len = result_len + path_len;
            if (__builtin_expect(new_len + 1 >= PATH_MAX, 0)) {
                status = -ENAMETOOLONG;
                break;
            }
            safe_strcat(result, &result_len, path, path_len);
        }
    }
    va_end(paths);

    return status;
}

int which(Tracee *tracee, const char *paths, char host_path[PATH_MAX], const char *command)
{
    char path[PATH_MAX];
    const char *cursor;
    struct stat stat_buf;
    int status;
    bool is_explicit;
    bool found;
    char cwd_path[PATH_MAX];

    assert(command != NULL);
    is_explicit = (strchr(command, PATH_SEP) != NULL);

    status = realpath2(tracee, host_path, command, true);
    if (__builtin_expect(status == 0, 1) && stat(host_path, &stat_buf) == 0) {
        if (is_explicit && !S_ISREG(stat_buf.st_mode)) {
            note(tracee, ERROR, USER, "'%s' is not a regular file", command);
            return -EACCES;
        }
        if (is_explicit && (stat_buf.st_mode & S_IXUSR) == 0) {
            note(tracee, ERROR, USER, "'%s' is not executable", command);
            return -EACCES;
        }
        found = true;
        (void) realpath2(tracee, host_path, command, false);
    }
    else {
        found = false;
    }

    if (is_explicit) {
        return found ? 0 : -ENOENT;
    }

    paths = paths ?: getenv("PATH");
    if (__builtin_expect(paths == NULL || *paths == '\0', 0))
        goto not_found;

    cursor = paths;
    do {
        const size_t seg_len = strcspn(cursor, ":");
        const char *seg_start = cursor;
        cursor += seg_len + 1;

        if (__builtin_expect(seg_len >= PATH_MAX, 0))
            continue;

        if (seg_len == 0) {
            strcpy(path, ".");
        }
        else {
            memcpy(path, seg_start, seg_len);
            path[seg_len] = '\0';
        }

        const size_t cmd_len = strlen(command);
        if (__builtin_expect(seg_len + cmd_len + 2 >= PATH_MAX, 0))
            continue;

        path[seg_len] = PATH_SEP;
        memcpy(path + seg_len + 1, command, cmd_len);
        path[seg_len + 1 + cmd_len] = '\0';

        status = realpath2(tracee, host_path, path, true);
        if (__builtin_expect(status == 0, 0)
            && stat(host_path, &stat_buf) == 0
            && S_ISREG(stat_buf.st_mode)
            && (stat_buf.st_mode & S_IXUSR) != 0) {
            (void) realpath2(tracee, host_path, path, false);
            return 0;
        }
    } while (*(cursor - 1) != '\0');

not_found:
    status = getcwd2(tracee, cwd_path);
    if (status < 0)
        strcpy(cwd_path, "<unknown>");

    note(tracee, ERROR, USER, "'%s' not found (root = %s, cwd = %s, $PATH=%s)",
        command, get_root(tracee), cwd_path, paths);

    if (found && !is_explicit) {
        note(tracee, ERROR, USER,
            "to execute a local program, use the './' prefix, for example: ./%s", command);
    }

    return -1;
}

int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path, bool deref_final)
{
    int status;
    if (__builtin_expect(tracee == NULL, 0))
        status = (realpath(path, host_path) == NULL ? -errno : 0);
    else
        status = translate_path(tracee, host_path, AT_FDCWD, path, deref_final);
    return status;
}

// 安卓8+兼容：增强getcwd2，解决低版本getcwd失败问题
int getcwd2(Tracee *tracee, char guest_path[PATH_MAX])
{
    if (__builtin_expect(tracee == NULL, 0)) {
#ifdef __ANDROID__
        char *cwd = getcwd(guest_path, PATH_MAX);
        if (__builtin_expect(cwd != NULL, 1)) {
            return 0;
        }
        // 安卓8兼容：getcwd失败时，读取/proc/self/cwd（低版本可靠路径）
        char proc_cwd[PATH_MAX] = "/proc/self/cwd";
        ssize_t len = readlink(proc_cwd, guest_path, PATH_MAX - 1);
        if (len > 0 && len < PATH_MAX) {
            guest_path[len] = '\0';
            return 0;
        }
        // 降级到PWD或根目录
        const char *pwd = getenv("PWD");
        if (pwd != NULL && strlen(pwd) < PATH_MAX) {
            strcpy(guest_path, pwd);
            return 0;
        }
        strcpy(guest_path, "/");
        return 0;
#else
        if (getcwd(guest_path, PATH_MAX) == NULL)
            return -errno;
#endif
    }
    else {
        const size_t cwd_len = strlen(tracee->fs->cwd);
        if (__builtin_expect(cwd_len >= PATH_MAX, 0))
            return -ENAMETOOLONG;
        memcpy(guest_path, tracee->fs->cwd, cwd_len + 1);
    }
    return 0;
}

// 修复断言失败：处理长度1/2的边界情况（安卓8+全兼容）
void chop_finality(char *path)
{
    const size_t length = strlen(path);
    if (__builtin_expect(length < 1, 0))
        return;

    // 长度1（仅"/"）：不修改
    if (length == 1) {
        assert(path[0] == '/');
        return;
    }

    // 长度2（如"/."、"//"）：统一改为"/"
    if (length == 2) {
        if (path[1] == '.' || path[1] == '/') {
            path[1] = '\0';
        }
        return;
    }

    // 长度>=3：原有逻辑
    if (path[length - 1] == '.') {
        assert(length >= 2);
        if (length == 2) {
            path[length - 1] = '\0';
        }
        else {
            path[length - 2] = '\0';
        }
    }
    else if (path[length - 1] == PATH_SEP) {
        if (length > 1)
            path[length - 1] = '\0';
    }
}

int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX])
{
    char link[PROC_PATH_BUF_SIZE];
    int status;

    status = snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
    if (__builtin_expect(status < 0 || (size_t)status >= sizeof(link), 0))
        return -EBADF;

    status = readlink(link, path, PATH_MAX - 1);
    if (__builtin_expect(status < 0, 0))
        return -errno;
    if (__builtin_expect(status >= PATH_MAX, 0))
        return -ENAMETOOLONG;

    path[status] = '\0';
    return 0;
}

int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd,
        const char *user_path, bool deref_final)
{
    char guest_path[PATH_MAX];
    int status;

    if (user_path[0] == PATH_SEP) {
        strcpy(result, PATH_SEP_STR);
    }
    else if (dir_fd != AT_FDCWD) {
        status = readlink_proc_pid_fd(tracee->pid, dir_fd, result);
        if (__builtin_expect(status < 0, 0))
            return status;

        if (__builtin_expect(result[0] != PATH_SEP, 0))
            return -ENOTDIR;

        status = detranslate_path(tracee, result, NULL);
        if (__builtin_expect(status < 0, 0))
            return status;
    }
    else {
        status = getcwd2(tracee, result);
        if (__builtin_expect(status < 0, 0))
            return status;
    }

    VERBOSE(tracee, 2, "vpid %" PRIu64 ": translate(\"%s\" + \"%s\")",
        tracee != NULL ? tracee->vpid : 0, result, user_path);

    status = notify_extensions(tracee, GUEST_PATH, (intptr_t) result, (intptr_t) user_path);
    if (__builtin_expect(status < 0, 0))
        return status;
    if (__builtin_expect(status > 0, 0))
        goto skip;

    assert(result[0] == PATH_SEP);
    status = join_paths(2, guest_path, result, user_path);
    if (__builtin_expect(status < 0, 0))
        return status;

    strcpy(result, PATH_SEP_STR);
    status = canonicalize(tracee, guest_path, deref_final, result, 0);
    if (__builtin_expect(status < 0, 0))
        return status;

    status = substitute_binding(tracee, GUEST, result);
    if (__builtin_expect(status < 0, 0))
        return status;

skip:
    VERBOSE(tracee, 2, "vpid %" PRIu64 ":          -> \"%s\"",
        tracee != NULL ? tracee->vpid : 0, result);

    status = notify_extensions(tracee, TRANSLATED_PATH, (intptr_t) result, 0);
    if (__builtin_expect(status < 0, 0))
        return status;

    return 0;
}

int detranslate_path(Tracee *tracee, char path[PATH_MAX], const char t_referrer[PATH_MAX])
{
    size_t prefix_length;
    ssize_t new_length;
    bool sanity_check;
    bool follow_binding;

    const size_t path_len = strnlen(path, PATH_MAX);
    if (__builtin_expect(path_len >= PATH_MAX, 0))
        return -ENAMETOOLONG;

    if (path[0] != PATH_SEP)
        return 0;

    if (t_referrer != NULL) {
        Comparison comparison;
        sanity_check = false;
        follow_binding = false;

        comparison = compare_paths("/proc", t_referrer);
        if (comparison == PATH1_IS_PREFIX) {
            char proc_path[PATH_MAX];
            strcpy(proc_path, path);
            new_length = readlink_proc2(tracee, proc_path, t_referrer);
            if (__builtin_expect(new_length < 0, 0))
                return new_length;
            if (new_length != 0) {
                strcpy(path, proc_path);
                return new_length + 1;
            }
            follow_binding = true;
        }
        else if (!belongs_to_guestfs(tracee, t_referrer)) {
            const char *binding_referree = get_path_binding(tracee, HOST, path);
            const char *binding_referrer = get_path_binding(tracee, HOST, t_referrer);
            assert(binding_referrer != NULL);

            if (binding_referree != NULL) {
                comparison = compare_paths(binding_referree, binding_referrer);
                follow_binding = (comparison == PATHS_ARE_EQUAL);
            }
        }
    }
    else {
        sanity_check = true;
        follow_binding = true;
    }

    if (follow_binding) {
        switch (substitute_binding(tracee, HOST, path)) {
        case 0:
            return 0;
        case 1:
            return strlen(path) + 1;
        default:
            break;
        }
    }

    const char *root_path = get_root(tracee);
    switch (compare_paths(root_path, path)) {
    case PATH1_IS_PREFIX:
        prefix_length = strlen(root_path);
        if (prefix_length == 1)
            prefix_length = 0;
        new_length = path_len - prefix_length;
        memmove(path, path + prefix_length, new_length);
        path[new_length] = '\0';
        break;
    case PATHS_ARE_EQUAL:
        new_length = 1;
        strcpy(path, PATH_SEP_STR);
        break;
    default:
        if (sanity_check)
            return -EPERM;
        else
            return 0;
    }

    return new_length + 1;
}

bool belongs_to_guestfs(const Tracee *tracee, const char *host_path)
{
    const Comparison comparison = compare_paths(get_root(tracee), host_path);
    return (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX);
}

__attribute__((pure))
Comparison compare_paths2(const char *path1, size_t length1, const char *path2, size_t length2)
{
    size_t length_min;
    char sentinel;

#if defined DEBUG_OPATH
    assert(strlen(path1) == length1);
    assert(strlen(path2) == length2);
#endif
    assert(length1 > 0);
    assert(length2 > 0);

    if (path1[length1 - 1] == PATH_SEP)
        length1--;
    if (path2[length2 - 1] == PATH_SEP)
        length2--;

    if (length1 < length2) {
        length_min = length1;
        sentinel = path2[length_min];
    }
    else {
        length_min = length2;
        sentinel = path1[length_min];
    }

    if (sentinel != PATH_SEP && sentinel != '\0')
        return PATHS_ARE_NOT_COMPARABLE;

    const bool is_prefix = (strncmp(path1, path2, length_min) == 0);
    if (!is_prefix)
        return PATHS_ARE_NOT_COMPARABLE;

    if (length1 == length2)
        return PATHS_ARE_EQUAL;
    else if (length1 < length2)
        return PATH1_IS_PREFIX;
    else
        return PATH2_IS_PREFIX;
}

__attribute__((pure))
Comparison compare_paths(const char *path1, const char *path2)
{
    return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

typedef int (*foreach_fd_t)(const Tracee *tracee, int fd, char path[PATH_MAX]);

static int foreach_fd(const Tracee *tracee, foreach_fd_t callback)
{
    struct dirent *dirent;
    char path[PATH_MAX];
    char proc_fd_path[PROC_PATH_BUF_SIZE];
    int status;
    DIR *dirp;

    status = snprintf(proc_fd_path, sizeof(proc_fd_path), "/proc/%d/fd", tracee->pid);
    if (__builtin_expect(status < 0 || (size_t)status >= sizeof(proc_fd_path), 0))
        return 0;

    dirp = opendir(proc_fd_path);
    if (__builtin_expect(dirp == NULL, 0))
        return 0;

    while ((dirent = readdir(dirp)) != NULL) {
        char link_path[PROC_PATH_BUF_SIZE];
        if (dirent->d_name[0] == '.')
            continue;

        status = snprintf(link_path, sizeof(link_path), "%s/%s", proc_fd_path, dirent->d_name);
        if (__builtin_expect(status < 0 || (size_t)status >= sizeof(link_path), 0))
            continue;

        status = readlink(link_path, path, PATH_MAX - 1);
        if (__builtin_expect(status < 0 || status >= PATH_MAX, 0))
            continue;
        path[status] = '\0';

        if (path[0] != PATH_SEP)
            continue;

        status = callback(tracee, atoi(dirent->d_name), path);
        if (__builtin_expect(status < 0, 0))
            goto end;
    }
    status = 0;

end:
    closedir(dirp);
    return status;
}

static int list_open_fd_callback(const Tracee *tracee, int fd, char path[PATH_MAX])
{
    VERBOSE(tracee, 1, "pid %d: access to \"%s\" (fd %d) won't be translated until closed",
        tracee->pid, path, fd);
    return 0;
}

int list_open_fd(const Tracee *tracee)
{
    return foreach_fd(tracee, list_open_fd_callback);
}

size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_length,
            const char *new_prefix, size_t new_prefix_length)
{
    const size_t path_len = strlen(path);
    size_t new_length;

    assert(old_prefix_length < PATH_MAX);
    assert(new_prefix_length < PATH_MAX);

    if (new_prefix_length == 1) {
        new_length = path_len - old_prefix_length;
        if (new_length != 0) {
            memmove(path, path + old_prefix_length, new_length);
        }
        else {
            path[0] = PATH_SEP;
            new_length = 1;
        }
    }
    else if (old_prefix_length == 1) {
        new_length = new_prefix_length + path_len;
        if (__builtin_expect(new_length >= PATH_MAX, 0))
            return -ENAMETOOLONG;
        if (path_len > 1) {
            memmove(path + new_prefix_length, path, path_len);
            memcpy(path, new_prefix, new_prefix_length);
        }
        else {
            memcpy(path, new_prefix, new_prefix_length);
            new_length = new_prefix_length;
        }
    }
    else {
        new_length = path_len - old_prefix_length + new_prefix_length;
        if (__builtin_expect(new_length >= PATH_MAX, 0))
            return -ENAMETOOLONG;
        memmove(path + new_prefix_length,
            path + old_prefix_length,
            path_len - old_prefix_length);
        memcpy(path, new_prefix, new_prefix_length);
    }

    assert(new_length < PATH_MAX);
    path[new_length] = '\0';
    return new_length;
}