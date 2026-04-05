#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>

#include "cli/note.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/statx.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "path/path.h"
#include "path/f2fs-bug.h"
#include "arch.h"
#include "attribute.h"

/* 链接文件前缀，区分USERLAND/非USERLAND环境 */
#ifdef USERLAND
#define PREFIX ".proot.l2s."
#else
#define PREFIX ".l2s."
#endif

#define DELETED_SUFFIX " (deleted)"
#define MAX_LINK_SUFFIX 1000
#define SIZEOF_RELEVANT_STRUCT_STAT 72

/* 前置函数声明 */
static int decrement_link_count(Tracee *tracee, Reg sysarg);

/**
 * 安全读取符号链接内容，自动补全终止符
 * @param link_path 符号链接路径
 * @param buf 输出缓冲区，至少PATH_MAX大小
 * @return 0-成功，非0-负的错误码
 */
static int my_readlink(const char link_path[PATH_MAX], char buf[PATH_MAX])
{
    if (link_path == NULL || buf == NULL)
        return -EINVAL;

    ssize_t size = readlink(link_path, buf, PATH_MAX);
    if (size < 0)
        return -errno;
    if (size >= PATH_MAX)
        return -ENAMETOOLONG;

    buf[size] = '\0';
    return 0;
}

/**
 * 移动原文件到中间路径，创建符号链接模拟硬链接
 * @param tracee 进程追踪句柄
 * @param src_sysarg 源路径参数寄存器
 * @param dest_sysarg 目标路径参数寄存器
 * @return 0-成功，非0-负的错误码
 */
static int move_and_symlink_path(Tracee *tracee, Reg src_sysarg, Reg dest_sysarg)
{
    if (tracee == NULL)
        return -EINVAL;

    char original[PATH_MAX] = {0};
    char intermediate[PATH_MAX] = {0};
    char new_intermediate[PATH_MAX] = {0};
    char final[PATH_MAX] = {0};
    char new_final[PATH_MAX] = {0};
    char *filename = NULL;
    const char *l2s_directory = NULL;
    struct stat statl = {0};
    ssize_t size;
    int status;
    int link_count;
    int first_link = 1;
    int suffix_counter = 1;

    /* 读取已规范化的源路径 */
    size = read_string(tracee, original, peek_reg(tracee, CURRENT, src_sysarg), PATH_MAX);
    if (size < 0)
        return size;
    if (size >= PATH_MAX)
        return -ENAMETOOLONG;

    /* 目录不支持硬链接模拟 */
    status = lstat(original, &statl);
    if (status < 0)
        return (errno > 0) ? -errno : -ENOENT;
    if (S_ISDIR(statl.st_mode))
        return -EPERM;

    /* 检查是否已经是l2s转换过的符号链接 */
    if (S_ISLNK(statl.st_mode)) {
        status = my_readlink(original, intermediate);
        if (status < 0)
            return status;

        filename = strrchr(intermediate, '/');
        filename = (filename == NULL) ? intermediate : (filename + 1);

        if (strncmp(filename, PREFIX, strlen(PREFIX)) == 0)
            first_link = 0;
    } else {
        /* 提取文件名，生成中间路径 */
        filename = strrchr(original, '/');
        filename = (filename == NULL) ? original : (filename + 1);

        l2s_directory = getenv("PROOT_L2S_DIR");
        if (l2s_directory != NULL && l2s_directory[0] != '\0') {
            size_t dir_len = strlen(l2s_directory);
            if (dir_len + 1 + strlen(PREFIX) + strlen(filename) + 5 >= PATH_MAX)
                return -ENAMETOOLONG;

            strcpy(intermediate, l2s_directory);
            if (l2s_directory[dir_len - 1] != '/') {
                strcat(intermediate, "/");
            }
        } else {
            size_t prefix_len = strlen(original) - strlen(filename);
            if (prefix_len + strlen(PREFIX) + strlen(filename) + 5 >= PATH_MAX)
                return -ENAMETOOLONG;

            strncpy(intermediate, original, prefix_len);
            intermediate[prefix_len] = '\0';
        }
        strcat(intermediate, PREFIX);
        strcat(intermediate, filename);
    }

    /* 首次创建硬链接：移动原文件，创建两级符号链接 */
    if (first_link) {
        /* 生成唯一的中间文件名，避免冲突 */
        do {
            snprintf(new_intermediate, PATH_MAX, "%s%04d", intermediate, suffix_counter);
            suffix_counter++;
        } while (access(new_intermediate, F_OK) != -1 && suffix_counter < MAX_LINK_SUFFIX);
        strcpy(intermediate, new_intermediate);

        /* 生成最终的带引用计数的文件路径 */
        snprintf(final, PATH_MAX, "%s.0002", intermediate);

        /* 移动原文件到最终路径 */
        status = rename(original, final);
        if (status < 0)
            return -errno;

        /* 通知其他扩展文件重命名事件 */
        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)original, (intptr_t)final);
        if (status < 0)
            return status;

        /* 中间链接 -> 最终文件 */
        status = symlink(final, intermediate);
        if (status < 0)
            return -errno;

        /* 原路径 -> 中间链接 */
        status = symlink(intermediate, original);
        if (status < 0)
            return -errno;
    }
    /* 已有硬链接，仅增加引用计数 */
    else {
        /* 读取最终文件路径，更新引用计数 */
        status = my_readlink(intermediate, final);
        if (status < 0)
            return status;

        link_count = atoi(final + strlen(final) - 4);
        link_count++;

        /* 生成新的带计数的文件名 */
        strncpy(new_final, final, strlen(final) - 4);
        snprintf(new_final + strlen(final) - 4, 5, "%04d", link_count);

        /* 重命名最终文件，更新计数 */
        status = rename(final, new_final);
        if (status < 0)
            return -errno;

        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)final, (intptr_t)new_final);
        if (status < 0)
            return status;

        strcpy(final, new_final);

        /* 更新中间链接指向新的最终文件 */
        status = unlink(intermediate);
        if (status < 0)
            return -errno;

        status = symlink(final, intermediate);
        if (status < 0)
            return -errno;
    }

    /* 处理目标路径的符号链接创建 */
    char dest_path[PATH_MAX] = {0};
    status = read_path(tracee, dest_path, peek_reg(tracee, CURRENT, dest_sysarg));
    if (status >= 0) {
        status = symlink(intermediate, dest_path);
        if (status < 0)
            status = -errno;
    }

    /* 创建目标链接失败，回滚引用计数 */
    if (status < 0) {
        decrement_link_count(tracee, src_sysarg);
        return status;
    }

    /* 标记系统调用已处理，无需内核执行 */
    poke_reg(tracee, SYSARG_RESULT, 0);
    set_sysnum(tracee, PR_void);

    return 0;
}

/**
 * 处理链接删除，递减引用计数，无引用时清理文件
 * @param tracee 进程追踪句柄
 * @param path_sysarg 待删除路径的参数寄存器
 * @return 0-成功，非0-负的错误码
 */
static int decrement_link_count(Tracee *tracee, Reg path_sysarg)
{
    if (tracee == NULL)
        return -EINVAL;

    char original[PATH_MAX] = {0};
    char intermediate[PATH_MAX] = {0};
    char final[PATH_MAX] = {0};
    char new_final[PATH_MAX] = {0};
    char *filename = NULL;
    struct stat statl = {0};
    ssize_t size;
    int status;
    int link_count;

    /* 读取已规范化的路径 */
    size = read_string(tracee, original, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
    if (size < 0)
        return size;
    if (size >= PATH_MAX)
        return -ENAMETOOLONG;

    /* 仅处理符号链接 */
    status = lstat(original, &statl);
    if (status < 0 || !S_ISLNK(statl.st_mode))
        return 0;

    /* 读取链接目标，检查是否是l2s生成的链接 */
    status = my_readlink(original, intermediate);
    if (status < 0)
        return status;

    filename = strrchr(intermediate, '/');
    filename = (filename == NULL) ? intermediate : (filename + 1);
    if (strncmp(filename, PREFIX, strlen(PREFIX)) != 0)
        return 0;

    /* 读取中间链接的最终目标 */
    status = my_readlink(intermediate, final);
    if (status < 0) {
        VERBOSE(tracee, 1, "Skipping broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
        return 0;
    }

    /* 解析并递减引用计数 */
    link_count = atoi(final + strlen(final) - 4);
    link_count--;

    /* 仍有引用，仅更新计数 */
    if (link_count > 0) {
        strncpy(new_final, final, strlen(final) - 4);
        snprintf(new_final + strlen(final) - 4, 5, "%04d", link_count);

        status = rename(final, new_final);
        if (status < 0)
            return -errno;

        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)final, (intptr_t)new_final);
        if (status < 0)
            return status;

        strcpy(final, new_final);

        /* 更新中间链接 */
        status = unlink(intermediate);
        if (status < 0)
            return -errno;

        status = symlink(final, intermediate);
        if (status < 0)
            return -errno;
    }
    /* 无剩余引用，清理所有相关文件 */
    else {
        status = unlink(intermediate);
        if (status < 0)
            return -errno;

        status = unlink(final);
        if (status < 0)
            return -errno;

        status = notify_extensions(tracee, LINK2SYMLINK_UNLINK, (intptr_t)final, 0);
        if (status < 0)
            return status;
    }

    return 0;
}

/**
 * 处理stat系列系统调用退出，修改stat结构，让软链接模拟出硬链接的链接数和inode表现
 * @param tracee 进程追踪句柄
 * @return 0-成功，非0-负的错误码
 */
static int handle_sysexit_end(Tracee *tracee)
{
    if (tracee == NULL)
        return 0;

    word_t sysnum = get_sysnum(tracee, ORIGINAL);

#ifdef USERLAND
    /* USERLAND下fstat已由fake_id0处理，跳过 */
    if ((get_sysnum(tracee, CURRENT) == PR_fstat) || (get_sysnum(tracee, CURRENT) == PR_fstat64))
        return 0;
    if (((sysnum == PR_fstat) || (sysnum == PR_fstat64)) && (get_sysnum(tracee, CURRENT) == PR_readlinkat))
        return 0;
#endif

    switch (sysnum) {
    case PR_fstatat64:
    case PR_newfstatat:
    case PR_stat64:
    case PR_lstat64:
    case PR_fstat64:
    case PR_stat:
    case PR_lstat:
    case PR_fstat: {
        word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        Reg stat_sysarg, path_sysarg;
        int status;
        struct stat statl = {0};
        struct stat final_stat = {0};
        ssize_t size;
        char original[PATH_MAX] = {0};
        char intermediate[PATH_MAX] = {0};
        char final[PATH_MAX] = {0};
        char *filename = NULL;

        /* 仅处理系统调用成功的情况 */
        if (result != 0)
            return 0;

        /* 读取目标文件路径 */
        if (sysnum == PR_fstat64 || sysnum == PR_fstat) {
#ifndef USERLAND
            /* 非USERLAND环境，从fd读取路径 */
            status = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, MODIFIED, SYSARG_1), original);
            if (status < 0) {
                VERBOSE(tracee, 3, "link2symlink: readlink_proc_pid_fd failed, status=%d", status);
                return 0;
            }
            /* 处理已删除文件的路径后缀 */
            size_t path_len = strlen(original);
            if (path_len > strlen(DELETED_SUFFIX) &&
                strcmp(original + path_len - strlen(DELETED_SUFFIX), DELETED_SUFFIX) == 0) {
                original[path_len - strlen(DELETED_SUFFIX)] = '\0';
            }
#endif
#ifdef USERLAND
            size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_2), PATH_MAX);
            if (size < 0)
                return size;
            if (size >= PATH_MAX)
                return -ENAMETOOLONG;
#endif
        } else {
            path_sysarg = (sysnum == PR_fstatat64 || sysnum == PR_newfstatat) ? SYSARG_2 : SYSARG_1;
            size = read_string(tracee, original, peek_reg(tracee, MODIFIED, path_sysarg), PATH_MAX);
            if (size < 0)
                return size;
            if (size >= PATH_MAX)
                return -ENAMETOOLONG;
        }

        /* 提取文件名，检查是否是l2s相关文件 */
        filename = strrchr(original, '/');
        filename = (filename == NULL) ? original : (filename + 1);

        status = lstat(original, &statl);
        /* 路径本身就是l2s前缀的中间/最终文件 */
        if (strncmp(filename, PREFIX, strlen(PREFIX)) == 0) {
            if (S_ISLNK(statl.st_mode)) {
                strcpy(intermediate, original);
                goto intermediate_proc;
            } else {
                strcpy(final, original);
                goto final_proc;
            }
        }

        /* 非符号链接，无需处理 */
        if (!S_ISLNK(statl.st_mode))
            return 0;

        /* 读取链接目标，检查是否是l2s链接 */
        size = my_readlink(original, intermediate);
        if (size < 0)
            return size;

        filename = strrchr(intermediate, '/');
        filename = (filename == NULL) ? intermediate : (filename + 1);
        if (strncmp(filename, PREFIX, strlen(PREFIX)) != 0)
            return 0;

        /* 读取最终文件路径 */
intermediate_proc:
        size = my_readlink(intermediate, final);
        if (size < 0)
            return size;

        /* 读取最终文件的stat信息，更新链接计数 */
final_proc:
        status = lstat(final, &final_stat);
        if (status < 0)
            return -errno;

        /* 用文件名中的计数覆盖st_nlink，模拟硬链接数 */
        final_stat.st_nlink = atoi(final + strlen(final) - 4);

        /* 获取stat结构的目标地址 */
        if (sysnum == PR_fstatat64 || sysnum == PR_newfstatat)
            stat_sysarg = SYSARG_3;
        else
            stat_sysarg = SYSARG_2;

#ifdef USERLAND
        /* USERLAND环境保留原有的uid/gid/mode，仅覆盖链接数 */
        (void)read_data(tracee, &statl, peek_reg(tracee, ORIGINAL, stat_sysarg), sizeof(statl));
        final_stat.st_mode = statl.st_mode;
        final_stat.st_uid = statl.st_uid;
        final_stat.st_gid = statl.st_gid;
#endif

        /* 写回修改后的stat结构，兼容32on64模式 */
        size_t write_size = is_32on64_mode(tracee) ? SIZEOF_RELEVANT_STRUCT_STAT : sizeof(final_stat);
        status = write_data(tracee, peek_reg(tracee, ORIGINAL, stat_sysarg), &final_stat, write_size);
        if (status < 0)
            return status;

        return 0;
    }

    default:
        return 0;
    }
}

/**
 * 处理statx系统调用，更新链接计数字段
 * @param state statx系统调用状态结构体
 */
static void link2symlink_handle_statx(struct statx_syscall_state *state)
 {
     if (state == NULL)  // 仅保留对state本身的空指针校验
         return;

    /* 仅当请求了链接数字段时处理 */
    if (!(state->statx_buf.stx_mask & STATX_NLINK))
        return;

    const char *path_ending = strrchr(state->host_path, '/');
    if (path_ending == NULL)
        return;

    size_t ending_len = strlen(path_ending);
    /* 最短路径要求：/ + 前缀 + .0000 */
    if (ending_len < strlen(PREFIX) + 6)
        return;

    /* 检查前缀和计数后缀格式 */
    if (strncmp(path_ending + 1, PREFIX, strlen(PREFIX)) != 0)
        return;
    if (path_ending[ending_len - 5] != '.')
        return;

    /* 检查后缀是否为4位数字 */
    for (size_t i = 1; i <= 4; i++) {
        if (!isdigit(path_ending[ending_len - i]))
            return;
    }

    /* 用文件名中的计数覆盖stx_nlink */
    state->statx_buf.stx_nlink = atoi(&path_ending[ending_len - 4]);
}

/**
 * 路径翻译回调，将l2s符号链接路径替换为真实文件路径
 * @param tracee 进程追踪句柄
 * @param translated_path 已翻译的路径，会被原地修改
 */
static void translated_path(Tracee *tracee, char translated_path[PATH_MAX])
{
    if (tracee == NULL || translated_path == NULL)
        return;

    char link_target[PATH_MAX] = {0};
    char final_target[PATH_MAX] = {0};
    char *filename = NULL;
    int status;

    /* 链接/删除/重命名相关系统调用，不翻译路径，避免破坏计数逻辑 */
    Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    case PR_unlink:
    case PR_unlinkat:
    case PR_link:
    case PR_linkat:
    case PR_rename:
    case PR_renameat:
    case PR_renameat2:
        return;
    default:
        break;
    }

    /* 跳过f2fs bug相关的路径 */
    if (should_skip_file_access_due_to_f2fs_bug(tracee, translated_path))
        return;

    /* 读取符号链接目标 */
    status = my_readlink(translated_path, link_target);
    if (status < 0)
        return;

    /* 检查是否是l2s中间链接 */
    filename = strrchr(link_target, '/');
    filename = (filename == NULL) ? link_target : (filename + 1);
    if (strncmp(filename, PREFIX, strlen(PREFIX)) != 0)
        return;

    /* 读取最终的真实文件路径 */
    status = my_readlink(link_target, final_target);
    if (status < 0)
        return;

    /* 替换为真实文件路径 */
    strcpy(translated_path, final_target);
}

/**
 * 处理特殊场景：linkat从/proc/pid/fd/创建硬链接（已删除的文件）
 * @param tracee 进程追踪句柄
 * @return 1-已处理完成，0-非目标场景，<0-错误码
 */
static int handle_linkat_from_proc_fd(Tracee *tracee)
{
    if (tracee == NULL)
        return 0;

    char proc_path[128] = {0};
    ssize_t size = read_string(tracee, proc_path, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(proc_path));
    if (size <= 0 || size >= (ssize_t)sizeof(proc_path))
        return 0;

    /* 仅处理/proc开头的路径 */
    if (compare_paths(proc_path, "/proc") != PATH2_IS_PREFIX)
        return 0;

    /* 检查是否指向已删除的文件 */
    char target_path[PATH_MAX] = {0};
    int status = readlink(proc_path, target_path, sizeof(target_path));
    if (status < 10 || status >= (ssize_t)sizeof(target_path))
        return 0;
    if (memcmp(&target_path[status - 10], DELETED_SUFFIX, 10) != 0)
        return 0;

    /* 检查是否是常规文件 */
    struct stat statl = {0};
    if (stat(proc_path, &statl) != 0 || !S_ISREG(statl.st_mode))
        return 0;

    /* 读取目标路径 */
    char dest_path[PATH_MAX] = {0};
    size = read_string(tracee, dest_path, peek_reg(tracee, CURRENT, SYSARG_4), PATH_MAX);
    if (size < 0 || size >= PATH_MAX)
        return 0;

    /* 打开源文件 */
    int source_fd = open(proc_path, O_RDONLY);
    if (source_fd < 0)
        return 0;

    /* 点无返回：后续任何错误都必须返回错误码，不能回退到原逻辑 */
    unlink(dest_path);

    /* 创建目标文件 */
    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_EXCL, statl.st_mode & 0777);
    if (dest_fd < 0) {
        status = -errno;
        close(source_fd);
        return (status < 0) ? status : -EPERM;
    }

    /* 复制文件内容 */
    char buf[4096];
    ssize_t nread, nwrite, pos;
    while ((nread = read(source_fd, buf, sizeof(buf))) != 0) {
        if (nread < 0) {
            status = -errno;
            close(source_fd);
            close(dest_fd);
            return (status < 0) ? status : -EPERM;
        }

        pos = 0;
        while (pos < nread) {
            nwrite = write(dest_fd, buf + pos, nread - pos);
            if (nwrite <= 0) {
                status = -errno;
                close(source_fd);
                close(dest_fd);
                return (status < 0) ? status : -EPERM;
            }
            pos += nwrite;
        }
    }

    /* 处理完成 */
    close(source_fd);
    close(dest_fd);
    return 1;
}

/**
 * link2symlink扩展核心回调函数，处理各类生命周期与系统调用事件
 * @param extension 扩展句柄
 * @param event 触发的事件类型
 * @param data1 事件附加数据1
 * @param data2 事件附加数据2
 * @return 0-成功，非0-错误码
 */
int link2symlink_callback(Extension *extension, ExtensionEvent event,
                          intptr_t data1, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -EINVAL;

    int status;
    switch (event) {
    case INITIALIZATION: {
        /* 注册需要处理的系统调用列表 */
        static const FilteredSysnum filtered_sysnums[] = {
            { PR_link,        FILTER_SYSEXIT },
            { PR_linkat,      FILTER_SYSEXIT },
            { PR_unlink,      FILTER_SYSEXIT },
            { PR_unlinkat,    FILTER_SYSEXIT },
            { PR_fstat,       FILTER_SYSEXIT },
            { PR_fstat64,     FILTER_SYSEXIT },
            { PR_fstatat64,   FILTER_SYSEXIT },
            { PR_lstat,       FILTER_SYSEXIT },
            { PR_lstat64,     FILTER_SYSEXIT },
            { PR_newfstatat,  FILTER_SYSEXIT },
            { PR_stat,        FILTER_SYSEXIT },
            { PR_stat64,      FILTER_SYSEXIT },
            { PR_rename,      FILTER_SYSEXIT },
            { PR_renameat,    FILTER_SYSEXIT },
            { PR_renameat2,   FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = (FilteredSysnum *)filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        Tracee *tracee = TRACEE(extension);
        Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

        switch (sysnum) {
        case PR_rename:
            /* 重命名目标路径，处理链接计数 */
            status = decrement_link_count(tracee, SYSARG_2);
            if (status < 0)
                return status;
            break;

        case PR_renameat:
        case PR_renameat2:
            /* 重命名目标路径，处理链接计数 */
            status = decrement_link_count(tracee, SYSARG_4);
            if (status < 0)
                return status;
            break;

        case PR_unlink:
            /* 删除文件，处理链接计数递减 */
            status = decrement_link_count(tracee, SYSARG_1);
            if (status < 0)
                return status;
            break;

        case PR_unlinkat:
            /* 跳过目录删除，仅处理文件 */
            if ((peek_reg(tracee, CURRENT, SYSARG_3) & AT_REMOVEDIR) != 0)
                return 0;
            /* 删除文件，处理链接计数递减 */
            status = decrement_link_count(tracee, SYSARG_2);
            if (status < 0)
                return status;
            break;

        case PR_link:
            /* 硬链接转符号链接 */
            status = move_and_symlink_path(tracee, SYSARG_1, SYSARG_2);
            if (status < 0)
                return status;
            break;

        case PR_linkat:
            /* 处理/proc/fd的特殊硬链接场景 */
            if (peek_reg(tracee, CURRENT, SYSARG_5) & AT_SYMLINK_FOLLOW) {
                status = handle_linkat_from_proc_fd(tracee);
                if (status < 0)
                    return status;
                if (status == 1) {
                    set_sysnum(tracee, PR_void);
                    poke_reg(tracee, SYSARG_RESULT, 0);
                    return 0;
                }
            }
            /* 常规硬链接转符号链接 */
            status = move_and_symlink_path(tracee, SYSARG_2, SYSARG_4);
            if (status < 0)
                return status;
            break;

        default:
            break;
        }
        return 0;
    }

    case SYSCALL_EXIT_END:
        return handle_sysexit_end(TRACEE(extension));

    case TRANSLATED_PATH:
        translated_path(TRACEE(extension), (char *)data1);
        return 0;

    case STATX_SYSCALL:
        link2symlink_handle_statx((struct statx_syscall_state *)data1);
        return 0;

    default:
        return 0;
    }
}
