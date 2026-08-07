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

#define FORCE_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALIGNED __attribute__((aligned(8)))

#ifdef USERLAND
#define PREFIX ".proot.l2s."
#else
#define PREFIX ".l2s."
#endif
#define PREFIX_LEN (sizeof(PREFIX)-1)

#define DELETED_SUFFIX " (deleted)"
#define DELETED_SUFFIX_LEN (sizeof(DELETED_SUFFIX)-1)
#define MAX_LINK_SUFFIX 1000
#define SIZEOF_RELEVANT_STRUCT_STAT 72

static int decrement_link_count(Tracee *tracee, Reg sysarg);

static FORCE_INLINE int my_readlink(const char *link_path, char *buf, size_t buf_size) {
    if (UNLIKELY(!link_path || !buf || buf_size < 1)) return -EINVAL;
    ssize_t size = readlink(link_path, buf, buf_size - 1);
    if (UNLIKELY(size < 0)) return -errno;
    if (UNLIKELY((size_t)size >= buf_size - 1)) return -ENAMETOOLONG;
    buf[size] = '\0';
    return (int)size;
}

static FORCE_INLINE int parse_4digit(const char *s) {
    return (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
}

static FORCE_INLINE char* get_filename(char *path, size_t *out_len) {
    size_t len = strlen(path);
    char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (out_len) *out_len = len;
    return name;
}

static HOT int move_and_symlink_path(Tracee *restrict tracee, Reg src_sysarg, Reg dest_sysarg) {
    if (UNLIKELY(!tracee)) return -EINVAL;

    char original[PATH_MAX] ALIGNED;
    char intermediate[PATH_MAX] ALIGNED;
    char new_intermediate[PATH_MAX] ALIGNED;
    char final[PATH_MAX] ALIGNED;
    char new_final[PATH_MAX] ALIGNED;
    char dest_path[PATH_MAX] ALIGNED;
    struct stat statl;
    char *filename;
    const char *l2s_dir;
    size_t path_len, prefix_len;
    ssize_t size;
    int status, link_count, suffix = 1;
    bool first_link = true;

    size = read_string(tracee, original, peek_reg(tracee, CURRENT, src_sysarg), PATH_MAX);
    if (UNLIKELY(size < 0)) return size;
    if (UNLIKELY(size >= PATH_MAX)) return -ENAMETOOLONG;

    status = lstat(original, &statl);
    if (UNLIKELY(status < 0)) return -errno;
    if (UNLIKELY(S_ISDIR(statl.st_mode))) return -EPERM;

    if (S_ISLNK(statl.st_mode)) {
        status = my_readlink(original, intermediate, PATH_MAX);
        if (UNLIKELY(status < 0)) return status;
        filename = get_filename(intermediate, NULL);
        if (strncmp(filename, PREFIX, PREFIX_LEN) == 0)
            first_link = false;
    } else {
        filename = get_filename(original, &path_len);
        prefix_len = path_len - strlen(filename);
        l2s_dir = getenv("PROOT_L2S_DIR");
        if (LIKELY(l2s_dir && l2s_dir[0])) {
            size_t dir_len = strlen(l2s_dir);
            if (UNLIKELY(dir_len + 1 + PREFIX_LEN + strlen(filename) + 5 >= PATH_MAX))
                return -ENAMETOOLONG;
            strcpy(intermediate, l2s_dir);
            if (l2s_dir[dir_len - 1] != '/') strcat(intermediate, "/");
        } else {
            if (UNLIKELY(prefix_len + PREFIX_LEN + strlen(filename) + 5 >= PATH_MAX))
                return -ENAMETOOLONG;
            strncpy(intermediate, original, prefix_len);
            intermediate[prefix_len] = '\0';
        }
        strcat(intermediate, PREFIX);
        strcat(intermediate, filename);
    }

    if (LIKELY(first_link)) {
        do {
            snprintf(new_intermediate, PATH_MAX, "%s%04d", intermediate, suffix++);
        } while (access(new_intermediate, F_OK) != -1 && suffix < MAX_LINK_SUFFIX);
        strcpy(intermediate, new_intermediate);
        snprintf(final, PATH_MAX, "%s.0002", intermediate);
        status = rename(original, final);
        if (UNLIKELY(status < 0)) return -errno;
        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)original, (intptr_t)final);
        if (UNLIKELY(status < 0)) return status;
        status = symlink(final, intermediate);
        if (UNLIKELY(status < 0)) return -errno;
        status = symlink(intermediate, original);
        if (UNLIKELY(status < 0)) return -errno;
    } else {
        status = my_readlink(intermediate, final, PATH_MAX);
        if (UNLIKELY(status < 0)) return status;
        size_t final_len = strlen(final);
        link_count = parse_4digit(final + final_len - 4) + 1;
        strncpy(new_final, final, final_len - 4);
        snprintf(new_final + final_len - 4, 5, "%04d", link_count);
        status = rename(final, new_final);
        if (UNLIKELY(status < 0)) return -errno;
        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)final, (intptr_t)new_final);
        if (UNLIKELY(status < 0)) return status;
        strcpy(final, new_final);
        status = unlink(intermediate);
        if (UNLIKELY(status < 0)) return -errno;
        status = symlink(final, intermediate);
        if (UNLIKELY(status < 0)) return -errno;
    }

    status = read_path(tracee, dest_path, peek_reg(tracee, CURRENT, dest_sysarg));
    if (LIKELY(status >= 0)) {
        status = symlink(intermediate, dest_path);
        if (UNLIKELY(status < 0)) status = -errno;
    }
    if (UNLIKELY(status < 0)) {
        decrement_link_count(tracee, src_sysarg);
        return status;
    }
    poke_reg(tracee, SYSARG_RESULT, 0);
    set_sysnum(tracee, PR_void);
    return 0;
}

static HOT int decrement_link_count(Tracee *restrict tracee, Reg path_sysarg) {
    if (UNLIKELY(!tracee)) return -EINVAL;
    char original[PATH_MAX] ALIGNED;
    char intermediate[PATH_MAX] ALIGNED;
    char final[PATH_MAX] ALIGNED;
    char new_final[PATH_MAX] ALIGNED;
    struct stat statl;
    char *filename;
    size_t final_len;
    ssize_t size;
    int status, link_count;

    size = read_string(tracee, original, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
    if (UNLIKELY(size < 0)) return size;
    if (UNLIKELY(size >= PATH_MAX)) return -ENAMETOOLONG;

    status = lstat(original, &statl);
    if (UNLIKELY(status < 0 || !S_ISLNK(statl.st_mode))) return 0;

    status = my_readlink(original, intermediate, PATH_MAX);
    if (UNLIKELY(status < 0)) return status;
    filename = get_filename(intermediate, NULL);
    if (UNLIKELY(strncmp(filename, PREFIX, PREFIX_LEN) != 0)) return 0;

    status = my_readlink(intermediate, final, PATH_MAX);
    if (UNLIKELY(status < 0)) {
        VERBOSE(tracee, 1, "Skipping broken link2symlink \"%s\" -> \"%s\"", original, intermediate);
        return 0;
    }
    final_len = strlen(final);
    link_count = parse_4digit(final + final_len - 4) - 1;

    if (LIKELY(link_count > 0)) {
        strncpy(new_final, final, final_len - 4);
        snprintf(new_final + final_len - 4, 5, "%04d", link_count);
        status = rename(final, new_final);
        if (UNLIKELY(status < 0)) return -errno;
        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)final, (intptr_t)new_final);
        if (UNLIKELY(status < 0)) return status;
        strcpy(final, new_final);
        status = unlink(intermediate);
        if (UNLIKELY(status < 0)) return -errno;
        status = symlink(final, intermediate);
        if (UNLIKELY(status < 0)) return -errno;
    } else {
        status = unlink(intermediate);
        if (UNLIKELY(status < 0)) return -errno;
        status = unlink(final);
        if (UNLIKELY(status < 0)) return -errno;
        status = notify_extensions(tracee, LINK2SYMLINK_UNLINK, (intptr_t)final, 0);
        if (UNLIKELY(status < 0)) return status;
    }
    return 0;
}

static HOT int handle_sysexit_end(Tracee *restrict tracee) {
    if (UNLIKELY(!tracee)) return 0;
    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
    struct stat final_stat, statl;
    char original[PATH_MAX] ALIGNED, intermediate[PATH_MAX] ALIGNED, final[PATH_MAX] ALIGNED;
    char *filename;
    Reg stat_reg, path_reg;
    ssize_t size;
    int status;

#ifdef USERLAND
    if ((sysnum == PR_fstat || sysnum == PR_fstat64) && get_sysnum(tracee, CURRENT) == PR_readlinkat)
        return 0;
#endif
    if (UNLIKELY(result != 0)) return 0;

    switch (sysnum) {
    case PR_stat: case PR_lstat: case PR_stat64: case PR_lstat64:
        path_reg = SYSARG_1;
        stat_reg = SYSARG_2;
        break;
    case PR_fstatat64: case PR_newfstatat:
        path_reg = SYSARG_2;
        stat_reg = SYSARG_3;
        break;
    case PR_fstat: case PR_fstat64:
#ifndef USERLAND
        status = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, MODIFIED, SYSARG_1), original);
        if (UNLIKELY(status < 0)) {
            VERBOSE(tracee, 3, "link2symlink: readlink_proc_pid_fd failed, status=%d", status);
            return 0;
        }
        size_t plen = strlen(original);
        if (plen > DELETED_SUFFIX_LEN &&
            !strcmp(original + plen - DELETED_SUFFIX_LEN, DELETED_SUFFIX))
            original[plen - DELETED_SUFFIX_LEN] = '\0';
        stat_reg = SYSARG_2;
        break;
#else
        size = read_string(tracee, original, peek_reg(tracee, CURRENT, SYSARG_2), PATH_MAX);
        if (UNLIKELY(size < 0 || size >= PATH_MAX)) return size;
        stat_reg = SYSARG_2;
        break;
#endif
    default:
        return 0;
    }

    if (sysnum != PR_fstat && sysnum != PR_fstat64) {
        size = read_string(tracee, original, peek_reg(tracee, MODIFIED, path_reg), PATH_MAX);
        if (UNLIKELY(size < 0 || size >= PATH_MAX)) return size;
    }

    filename = get_filename(original, NULL);
    status = lstat(original, &statl);
    if (strncmp(filename, PREFIX, PREFIX_LEN) == 0) {
        if (S_ISLNK(statl.st_mode)) {
            strcpy(intermediate, original);
            goto proc_intermediate;
        } else {
            strcpy(final, original);
            goto proc_final;
        }
    }
    if (UNLIKELY(!S_ISLNK(statl.st_mode))) return 0;

    size = my_readlink(original, intermediate, PATH_MAX);
    if (UNLIKELY(size < 0)) return size;
    filename = get_filename(intermediate, NULL);
    if (UNLIKELY(strncmp(filename, PREFIX, PREFIX_LEN) != 0)) return 0;

proc_intermediate:
    size = my_readlink(intermediate, final, PATH_MAX);
    if (UNLIKELY(size < 0)) return size;

proc_final:
    status = lstat(final, &final_stat);
    if (UNLIKELY(status < 0)) return -errno;
    size_t final_len = strlen(final);
    final_stat.st_nlink = parse_4digit(final + final_len - 4);

#ifdef USERLAND
    read_data(tracee, &statl, peek_reg(tracee, ORIGINAL, stat_reg), sizeof(statl));
    final_stat.st_mode = statl.st_mode;
    final_stat.st_uid = statl.st_uid;
    final_stat.st_gid = statl.st_gid;
#endif

    // 64位环境，不再区分32/64
    size_t write_size = sizeof(final_stat);
    status = write_data(tracee, peek_reg(tracee, ORIGINAL, stat_reg), &final_stat, write_size);
    return UNLIKELY(status < 0) ? status : 0;
}

static FORCE_INLINE void link2symlink_handle_statx(struct statx_syscall_state *state) {
    if (UNLIKELY(!state || !(state->statx_buf.stx_mask & STATX_NLINK))) return;
    const char *name = strrchr(state->host_path, '/');
    if (UNLIKELY(!name)) return;
    size_t name_len = strlen(name);
    if (UNLIKELY(name_len < PREFIX_LEN + 6)) return;
    if (UNLIKELY(strncmp(name + 1, PREFIX, PREFIX_LEN) != 0)) return;
    if (UNLIKELY(name[name_len - 5] != '.')) return;
    if (UNLIKELY(!isdigit(name[name_len-4]) || !isdigit(name[name_len-3]) ||
                 !isdigit(name[name_len-2]) || !isdigit(name[name_len-1]))) return;
    state->statx_buf.stx_nlink = parse_4digit(name + name_len - 4);
}

/* 判断文件名是否为 link2symlink 内部文件名：
 *   .l2s.<name><NNNN>          （中间符号链接，数字前无点）
 *   .l2s.<name><NNNN>.0002    （最终真实文件）
 * <name> 本身可能含点（如 lib.d.ts），因此统一按“前缀 + 尾部 4 位数字”判断 */
static FORCE_INLINE bool is_l2s_internal_name(const char *name) {
    if (UNLIKELY(strncmp(name, PREFIX, PREFIX_LEN) != 0)) return false;
    size_t len = strlen(name);
    if (UNLIKELY(len < PREFIX_LEN + 5)) return false;   /* .l2s.xNNNN 为最短形态 */
    for (int i = 1; i <= 4; i++) {
        if (UNLIKELY(!isdigit((unsigned char)name[len - i]))) return false;
    }
    return true;
}

static FORCE_INLINE void translated_path(Tracee *restrict tracee, char *restrict translated_path) {
    if (UNLIKELY(!tracee || !translated_path)) return;
    Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
    bool is_readlink_syscall = false;
    switch (sysnum) {
    case PR_unlink: case PR_unlinkat: case PR_link: case PR_linkat:
    case PR_rename: case PR_renameat: case PR_renameat2:
        /* 这些 syscall 需要直接操作 .l2s 内部文件（decrement_link_count 等），不做任何改写 */
        return;
    case PR_readlink: case PR_readlinkat:
        /* readlink 应返回链接内容本身而非解析后的 final 路径（否则 EINVAL），
         * 但对 .l2s 内部路径仍需映射（见下） */
        is_readlink_syscall = true;
        break;
    default: break;
    }
    if (UNLIKELY(should_skip_file_access_due_to_f2fs_bug(tracee, translated_path))) return;

    char *filename = get_filename(translated_path, NULL);
    if (UNLIKELY(is_l2s_internal_name(filename))) {
        /* 进程可能通过 realpath/readlink 拿到 link2symlink 内部文件名后再次访问
         * （如 /.l2s.lib.d.ts0001.0002，典型场景：pnpm store + tsc/Node 解析真实路径）。
         * 此时翻译路径落在 rootfs 内而真实文件在 PROOT_L2S_DIR（可能在 rootfs 之外），
         * 需要映射回真实位置，否则 open/stat/readlink 会 ENOENT。
         * 翻译路径自身存在（L2S_DIR 未设置、文件在原目录）时无需映射。 */
        if (UNLIKELY(access(translated_path, F_OK) != 0)) {
            char alt[PATH_MAX] ALIGNED;
            const char *l2s_dir = getenv("PROOT_L2S_DIR");
            if (LIKELY(l2s_dir && l2s_dir[0] && strcmp(l2s_dir, "/") != 0)) {
                snprintf(alt, sizeof(alt), "%s/%s", l2s_dir, filename);
                if (LIKELY(access(alt, F_OK) == 0)) {
                    strcpy(translated_path, alt);
                    return;
                }
            }
            /* PROOT_L2S_DIR=/ 或变量不可见时的常见情况：文件位于 host 根目录 */
            snprintf(alt, sizeof(alt), "/%s", filename);
            if (LIKELY(access(alt, F_OK) == 0)) {
                strcpy(translated_path, alt);
                return;
            }
        }
        /* 翻译路径存在（同目录模式）或映射失败：readlink 返回链接内容，其余继续链解析 */
        if (is_readlink_syscall) return;
    } else if (is_readlink_syscall) {
        /* 普通路径上的 readlink 不做链解析，返回链接内容本身 */
        return;
    }

    char link_target[PATH_MAX] ALIGNED, final_target[PATH_MAX] ALIGNED;
    int status = my_readlink(translated_path, link_target, PATH_MAX);
    if (UNLIKELY(status < 0)) return;
    char *link_filename = get_filename(link_target, NULL);
    if (UNLIKELY(strncmp(link_filename, PREFIX, PREFIX_LEN) != 0)) return;
    status = my_readlink(link_target, final_target, PATH_MAX);
    if (UNLIKELY(status < 0)) return;
    strcpy(translated_path, final_target);
}

static FORCE_INLINE int handle_linkat_from_proc_fd(Tracee *restrict tracee) {
    if (UNLIKELY(!tracee)) return 0;
    char proc_path[128] ALIGNED;
    ssize_t size = read_string(tracee, proc_path, peek_reg(tracee, CURRENT, SYSARG_2), sizeof(proc_path));
    if (UNLIKELY(size <= 0 || size >= (ssize_t)sizeof(proc_path))) return 0;
    if (UNLIKELY(compare_paths(proc_path, "/proc") != PATH2_IS_PREFIX)) return 0;
    char target_path[PATH_MAX] ALIGNED;
    size = readlink(proc_path, target_path, sizeof(target_path));
    if (UNLIKELY(size < 10 || size >= (ssize_t)sizeof(target_path))) return 0;
    if (UNLIKELY(memcmp(&target_path[size - 10], DELETED_SUFFIX, 10) != 0)) return 0;
    struct stat statl;
    if (UNLIKELY(stat(proc_path, &statl) != 0 || !S_ISREG(statl.st_mode))) return 0;
    char dest_path[PATH_MAX] ALIGNED;
    size = read_string(tracee, dest_path, peek_reg(tracee, CURRENT, SYSARG_4), PATH_MAX);
    if (UNLIKELY(size < 0 || size >= PATH_MAX)) return 0;
    int src_fd = open(proc_path, O_RDONLY);
    if (UNLIKELY(src_fd < 0)) return 0;
    unlink(dest_path);
    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_EXCL, statl.st_mode & 0777);
    if (UNLIKELY(dest_fd < 0)) {
        int ret = -errno;
        close(src_fd);
        return ret;
    }
    char buf[4096] ALIGNED;
    ssize_t nread, nwrite, pos;
    while ((nread = read(src_fd, buf, sizeof(buf))) > 0) {
        pos = 0;
        while (pos < nread) {
            nwrite = write(dest_fd, buf + pos, nread - pos);
            if (UNLIKELY(nwrite <= 0)) {
                int ret = -errno;
                close(src_fd);
                close(dest_fd);
                return ret;
            }
            pos += nwrite;
        }
    }
    close(src_fd);
    close(dest_fd);
    return 1;
}

HOT int link2symlink_callback(Extension *extension, ExtensionEvent event,
                               intptr_t data1, intptr_t data2 UNUSED) {
    if (UNLIKELY(!extension)) return -EINVAL;
    Tracee *tracee = TRACEE(extension);
    int status;

    switch (event) {
    case SYSCALL_ENTER_END: {
        Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
        switch (sysnum) {
        case PR_rename:
            status = decrement_link_count(tracee, SYSARG_2);
            return UNLIKELY(status < 0) ? status : 0;
        case PR_renameat: case PR_renameat2:
            status = decrement_link_count(tracee, SYSARG_4);
            return UNLIKELY(status < 0) ? status : 0;
        case PR_unlink:
            status = decrement_link_count(tracee, SYSARG_1);
            return UNLIKELY(status < 0) ? status : 0;
        case PR_unlinkat:
            if ((peek_reg(tracee, CURRENT, SYSARG_3) & AT_REMOVEDIR) != 0)
                return 0;
            status = decrement_link_count(tracee, SYSARG_2);
            return UNLIKELY(status < 0) ? status : 0;
        case PR_link:
            status = move_and_symlink_path(tracee, SYSARG_1, SYSARG_2);
            return UNLIKELY(status < 0) ? status : 0;
        case PR_linkat:
            if (peek_reg(tracee, CURRENT, SYSARG_5) & AT_SYMLINK_FOLLOW) {
                status = handle_linkat_from_proc_fd(tracee);
                if (UNLIKELY(status < 0)) return status;
                if (status == 1) {
                    set_sysnum(tracee, PR_void);
                    poke_reg(tracee, SYSARG_RESULT, 0);
                    return 0;
                }
            }
            status = move_and_symlink_path(tracee, SYSARG_2, SYSARG_4);
            return UNLIKELY(status < 0) ? status : 0;
        default:
            return 0;
        }
    }
    case SYSCALL_EXIT_END:
        return handle_sysexit_end(tracee);
    case INITIALIZATION: {
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
    case GUEST_PATH: {
        /* .l2s 内部路径（readlink/realpath 泄漏回 guest 的 host 路径）在翻译前拦截：
         * 直接替换为 host 真实路径并跳过 rootfs 拼接/canonicalize（后者必然失败）。
         * 注意：绝对路径时 data1(result) 仅为 "/"，完整路径在 data2(user_path)；
         * 相对路径时 data1 为 cwd。因此基于 user_path 的 basename 判断，
         * 命中后把映射后的 host 绝对路径写入 result 并返回 1（跳过翻译）。
         * 同目录模式（文件在 rootfs 内）时映射目标不存在，走正常翻译路径。 */
        char *result = (char *)data1;
        char *user_path = (char *)data2;
        char *filename = get_filename(user_path, NULL);
        if (UNLIKELY(is_l2s_internal_name(filename))) {
            char alt[PATH_MAX] ALIGNED;
            const char *l2s_dir = getenv("PROOT_L2S_DIR");
            if (LIKELY(l2s_dir && l2s_dir[0] && strcmp(l2s_dir, "/") != 0)) {
                snprintf(alt, sizeof(alt), "%s/%s", l2s_dir, filename);
                if (LIKELY(access(alt, F_OK) == 0)) {
                    strcpy(result, alt);
                    return 1;
                }
            }
            /* PROOT_L2S_DIR=/ 或变量不可见时的常见情况：文件位于 host 根目录 */
            snprintf(alt, sizeof(alt), "/%s", filename);
            if (LIKELY(access(alt, F_OK) == 0)) {
                strcpy(result, alt);
                return 1;
            }
        }
        return 0;
    }
    case TRANSLATED_PATH:
        translated_path(tracee, (char *)data1);
        return 0;
    case STATX_SYSCALL:
        link2symlink_handle_statx((struct statx_syscall_state *)data1);
        return 0;
    case INHERIT_PARENT:
        return 1;
    case INHERIT_CHILD: {
        Extension *parent = (Extension *)data1;
        extension->filtered_sysnums = parent->filtered_sysnums;
        return 0;
    }
    case SIGSYS_OCC:
        if (get_sysnum(tracee, CURRENT) == PR_memfd_create)
            return handle_linkat_from_proc_fd(tracee);
        return 0;
    default:
        return 0;
    }
}