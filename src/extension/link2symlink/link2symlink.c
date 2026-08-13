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
#include "path/binding.h"
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
/* final 编号（%04d）上限：9999 = 数据本体 1 + 链接数 9998。
 * 超限（第 9999 个链接）时 %04d 溢出为 5 位，parse_4digit 取尾 4 位
 * 错乱（0000→0）→ 后续 unlink 误判计数归零删数据——必须提前拒绝。
 * 返回 -EMLINK（与真硬链接超限同 errno），pnpm 等会自动 fallback copy。 */
#define MAX_LINK_COUNT 9999
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
        struct stat l2s_st;
        do {
            snprintf(new_intermediate, PATH_MAX, "%s%04d", intermediate, suffix++);
        } while (lstat(new_intermediate, &l2s_st) == 0 && suffix < MAX_LINK_SUFFIX);
        /* 用 lstat（不跟随）替代 access：access 跟随 symlink，旧残留断链
         * （.l2s.xxxNNNN → 不存在的 final）会被误判为"名字可用"，随后
         * symlink 报 EEXIST（symlink 不跟随，能看见断链本身） */
        strcpy(intermediate, new_intermediate);
        snprintf(final, PATH_MAX, "%s.0002", intermediate);
        status = rename(original, final);
        if (UNLIKELY(status < 0)) {
            /* 并发竞态：pnpm 多 worker 同时 link 同一 store 文件（内容寻址，
             * 多包共享同内容）。数据已被其他 worker rename 走（同 hash 链
             * 已建好）→ 直接把 dest 链接到已存在的中间链接，链内容相同安全 */
            if (errno == ENOENT) {
                status = read_path(tracee, dest_path, peek_reg(tracee, CURRENT, dest_sysarg));
                if (LIKELY(status >= 0) && lstat(intermediate, &l2s_st) == 0) {
                    status = symlink(intermediate, dest_path);
                    if (LIKELY(status == 0)) {
                        poke_reg(tracee, SYSARG_RESULT, 0);
                        set_sysnum(tracee, PR_void);
                        return 0;
                    }
                }
            }
            return -errno;
        }
        status = notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)original, (intptr_t)final);
        if (UNLIKELY(status < 0)) return status;
        status = symlink(final, intermediate);
        if (UNLIKELY(status < 0)) {
            if (errno == EEXIST) {
                /* 并发或残留：中间链接名已存在。检查它是否可用：
                 * lstat 确认存在 + readlink 目标存在 → 复用（同 hash 内容相同）；
                 * 断链（目标不存在）→ 删除重建 */
                char existing[PATH_MAX] ALIGNED;
                if (lstat(intermediate, &l2s_st) == 0 &&
                    my_readlink(intermediate, existing, PATH_MAX) >= 0 &&
                    access(existing, F_OK) == 0) {
                    /* 有效链：复用。数据同 hash 内容相同（我们的 rename
                     * 覆盖同内容无害）。重建 original 链接 + dest 链接 */
                    if (access(original, F_OK) != 0)
                        symlink(intermediate, original);
                    status = read_path(tracee, dest_path, peek_reg(tracee, CURRENT, dest_sysarg));
                    if (LIKELY(status >= 0)) {
                        status = symlink(intermediate, dest_path);
                        if (LIKELY(status == 0)) {
                            poke_reg(tracee, SYSARG_RESULT, 0);
                            set_sysnum(tracee, PR_void);
                            return 0;
                        }
                    }
                } else {
                    /* 断链残留：删除后重建自己的链 */
                    unlink(intermediate);
                    if (symlink(final, intermediate) == 0) {
                        status = symlink(intermediate, original);
                        if (UNLIKELY(status < 0 && errno != EEXIST)) return -errno;
                        goto dest_link;
                    }
                }
            }
            return -errno;
        }
        status = symlink(intermediate, original);
        if (UNLIKELY(status < 0 && errno != EEXIST)) return -errno;
    } else {
        status = my_readlink(intermediate, final, PATH_MAX);
        if (UNLIKELY(status < 0)) return status;
        size_t final_len = strlen(final);
        link_count = parse_4digit(final + final_len - 4) + 1;
        /* 编号溢出保护：链接数到顶（第 9999 个链接会写出 5 位编号）
         * → 拒绝并返回 EMLINK，让调用方（pnpm）fallback 到复制模式 */
        if (UNLIKELY(link_count > MAX_LINK_COUNT))
            return -EMLINK;
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

dest_link:
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

/* open/execve 物化（tsgo/tsc 7.0 兼容，方案 C）：
 * 被 open/exec 的路径若是 link2symlink 链（symlink -> 中间链接 -> final 数据文件），
 * 在 canonicalize 解析链之前把数据【复制】到目标路径（普通文件副本，保留权限），
 * 数据仍保留在 final（.l2s 目录），store 链永远完整：
 *
 *   物化前：exec路径[symlink] -> 中间链接[symlink] -> final（数据）
 *   物化后：exec路径[普通文件=副本]    final 仍持有数据（store 链原样）
 *
 * 这样 tsgo 用 O_PATH + readlink(/proc/self/fd/N) 解析自身路径时得到真实的
 * node_modules 路径（而非 /.l2s/...），dirname 下找 lib.d.ts 恢复正常。
 * 幂等：目标已是普通文件时直接跳过（并发 exec / 多级 shebang 安全）。
 * 空间：副本多一份（仅限被物化的文件）；不用 rename 移动——若目标随后被删除
 * （如 pnpm 重建 node_modules），移动会丢掉唯一数据副本导致 store 链断
 * （ERR_PNPM_ENOENT 根因），复制则数据永在 .l2s。 */
static FORCE_INLINE int materialize_executable(Tracee *restrict tracee, char *path) {
    if (UNLIKELY(!tracee || !path)) return 0;
    struct stat statl;
    char intermediate[PATH_MAX] ALIGNED, final[PATH_MAX] ALIGNED;
    char *filename;
    int status;

    /* 链起点判断用 readlink（不用 lstat）：嵌套环境下外层 proot 的
     * link2symlink 会把 lstat 的链路径解析成 .l2s 内部名并拒绝（EPERM），
     * 而 readlink 返回链接内容本身，任何环境下都可靠。
     * readlink 失败 = 普通文件（已物化/无关）或不存在 → 跳过（幂等）。 */
    status = my_readlink(path, intermediate, PATH_MAX);
    if (UNLIKELY(status < 0)) return 0;

    /* 第一跳：path -> 中间链接（.l2s.<name><NNNN>）。
     * 名字不匹配 = 普通 symlink（非 link2symlink 链），不动 */
    filename = get_filename(intermediate, NULL);
    if (UNLIKELY(!is_l2s_internal_name(filename))) return 0;

    /* 链内容可能是 guest 路径（/.l2s/.l2s.<name>，proot-distro 时代造的旧链）
     * 或 host 绝对路径（uproot 容器会话造的链）。uproot 进程运行在 host（Termux）
     * 侧，guest 路径 /.l2s/... 不可见，必须用 PROOT_L2S_DIR（host 绝对路径）定位。 */
    const char *l2s_dir = getenv("PROOT_L2S_DIR");
    char inter_host[PATH_MAX] ALIGNED, final_host[PATH_MAX] ALIGNED;
    if (LIKELY(l2s_dir && l2s_dir[0] && strcmp(l2s_dir, "/") != 0)) {
        snprintf(inter_host, sizeof(inter_host), "%s/%s", l2s_dir, filename);
    } else {
        strcpy(inter_host, intermediate);
    }

    /* 第二跳：中间链接 -> final（.l2s.<name><NNNN>.0002，普通文件 = 数据）。
     * readlink 成功本身即证明 intermediate 是符号链接；
     * 不 lstat intermediate（外层 proot 对链中间件 EPERM，真机虽无此问题
     * 但统一用 readlink 更简洁）。final 是普通文件组件，lstat 安全。 */
    status = my_readlink(inter_host, final, PATH_MAX);
    if (UNLIKELY(status < 0)) return 0;
    if (LIKELY(l2s_dir && l2s_dir[0] && strcmp(l2s_dir, "/") != 0)) {
        char *final_name = get_filename(final, NULL);
        snprintf(final_host, sizeof(final_host), "%s/%s", l2s_dir, final_name);
    } else {
        strcpy(final_host, final);
    }
    status = lstat(final_host, &statl);
    if (UNLIKELY(status < 0 || !S_ISREG(statl.st_mode))) return 0;

    /* 物化改为【复制】而非移动：数据永远保留在 final（.l2s 目录），
     * 目标路径放一份副本（保留权限）。
     * 原实现用 rename 把唯一数据副本移到目标路径，若目标随后被删除
     * （如 pnpm install 重建 node_modules 时删除旧文件/旧包目录），
     * 唯一数据副本丢失 → store 链断裂 → 后续访问 ENOENT
     * （ERR_PNPM_ENOENT copyfile 根因）。复制后数据永在 .l2s，
     * 链永不断，副本可被任意删除重建。
     * 空间代价：被物化的文件多一份副本（仅限 open/exec 的文件），
     * 正确性优先。 */
    unlink(path); /* 删除链（不跟随），副本作为普通文件创建 */
    int in_fd = open(final_host, O_RDONLY);
    int out_fd = open(path, O_WRONLY | O_CREAT | O_EXCL, statl.st_mode & 07777);
    if (LIKELY(in_fd >= 0 && out_fd >= 0)) {
        char buf[65536];
        ssize_t rd;
        while ((rd = read(in_fd, buf, sizeof(buf))) > 0) {
            ssize_t wr = write(out_fd, buf, rd);
            if (UNLIKELY(wr != rd)) { rd = -1; break; }
        }
        if (UNLIKELY(rd < 0)) {
            close(in_fd);
            close(out_fd);
            unlink(path);
            return 0;
        }
        close(in_fd);
        close(out_fd);
        /* 保留可执行位等权限（rename 保持 inode 权限，复制需显式恢复） */
        if (UNLIKELY(chmod(path, statl.st_mode & 07777) != 0)) {
            unlink(path);
            return 0;
        }
    } else {
        if (in_fd >= 0) close(in_fd);
        if (out_fd >= 0) close(out_fd);
        unlink(path);
        return 0;
    }

    /* 物化后清理链（2026-08-13 孤儿链 GC 修复）：物化把 path 从链成员
     * 变成普通副本，相当于该成员退出家族——但 tracer 直接 unlink 不经
     * decrement_link_count，计数永不归零，家族残骸（intermediate+final）
     * 永远滞留 /.l2s（容器已积 2.8G 孤儿）。这里补做 decrement：
     * 计数>0 → final 改名（NNNN-1）+ 重建共享中间链接（其他成员仍可达）；
     * 计数=0 → 删 intermediate+final（家族除名）。
     * 必须在复制完成之后：计数=0 会删 final 数据，副本已保存数据无损失。 */
    size_t final_len = strlen(final_host);
    int link_count = parse_4digit(final_host + final_len - 4) - 1;
    if (LIKELY(link_count >= 0)) {
        if (link_count > 0) {
            char new_final[PATH_MAX] ALIGNED;
            strncpy(new_final, final_host, final_len - 4);
            snprintf(new_final + final_len - 4, 5, "%04d", link_count);
            if (LIKELY(rename(final_host, new_final) == 0)) {
                notify_extensions(tracee, LINK2SYMLINK_RENAME, (intptr_t)final_host, (intptr_t)new_final);
                unlink(inter_host);
                symlink(new_final, inter_host);
                VERBOSE(tracee, 1, "link2symlink: materialize 退链：final 改名 %s -> %s", final_host, new_final);
            }
        } else {
            unlink(inter_host);
            unlink(final_host);
            notify_extensions(tracee, LINK2SYMLINK_UNLINK, (intptr_t)final_host, 0);
            VERBOSE(tracee, 1, "link2symlink: materialize 退链：家族除名 %s", final_host);
        }
    }

    VERBOSE(tracee, 1, "link2symlink: materialized \"%s\" (copied from \"%s\")", path, final_host);
    return 1;
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
        /* execve 物化（方案 C）：canonicalize 解析链之前、翻译前拦截。
         * 此时 user_path 仍是原始 guest 路径（symlink 链状态），
         * 用 substitute_binding 转成 host 路径后物化（只做前缀替换，不解析链）。
         * 相对路径的 execve 跳过（pnpm/tsgo 场景均为绝对路径）。 */
        Sysnum g_sysnum = get_sysnum(tracee, ORIGINAL);
        if (UNLIKELY(g_sysnum == PR_execve || g_sysnum == PR_execveat)) {
            char *user_path = (char *)data2;
            if (LIKELY(user_path && user_path[0] == '/')) {
                char host_path[PATH_MAX] ALIGNED;
                strcpy(host_path, user_path);
                if (LIKELY(substitute_binding(tracee, GUEST, host_path) >= 0))
                    materialize_executable(tracee, host_path);
            }
        }
        /* tsgo 场景（open 物化）：tsgo 用 open(path, O_PATH) + readlink(/proc/self/fd/N)
         * 解析真实路径，readlink(fd) 由内核直接返回（uproot 无法拦截），若 fd 指向
         * .l2s 链（symlink），readlink 返回链内容（/.l2s/.l2s.<hash>.0001.0002）→
         * 当 TS 文件处理报 TS6054/TS2307/TS7006（类型库解析失败）。必须在 open 之前
         * 把链物化为普通文件（此时 user_path 还是原始 guest 路径，链状态完好；
         * SYSCALL_ENTER_END 时已被 canonicalize 解析成 final，链信息丢失）。
         * 对所有 open 触发（不限于 O_PATH）：tsgo 会以多种方式访问类型文件，
         * 全量物化保证一次 tsc 即全部就位；物化是幂等的（普通文件跳过），
         * 数据仍 1 份（rename 移动），store 链由反向 symlink 保持完整。 */
        /* node ESM 场景（readlink 物化，2026-08-13 新增）：libuv 的 realpath
         * 不先 lstat、直接 readlink 循环，链文件 readlink 会返回 /.l2s 中间链
         * → node 按扩展名 .0002 判定模块格式 → ERR_UNKNOWN_FILE_EXTENSION
         * （pnpm install 后 pnpm dev/vite 崩溃，8.13 实测）。在 readlink 执行前
         * 物化：物化后是普通文件，readlink 自然 EINVAL → realpath 停在原路径
         * （扩展名正确）；非链 symlink 不受影响（materialize 幂等跳过）。 */
        if (UNLIKELY(g_sysnum == PR_open || g_sysnum == PR_openat
                     || g_sysnum == PR_readlink || g_sysnum == PR_readlinkat)) {
            char *user_path = (char *)data2;
            if (LIKELY(user_path && user_path[0] == '/')) {
                char host_path[PATH_MAX] ALIGNED;
                strcpy(host_path, user_path);
                if (LIKELY(substitute_binding(tracee, GUEST, host_path) >= 0))
                    materialize_executable(tracee, host_path);
            }
        }
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