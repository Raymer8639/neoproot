#include <errno.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "tracee/statx.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "extension/extension.h"

// 与项目全局宏统一
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten)) inline
#define HOT __attribute__((hot))

static int statx_host_path(const char *path, int flags, unsigned int mask,
                           struct statx *buffer)
{
#if defined(SYS_statx)
    return syscall(SYS_statx, AT_FDCWD, path, flags & ~AT_EMPTY_PATH, mask, buffer);
#elif defined(__NR_statx)
    return syscall(__NR_statx, AT_FDCWD, path, flags & ~AT_EMPTY_PATH, mask, buffer);
#else
    (void)path;
    (void)flags;
    (void)mask;
    (void)buffer;
    errno = ENOSYS;
    return -1;
#endif
}

// 常量定义，避免魔法数
#define STATX_ALL_SUPPORTED_MASK ( \
    STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_GID | \
    STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_INO | \
    STATX_SIZE | STATX_BLOCKS | STATX_BTIME \
)

[[nodiscard]]
HOT
int handle_statx_syscall(Tracee *restrict tracee, bool from_sigsys)
{
    const RegVersion reg_ver = from_sigsys ? CURRENT : ORIGINAL;
    struct statx_syscall_state state = {
        .statx_buf = {0}, // 彻底清零，避免栈垃圾数据泄露
        .host_path = {0},
        .updated_stats = 0
    };
    char guest_path[PATH_MAX] = {0};
    char proc_fd_path[64];
    struct stat st = {0};

    // 【性能优化】一次性批量读取所有寄存器，减少ptrace调用开销
    const word_t reg1 = peek_reg(tracee, reg_ver, SYSARG_1);
    const word_t reg2 = peek_reg(tracee, reg_ver, SYSARG_2);
    const word_t reg3 = peek_reg(tracee, reg_ver, SYSARG_3);
    const word_t reg4 = peek_reg(tracee, reg_ver, SYSARG_4);
    /* SIGSYS handling rewrites the live register set before emulation. */
    const word_t statx_addr = peek_reg(tracee, reg_ver, SYSARG_5);

    const int dirfd     = (int)reg1;
    const word_t path_addr = reg2;
    const int flags     = (int)reg3;
    const int mask      = (int)reg4;
    // 正确处理AT_SYMLINK_FOLLOW优先级高于AT_SYMLINK_NOFOLLOW
    const bool do_lstat = !!(flags & AT_SYMLINK_NOFOLLOW) && !(flags & AT_SYMLINK_FOLLOW);

    int status;

    // 读取用户态路径
    status = read_string(tracee, guest_path, path_addr, PATH_MAX);
    if (UNLIKELY(status < 0)) {
        return status;
    }

    // 空路径特殊处理（AT_EMPTY_PATH）
    if (UNLIKELY(status == 1 && guest_path[0] == '\0')) {
        if (UNLIKELY(!(flags & AT_EMPTY_PATH))) {
            return -ENOENT;
        }
        status = readlink_proc_pid_fd(tracee->pid, dirfd, state.host_path);
        if (UNLIKELY(status < 0)) {
            return status;
        }

        /* AT_EMPTY_PATH names an already-open descriptor.  The procfd
         * symlink target can be an anonymous object such as "pipe:[N]";
         * stat() on that target is invalid, while statx on the procfd path
         * correctly follows it and preserves FIFO/socket metadata. */
        status = snprintf(proc_fd_path, sizeof(proc_fd_path),
                          "/proc/%d/fd/%d", tracee->pid, dirfd);
        if (UNLIKELY(status < 0 || (size_t)status >= sizeof(proc_fd_path)))
            return -ENAMETOOLONG;

        // Preserve mount metadata such as STATX_MNT_ID when emulating an
        // empty-path lookup. Fall back to stat(2) on older host kernels.
        status = statx_host_path(proc_fd_path, flags, (unsigned int)mask,
                                 &state.statx_buf);
        if (status == 0) {
            state.updated_stats = 1;
            status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t)&state, 0);
            if (UNLIKELY(status < 0)) {
                return status;
            }
            return write_data(tracee, statx_addr, &state.statx_buf,
                              sizeof(struct statx));
        }

        // Empty path only supports stat semantics in the legacy fallback.
        status = stat(proc_fd_path, &st);
        if (UNLIKELY(status < 0)) {
            return -errno;
        }
        goto fill_statx;
    }

    // 路径长度越界校验
    if (UNLIKELY(status >= PATH_MAX)) {
        return -ENAMETOOLONG;
    }

    // 路径翻译（guest -> host）
    status = translate_path(tracee, state.host_path, dirfd, guest_path, !do_lstat);
    if (UNLIKELY(status < 0)) {
        return status;
    }

    // 【逻辑修复】严格区分sigsys/正常syscall路径，保存errno避免被覆盖
    const bool syscall_failed = peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0;
    if (from_sigsys || syscall_failed) {
        if (do_lstat) {
            status = lstat(state.host_path, &st);
        } else {
            status = stat(state.host_path, &st);
        }
        if (UNLIKELY(status < 0)) {
            const int saved_errno = errno;
            return -saved_errno;
        }
    } else {
        // 内核已返回成功结果，直接读取用户态statx缓冲区
        status = read_data(tracee, &state.statx_buf, statx_addr, sizeof(struct statx));
        if (UNLIKELY(status < 0)) {
            return status;
        }
        // 通知扩展处理（fake_id0 属主改写 / link2symlink nlink），然后写回用户缓冲区
        status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t)&state, 0);
        if (UNLIKELY(status < 0)) {
            return status;
        }
        return write_data(tracee, statx_addr, &state.statx_buf, sizeof(struct statx));
    }

fill_statx:
    // 仅填充用户请求的、且支持的字段
    state.statx_buf.stx_mask = mask & STATX_ALL_SUPPORTED_MASK;

    // 固定字段填充（不受mask影响）
    state.statx_buf.stx_blksize = st.st_blksize;
    state.statx_buf.stx_rdev_major = major(st.st_rdev);
    state.statx_buf.stx_rdev_minor = minor(st.st_rdev);
    state.statx_buf.stx_dev_major  = major(st.st_dev);
    state.statx_buf.stx_dev_minor  = minor(st.st_dev);

    // 按mask按需填充，减少不必要的内存写入
    if (mask & (STATX_TYPE | STATX_MODE)) state.statx_buf.stx_mode = st.st_mode;
    if (mask & STATX_NLINK) state.statx_buf.stx_nlink = st.st_nlink;
    if (mask & STATX_UID)   state.statx_buf.stx_uid   = st.st_uid;
    if (mask & STATX_GID)   state.statx_buf.stx_gid   = st.st_gid;
    if (mask & STATX_INO)   state.statx_buf.stx_ino   = st.st_ino;
    if (mask & STATX_SIZE)  state.statx_buf.stx_size  = st.st_size;
    if (mask & STATX_BLOCKS) state.statx_buf.stx_blocks = st.st_blocks;

    // 时间字段填充
    if (mask & STATX_ATIME) {
        state.statx_buf.stx_atime.tv_sec  = st.st_atim.tv_sec;
        state.statx_buf.stx_atime.tv_nsec = st.st_atim.tv_nsec;
    }
    if (mask & STATX_MTIME) {
        state.statx_buf.stx_mtime.tv_sec  = st.st_mtim.tv_sec;
        state.statx_buf.stx_mtime.tv_nsec = st.st_mtim.tv_nsec;
    }
    if (mask & STATX_CTIME) {
        state.statx_buf.stx_ctime.tv_sec  = st.st_ctim.tv_sec;
        state.statx_buf.stx_ctime.tv_nsec = st.st_ctim.tv_nsec;
    }
    // BTIME不支持时置0，而非强制回退CTIME，符合statx标准
    if (mask & STATX_BTIME) {
#ifdef STATX_BTIME
        state.statx_buf.stx_btime.tv_sec  = st.st_mtim.tv_sec;
        state.statx_buf.stx_btime.tv_nsec = st.st_mtim.tv_nsec;
#else
        state.statx_buf.stx_btime.tv_sec  = 0;
        state.statx_buf.stx_btime.tv_nsec = 0;
        // 移除不支持的BTIME标记
        state.statx_buf.stx_mask &= ~STATX_BTIME;
#endif
    }

    state.updated_stats = 1;

    // 扩展钩子处理
    status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t)&state, 0);
    if (UNLIKELY(status < 0)) {
        return status;
    }

    // 使用初始读取的ORIGINAL地址写入，避免地址被篡改
    return write_data(tracee, statx_addr, &state.statx_buf, sizeof(struct statx));
}
