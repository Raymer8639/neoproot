#include <errno.h>          /* E*, */
#include <sys/sysmacros.h>  /* major, minor, */
#include <string.h>         /* strncpy, snprintf */
#include <limits.h>         /* PATH_MAX */

#include "tracee/statx.h"
#include "tracee/mem.h"
#include "extension/extension.h"  /* notify_extensions */
#include "path/path.h"            /* translate_path, readlink_proc_pid_fd */

int handle_statx_syscall(Tracee *tracee, bool from_sigsys) {
    // 显式初始化所有变量，消除未初始化警告
    RegVersion regVersion = from_sigsys ? CURRENT : ORIGINAL;
    struct statx_syscall_state state = {0};  // 结构体零初始化
    char guest_path[PATH_MAX] = {0};         // 字符数组零初始化
    struct stat stat_buf = {0};              // stat结构体零初始化
    bool do_fstat = false;
    bool do_lstat = false;
    int status = 0;
    word_t dirfd = 0, flags = 0, mask = 0;

    /* 1. 读取系统调用参数，批量获取寄存器值，减少peek_reg调用 */
    dirfd = peek_reg(tracee, regVersion, SYSARG_1);
    flags = peek_reg(tracee, regVersion, SYSARG_3);
    mask  = peek_reg(tracee, regVersion, SYSARG_4);
    do_lstat = ((flags & AT_SYMLINK_NOFOLLOW) != 0);

    /* 2. 读取并转换客端路径 */
    status = read_string(tracee, guest_path, peek_reg(tracee, regVersion, SYSARG_2), PATH_MAX);
    if (status < 0) {
        return status;
    }
    // 修复原逻辑：status==0时直接返回-EFAULT（路径读取失败）
    if (status == 0) {
        return -EFAULT;
    }
    // 空路径处理：需AT_EMPTY_PATH标志，否则返回ENOENT
    if (status == 1) {
        if ((flags & AT_EMPTY_PATH) == 0) {
            return -ENOENT;
        }
        status = readlink_proc_pid_fd(tracee->pid, dirfd, state.host_path);
        do_fstat = true;
    } else {
        // 路径过长校验，避免越界
        if (status >= PATH_MAX) {
            return -ENAMETOOLONG;
        }
        // 转换客端路径到主机路径，根据do_lstat决定是否跟随软链接
        status = translate_path(tracee, state.host_path, dirfd, guest_path, !do_lstat);
    }
    // 路径转换失败，直接返回错误码
    if (status < 0) {
        return status;
    }

    /* 3. 执行主机侧[ l ]stat / fstat 操作 */
    if (from_sigsys || peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0) {
        if (do_fstat) {
            // 固定缓冲区大小，避免魔法数字，加snprintf返回值校验
            char link[64] = {0};  // 足够容纳/proc/[pid]/fd/[fd] 路径
            int ret = snprintf(link, sizeof(link), "/proc/%d/fd/%d", 
                              tracee->pid, (int)dirfd);
            if (ret < 0 || (size_t)ret >= sizeof(link)) {
                return -EINVAL;
            }
            status = stat(link, &stat_buf);
        } else if (do_lstat) {
            status = lstat(state.host_path, &stat_buf);
        } else {
            status = stat(state.host_path, &stat_buf);
        }
        // 系统调用失败，转换为负的错误码，兜底EPERM
        if (status < 0) {
            status = -errno;
            if (status >= 0) {
                status = -EPERM;
            }
            return status;
        }

        /* 4. 将stat结果转换为statx格式，按mask过滤字段 */
        state.statx_buf.stx_mask = mask & (
            STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID | STATX_GID |
            STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_INO | STATX_SIZE |
            STATX_BLOCKS | STATX_BTIME
        );
        state.statx_buf.stx_blksize = stat_buf.st_blksize;
        state.statx_buf.stx_rdev_major = major(stat_buf.st_rdev);
        state.statx_buf.stx_rdev_minor = minor(stat_buf.st_rdev);

        // 按mask按需赋值，精简分支（无冗余判断）
        if (mask & (STATX_TYPE | STATX_MODE)) state.statx_buf.stx_mode = stat_buf.st_mode;
        if (mask & STATX_NLINK)                state.statx_buf.stx_nlink = stat_buf.st_nlink;
        if (mask & STATX_UID)                  state.statx_buf.stx_uid = stat_buf.st_uid;
        if (mask & STATX_GID)                  state.statx_buf.stx_gid = stat_buf.st_gid;
        if (mask & STATX_ATIME) {
            state.statx_buf.stx_atime.tv_sec = stat_buf.st_atim.tv_sec;
            state.statx_buf.stx_atime.tv_nsec = stat_buf.st_atim.tv_nsec;
        }
        if (mask & STATX_MTIME) {
            state.statx_buf.stx_mtime.tv_sec = stat_buf.st_mtim.tv_sec;
            state.statx_buf.stx_mtime.tv_nsec = stat_buf.st_mtim.tv_nsec;
        }
        if (mask & STATX_CTIME) {
            state.statx_buf.stx_ctime.tv_sec = stat_buf.st_ctim.tv_sec;
            state.statx_buf.stx_ctime.tv_nsec = stat_buf.st_ctim.tv_nsec;
        }
        if (mask & STATX_INO)                  state.statx_buf.stx_ino = stat_buf.st_ino;
        if (mask & STATX_SIZE)                 state.statx_buf.stx_size = stat_buf.st_size;
        if (mask & STATX_BLOCKS)               state.statx_buf.stx_blocks = stat_buf.st_blocks;
        if (mask & STATX_BTIME) {  // stat无btime，复用ctime
            state.statx_buf.stx_btime.tv_sec = stat_buf.st_ctim.tv_sec;
            state.statx_buf.stx_btime.tv_nsec = stat_buf.st_ctim.tv_nsec;
        }
        state.updated_stats = true;
    } else {
        /* 5. 未触发sigsys，读取tracee侧的statx缓冲区 */
        status = read_data(tracee, &state.statx_buf, 
                          peek_reg(tracee, ORIGINAL, SYSARG_5), 
                          sizeof(struct statx));
        if (status < 0) {
            return status;
        }
    }

    /* 6. 通知扩展模块，传递statx状态 */
    status = notify_extensions(tracee, STATX_SYSCALL, (intptr_t)&state, 0);
    if (status < 0) {
        return status;
    }

    /* 7. 将更新后的statx结果写回tracee */
    if (state.updated_stats) {
        status = write_data(tracee, 
                          peek_reg(tracee, CURRENT, SYSARG_5), 
                          &state.statx_buf, 
                          sizeof(state.statx_buf));
        if (status < 0) {
            return status;
        }
    }

    return 0;
}
