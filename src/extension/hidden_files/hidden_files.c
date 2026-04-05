#include "extension/extension.h"
#include "tracee/mem.h"
#include "syscall/chain.h"
#include "path/path.h"
#include <string.h>
#include <limits.h>

/* 需隐藏的文件前缀，可按需修改 */
#define HIDDEN_PREFIX ".proot"

/* 32位目录项结构 */
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

/* 64位目录项结构 */
struct linux_dirent64 {
    unsigned long long d_ino;
    long long          d_off;
    unsigned short     d_reclen;
    unsigned char      d_type;
    char               d_name[];
};

/**
 * 内存字节拷贝，替代原生bcopy
 * @param src 源地址
 * @param dst 目标地址
 * @param num 拷贝字节数
 */
static void mem_copy(char *src, char *dst, unsigned int num)
{
    if (src == NULL || dst == NULL || num == 0)
        return;
    while (num--) {
        *(dst++) = *(src++);
    }
}

/**
 * 检查字符串是否以指定前缀开头
 * @param prefix 前缀字符串
 * @param str    待检查字符串
 * @return 1-是，0-否
 */
static int str_has_prefix(const char *prefix, const char *str)
{
    if (prefix == NULL || str == NULL)
        return 0;
    while (*prefix && *str && (*prefix == *str)) {
        prefix++;
        str++;
    }
    return (*prefix == '\0') ? 1 : 0;
}

/**
 * 处理getdents/getdents64系统调用，过滤指定前缀的隐藏文件
 * @param tracee 进程追踪句柄
 * @return 0-成功，非0-错误码
 */
static int handle_getdents(Tracee *tracee)
{
    if (tracee == NULL)
        return -1;

    word_t sysnum = get_sysnum(tracee, ORIGINAL);
    if (sysnum != PR_getdents && sysnum != PR_getdents64)
        return 0;

    /* 获取系统调用返回值（实际读取的字节数） */
    unsigned int res = (unsigned int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
    if (res <= 0)
        return (int)res;

    /* 获取系统调用参数：fd=SYSARG_1, buf=SYSARG_2, count=SYSARG_3 */
    word_t fd = peek_reg(tracee, ORIGINAL, SYSARG_1);
    word_t buf_addr = peek_reg(tracee, CURRENT, SYSARG_2);
    unsigned int count = (unsigned int)peek_reg(tracee, CURRENT, SYSARG_3);

    /* 校验缓冲区大小，避免内存越界 */
    if (count == 0 || count > PATH_MAX * 1024)
        return 0;

    /* 验证路径是否属于guestfs，非guestfs路径不做过滤 */
    char path[PATH_MAX] = {0};
    int status = readlink_proc_pid_fd(tracee->pid, fd, path);
    if (status < 0 || !belongs_to_guestfs(tracee, path))
        return 0;

    /* 读取getdents返回的原始目录项数据 */
    char orig_data[count];
    status = read_data(tracee, orig_data, buf_addr, res);
    if (status < 0)
        return status;

    /* 分配过滤后的数据缓冲区 */
    char filtered_data[count];
    char *orig_ptr = orig_data;    // 原始数据指针
    char *filter_ptr = filtered_data; // 过滤后数据指针
    unsigned int filtered_len = 0; // 过滤后数据总长度

    /* 分64/32位处理目录项 */
    if (sysnum == PR_getdents64) {
        struct linux_dirent64 *dir64;
        while (orig_ptr < orig_data + res) {
            dir64 = (struct linux_dirent64 *)orig_ptr;
            /* 过滤掉指定前缀的文件，保留其他文件 */
            if (!str_has_prefix(HIDDEN_PREFIX, dir64->d_name)) {
                mem_copy(orig_ptr, filter_ptr, dir64->d_reclen);
                filter_ptr += dir64->d_reclen;
                filtered_len += dir64->d_reclen;
            }
            orig_ptr += dir64->d_reclen;
        }
    } else {
        struct linux_dirent *dir32;
        while (orig_ptr < orig_data + res) {
            dir32 = (struct linux_dirent *)orig_ptr;
            /* 过滤掉指定前缀的文件，保留其他文件 */
            if (!str_has_prefix(HIDDEN_PREFIX, dir32->d_name)) {
                mem_copy(orig_ptr, filter_ptr, dir32->d_reclen);
                filter_ptr += dir32->d_reclen;
                filtered_len += dir32->d_reclen;
            }
            orig_ptr += dir32->d_reclen;
        }
    }

    /* 无有效数据时，链式调用重新执行getdents */
    if (filtered_len == 0) {
        register_chained_syscall(tracee, sysnum,
            peek_reg(tracee, ORIGINAL, SYSARG_1),
            buf_addr, count, 0, 0, 0);
    } else {
        /* 将过滤后的数据写回进程内存，并更新返回值 */
        status = write_data(tracee, buf_addr, filtered_data, filtered_len);
        if (status < 0)
            return status;
        poke_reg(tracee, SYSARG_RESULT, (word_t)filtered_len);
    }

    return 0;
}

/**
 * 扩展核心回调函数，处理各类事件触发
 * @param extension 扩展句柄
 * @param event     触发事件类型
 * @param data1     事件附加数据1
 * @param data2     事件附加数据2
 * @return 0-成功，非0-错误码
 */
int hidden_files_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    if (extension == NULL)
        return -1;

    switch (event) {
    case INITIALIZATION: {
        /* 注册需要处理的系统调用：getdents/getdents64（退出阶段过滤） */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_getdents,    FILTER_SYSEXIT },
            { PR_getdents64,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_CHAINED_EXIT:
    case SYSCALL_EXIT_END:
        /* 系统调用退出时执行文件过滤逻辑 */
        return handle_getdents(TRACEE(extension));

    default:
        return 0;
    }
}
