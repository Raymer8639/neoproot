/*
 * Optimized hidden files extension
 * Only keeps essential open/readdir hooks with minimal logic
 * Copyright (C) 2026 Scicat - proot-scicat
 * GPLv2 License
 */
#include "extension/extension.h"
#include "tracee/mem.h"
#include <string.h>

/* Hidden file prefix (adjust as needed) */
#define HIDDEN_PREFIX    ".proot"
#define PREFIX_LEN       (sizeof(HIDDEN_PREFIX) - 1)

/**
 * Ultra-optimized callback - single function, minimal branches
 * Inline dirent structs, direct strncmp check, no extra helper funcs
 */
int hidden_files_callback(Extension *extension, ExtensionEvent event,
                          intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
        // 仅注册核心需要过滤的系统调用，无多余注册
        case INITIALIZATION: {
            static const FilteredSysnum filtered_sysnums[] = {
                { PR_getdents,    FILTER_SYSEXIT },
                { PR_getdents64,  FILTER_SYSEXIT },
                FILTERED_SYSNUM_END,
            };
            extension->filtered_sysnums = (FilteredSysnum *)filtered_sysnums;
            return 0;
        }

        // 仅处理系统调用退出阶段，核心过滤逻辑一站式实现
        case SYSCALL_EXIT_END: {
            Tracee *const tracee = TRACEE(extension);
            const word_t sysnum = get_sysnum(tracee, ORIGINAL);

            // 仅处理getdents/getdents64，快速分支退出
            if (sysnum != PR_getdents && sysnum != PR_getdents64)
                return 0;

            // 获取系统调用返回值和核心参数，失败直接退出
            const unsigned int res = (unsigned int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
            if (res <= 0) return 0;

            const word_t buf_addr = peek_reg(tracee, CURRENT, SYSARG_2);
            const unsigned int buf_size = (unsigned int)peek_reg(tracee, CURRENT, SYSARG_3);
            if (buf_addr == 0 || buf_size == 0) return 0;

            // 分配缓冲区读取原始目录项数据，读失败直接退出
            char *const buffer = (char *)__builtin_alloca(buf_size);
            if (read_data(tracee, buffer, buf_addr, res) < 0)
                return 0;

            // 核心变量：输入指针/输出指针/过滤后长度，极简初始化
            char *ptr = buffer, *pos = buffer;
            unsigned int nleft = 0;

            // 64位目录项过滤 - 内联结构体，无外部定义
            if (sysnum == PR_getdents64) {
                while (ptr < buffer + res) {
                    struct linux_dirent64 {
                        unsigned long long d_ino;
                        long long d_off;
                        unsigned short d_reclen;
                        unsigned char d_type;
                        char d_name[];
                    } *const curr = (struct linux_dirent64 *)ptr;

                    // 单行核心判断：非隐藏前缀则拷贝，无多余逻辑
                    if (strncmp(curr->d_name, HIDDEN_PREFIX, PREFIX_LEN) != 0) {
                        memcpy(pos, curr, curr->d_reclen);
                        pos += curr->d_reclen;
                        nleft += curr->d_reclen;
                    }
                    ptr += curr->d_reclen;
                }
            }
            // 32位目录项过滤 - 内联结构体，与64位逻辑一致
            else {
                while (ptr < buffer + res) {
                    struct linux_dirent {
                        unsigned long d_ino;
                        unsigned long d_off;
                        unsigned short d_reclen;
                        char d_name[];
                    } *const curr = (struct linux_dirent *)ptr;

                    // 单行核心判断：复用相同的前缀检测逻辑
                    if (strncmp(curr->d_name, HIDDEN_PREFIX, PREFIX_LEN) != 0) {
                        memcpy(pos, curr, curr->d_reclen);
                        pos += curr->d_reclen;
                        nleft += curr->d_reclen;
                    }
                    ptr += curr->d_reclen;
                }
            }

            // 仅在过滤后数据有变化时，写回内存并更新返回值，减少系统调用
            if (nleft > 0 && nleft != res) {
                write_data(tracee, buf_addr, buffer, nleft);
                poke_reg(tracee, SYSARG_RESULT, (word_t)nleft);
            }
            return 0;
        }

        // 所有非核心事件，直接返回0，无多余处理
        default:
            return 0;
    }
}
