#ifndef TRACEE_ABI_H
#define TRACEE_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "arch.h"
#include "attribute.h"

// 仅支持 64 位 ARM64，ABI 固定为默认
typedef enum {
    ABI_DEFAULT = 0,
    NB_MAX_ABIS
} Abi;

// 获取当前 ABI（始终为默认）
static inline Abi get_abi(const Tracee *tracee) {
    (void)tracee;
    return ABI_DEFAULT;
}

// 是否为 32-on-64 模式（始终为 false）
static inline bool is_32on64_mode(const Tracee *tracee) {
    (void)tracee;
    return false;
}

// 获取字长（始终为 8 字节）
static inline size_t sizeof_word(const Tracee *tracee) {
    (void)tracee;
    return sizeof(word_t);
}

// 获取 stat 结构中 uid 的偏移量（编译期常量）
static inline off_t offsetof_stat_uid(const Tracee *tracee) {
    (void)tracee;
    return offsetof(struct stat, st_uid);
}

// 获取 stat 结构中 gid 的偏移量（编译期常量）
static inline off_t offsetof_stat_gid(const Tracee *tracee) {
    (void)tracee;
    return offsetof(struct stat, st_gid);
}

#endif /* TRACEE_ABI_H */