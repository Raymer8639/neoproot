#ifndef ARCH_H
#define ARCH_H

#ifndef NO_LIBC_HEADER
#include <sys/ptrace.h>
#include <linux/audit.h>
#endif

typedef unsigned long word_t;
typedef unsigned char byte_t;

#define SYSCALL_AVOIDER ((word_t) -1)
#define SYSTRAP_NUM SYSARG_NUM

/* 强制只支持 ARM64 / aarch64 */
#if !defined(ARCH_ARM64)
#    if defined(__aarch64__)
#        define ARCH_ARM64 1
#    else
//#        error "This build only supports aarch64"
#    endif
#endif

/* -------------------------- ARM64 (aarch64) ONLY -------------------------- */
#if defined(ARCH_ARM64)

#   define SYSNUMS_HEADER1 "syscall/sysnums-arm64.h"

#   define SYSNUMS_ABI1    sysnums_arm64

#   define SYSTRAP_SIZE 4

#   ifndef AUDIT_ARCH_AARCH64
#       define AUDIT_ARCH_AARCH64 (183 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#   endif

#   define SECCOMP_ARCHS { \
        { .value = AUDIT_ARCH_AARCH64, .nb_abis = 1, .abis = { ABI_DEFAULT } }, \
    }

#   define HOST_ELF_MACHINE {183, 0};
#   define RED_ZONE_SIZE 0
#   define OFFSETOF_STAT_UID_32 24
#   define OFFSETOF_STAT_GID_32 28

#   define LOADER_ADDRESS     0x2000000000
#   define EXEC_PIC_ADDRESS   0x3000000000
#   define INTERP_PIC_ADDRESS 0x3f00000000
#   define HAS_POKEDATA_WORKAROUND true

/* 彻底禁用 32 位支持 */
#   undef HAS_LOADER_32BIT

#endif

#endif /* ARCH_H */
