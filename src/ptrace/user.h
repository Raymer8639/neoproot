#ifndef USER_H
#define USER_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "arch.h"
#include "attribute.h"

/* For ARM64 architecture, define the register counts for compatibility */
#define USER32_NB_REGS   16  /* 16 general purpose registers for 32-bit compatibility */
#define USER32_NB_FPREGS 8   /* 8 floating point registers for 32-bit compatibility */

#if defined(ARCH_ARM64)
/* For ARM64, we use the appropriate types and structures */
extern word_t convert_user_offset(word_t offset UNUSED);

extern void convert_user_regs_struct(
    bool reverse,
    uint64_t *user_regs64,
    uint32_t user_regs32[USER32_NB_REGS]);
#else
/* For other architectures, provide a default implementation */
static inline word_t convert_user_offset(word_t offset UNUSED)
{
    return 0;
}

static inline void convert_user_regs_struct(
    bool reverse UNUSED,
    uint64_t *user_regs64 UNUSED,
    uint32_t user_regs32[USER32_NB_REGS] UNUSED)
{
}
#endif

#endif /* USER_H */
