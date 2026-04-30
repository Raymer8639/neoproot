#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "ptrace/user.h"

#if defined(ARCH_ARM64)

/* aarch64 不支持 32bit <-> 64bit user 偏移转换 */
word_t convert_user_offset(word_t offset)
{
    (void)offset;
    return (word_t)-1;
}

/* aarch64 无需寄存器格式转换 */
void convert_user_regs_struct(bool reverse, uint64_t *user_regs64,
                              uint32_t user_regs32[USER32_NB_REGS])
{
    (void)reverse;
    (void)user_regs64;
    (void)user_regs32;
}

#endif
