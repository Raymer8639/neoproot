#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/user.h>
#include <stddef.h>

#include "ptrace/user.h"
#include "cli/note.h"

#if defined(ARCH_ARM64)

/**
 * Return the offset in the "user" area for aarch64 that corresponds to the
 * specified @offset in a 32-bit "user" area. This function returns
 * "(word_t) -1" if the specified @offset is invalid.
 */
word_t convert_user_offset(word_t offset UNUSED)
{
	note(NULL, WARNING, INTERNAL, "ptrace user area conversion not supported for aarch64 yet");
	return (word_t) -1;  /* Unknown offset.  */
}

/**
 * Convert the "regs" field from a 64-bit "user" area into a "regs"
 * field from a 32-bit "user" area, or vice versa according to
 * @reverse for aarch64.
 */
void convert_user_regs_struct(bool reverse, uint64_t *user_regs64,
			uint32_t user_regs32[USER32_NB_REGS])
{
	/* For aarch64, we currently don't need conversion between 32-bit and 64-bit register formats */
	(void)reverse;
	(void)user_regs64;
	(void)user_regs32;
	/* Do nothing for aarch64 until needed */
}

#endif /* ARCH_ARM64 */
