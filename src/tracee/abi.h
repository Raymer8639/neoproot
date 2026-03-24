#ifndef TRACEE_ABI_H
#define TRACEE_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "arch.h"
#include "attribute.h"

typedef enum {
	ABI_DEFAULT = 0,
	ABI_2,   /* ARM32 on AArch64 */
	NB_MAX_ABIS
} Abi;

// 纯 ARM64，直接保留 AArch64 逻辑
static inline Abi get_abi(const Tracee *tracee)
{
	return tracee->is_aarch32 ? ABI_2 : ABI_DEFAULT;
}

static inline bool is_32on64_mode(const Tracee *tracee)
{
	return tracee->is_aarch32;
}

static inline size_t sizeof_word(const Tracee *tracee)
{
	return is_32on64_mode(tracee) ? sizeof(uint32_t) : sizeof(word_t);
}

static inline off_t offsetof_stat_uid(const Tracee *tracee)
{
	return is_32on64_mode(tracee) ? OFFSETOF_STAT_UID_32 : offsetof(struct stat, st_uid);
}

static inline off_t offsetof_stat_gid(const Tracee *tracee)
{
	return is_32on64_mode(tracee) ? OFFSETOF_STAT_GID_32 : offsetof(struct stat, st_gid);
}

#endif /* TRACEE_ABI_H */
