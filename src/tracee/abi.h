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
	NB_MAX_ABIS
} Abi;

static inline Abi get_abi(const Tracee *tracee)
{
	return ABI_DEFAULT;
}

static inline bool is_32on64_mode(const Tracee *tracee)
{
	return false;
}

static inline size_t sizeof_word(const Tracee *tracee)
{
	return sizeof(word_t);
}

static inline off_t offsetof_stat_uid(const Tracee *tracee)
{
	return offsetof(struct stat, st_uid);
}

static inline off_t offsetof_stat_gid(const Tracee *tracee)
{
	return offsetof(struct stat, st_gid);
}

#endif /* TRACEE_ABI_H */
