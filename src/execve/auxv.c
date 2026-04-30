#include <linux/auxvec.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <talloc.h>

#include "syscall/sysnum.h"
#include "execve/auxv.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "arch.h"

#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x)  __builtin_expect(!!(x), 1)

int add_elf_aux_vector(ElfAuxVector **vectors, word_t type, word_t value)
{
	if (UNLIKELY(!vectors || !*vectors))
		return -EINVAL;

	size_t total = talloc_array_length(*vectors);
	if (UNLIKELY(total == 0 || (*vectors)[total - 1].type != AT_NULL))
		return -EINVAL;

	ElfAuxVector *new_block = talloc_realloc(talloc_parent(*vectors),
		*vectors, ElfAuxVector, total + 1);
	if (UNLIKELY(!new_block))
		return -ENOMEM;

	*vectors = new_block;
	new_block[total - 1].type  = type;
	new_block[total - 1].value = value;
	new_block[total].type  = AT_NULL;
	new_block[total].value = 0;

	return 0;
}

word_t get_elf_aux_vectors_address(const Tracee *tracee)
{
	if (UNLIKELY(!tracee || !IS_IN_SYSEXIT2(tracee, PR_execve)))
		return 0;

	word_t sp = peek_reg(tracee, CURRENT, STACK_POINTER);
	word_t ws = sizeof_word(tracee);

	word_t argc = peek_word(tracee, sp);
	if (UNLIKELY(errno != 0))
		return 0;

	// 跳过 argc + argv + NULL
	sp += (1 + argc + 1) * ws;

	// 跳过 envp
	while (LIKELY(1)) {
		word_t val = peek_word(tracee, sp);
		if (UNLIKELY(errno != 0))
			return 0;
		sp += ws;
		if (val == 0)
			break;
	}

	return sp;
}

ElfAuxVector *fetch_elf_aux_vectors(const Tracee *tracee, word_t addr)
{
	if (UNLIKELY(!tracee || addr == 0))
		return NULL;

	word_t ws = sizeof_word(tracee);
	ElfAuxVector *vecs = talloc_array(tracee->ctx, ElfAuxVector, 1);
	if (UNLIKELY(!vecs))
		return NULL;

	vecs[0].type = AT_NULL;
	vecs[0].value = 0;

	while (LIKELY(1)) {
		word_t type = peek_word(tracee, addr);
		if (UNLIKELY(errno != 0))
			goto error;
		addr += ws;

		if (type == AT_NULL)
			break;

		word_t value = peek_word(tracee, addr);
		if (UNLIKELY(errno != 0))
			goto error;
		addr += ws;

		if (UNLIKELY(add_elf_aux_vector(&vecs, type, value) < 0))
			goto error;
	}

	return vecs;

error:
	talloc_free(vecs);
	return NULL;
}

int push_elf_aux_vectors(const Tracee *tracee, ElfAuxVector *vecs, word_t addr)
{
	if (UNLIKELY(!tracee || !vecs))
		return -EINVAL;

	word_t ws = sizeof_word(tracee);

	for (size_t i = 0; LIKELY(vecs[i].type != AT_NULL); i++) {
		poke_word(tracee, addr, vecs[i].type);
		if (UNLIKELY(errno != 0))
			return -errno;
		addr += ws;

		poke_word(tracee, addr, vecs[i].value);
		if (UNLIKELY(errno != 0))
			return -errno;
		addr += ws;
	}

	// 结尾 AT_NULL
	poke_word(tracee, addr, AT_NULL);
	if (UNLIKELY(errno != 0))
		return -errno;
	addr += ws;

	poke_word(tracee, addr, 0);
	if (UNLIKELY(errno != 0))
		return -errno;

	return 0;
}
