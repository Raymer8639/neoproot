#include <linux/auxvec.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <talloc.h>

// 🔥 修复：补上缺失的头文件
#include "syscall/sysnum.h"
#include "execve/auxv.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/abi.h"
#include "arch.h"

int add_elf_aux_vector(ElfAuxVector **vectors, word_t type, word_t value)
{
	if (!vectors || !*vectors)
		return -EINVAL;

	size_t total = talloc_array_length(*vectors);
	if (total == 0 || (*vectors)[total - 1].type != AT_NULL)
		return -EINVAL;

	ElfAuxVector *new_block = talloc_realloc(talloc_parent(*vectors),
		*vectors, ElfAuxVector, total + 1);
	if (!new_block)
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
	if (!tracee || !IS_IN_SYSEXIT2(tracee, PR_execve))
		return 0;

	word_t sp = peek_reg(tracee, CURRENT, STACK_POINTER);
	word_t ws = sizeof_word(tracee);

	word_t argc = peek_word(tracee, sp);
	if (errno != 0)
		return 0;

	sp += (1 + argc + 1) * ws;

	while (1) {
		word_t value = peek_word(tracee, sp);
		if (errno != 0)
			return 0;
		sp += ws;
		if (value == 0)
			break;
	}

	return sp;
}

ElfAuxVector *fetch_elf_aux_vectors(const Tracee *tracee, word_t address)
{
	if (!tracee || address == 0)
		return NULL;

	ElfAuxVector *vecs = talloc_array(tracee->ctx, ElfAuxVector, 1);
	if (!vecs)
		return NULL;

	vecs[0].type = AT_NULL;
	vecs[0].value = 0;

	word_t ws = sizeof_word(tracee);
	while (1) {
		word_t type = peek_word(tracee, address);
		if (errno != 0)
			goto error;
		address += ws;

		if (type == AT_NULL)
			break;

		word_t value = peek_word(tracee, address);
		if (errno != 0)
			goto error;
		address += ws;

		if (add_elf_aux_vector(&vecs, type, value) < 0)
			goto error;
	}

	return vecs;

error:
	talloc_free(vecs);
	return NULL;
}

int push_elf_aux_vectors(const Tracee *tracee, ElfAuxVector *vectors, word_t address)
{
	if (!tracee || !vectors)
		return -EINVAL;

	word_t ws = sizeof_word(tracee);
	size_t i;

	for (i = 0; vectors[i].type != AT_NULL; i++) {
		poke_word(tracee, address, vectors[i].type);
		if (errno != 0) return -errno;
		address += ws;

		poke_word(tracee, address, vectors[i].value);
		if (errno != 0) return -errno;
		address += ws;
	}

	poke_word(tracee, address, AT_NULL);
	if (errno != 0) return -errno;
	address += ws;

	poke_word(tracee, address, 0);
	if (errno != 0) return -errno;

	return 0;
}
