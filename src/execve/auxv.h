
#ifndef AUXV_H
#define AUXV_H

#include "tracee/tracee.h"
#include "arch.h"

typedef struct elf_aux_vector {
	word_t type;
	word_t value;
} ElfAuxVector;

extern word_t get_elf_aux_vectors_address(const Tracee *tracee);
extern ElfAuxVector *fetch_elf_aux_vectors(const Tracee *tracee, word_t address);
extern int add_elf_aux_vector(ElfAuxVector **vectors, word_t type, word_t value);
extern int push_elf_aux_vectors(const Tracee *tracee, ElfAuxVector *vectors, word_t address);

#endif /* AUXV_H */
