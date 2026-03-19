#ifndef ELF_H
#define ELF_H

#define EI_NIDENT 16

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint32_t e_entry;
	uint32_t e_phoff;
	uint32_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} ElfHeader32;

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} ElfHeader64;

typedef union {
	ElfHeader32 class32;
	ElfHeader64 class64;
} ElfHeader;

typedef struct {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
} ProgramHeader32;

typedef struct {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
} ProgramHeader64;

typedef union {
	ProgramHeader32 class32;
	ProgramHeader64 class64;
} ProgramHeader;

#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4

#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef enum {
	PT_LOAD    = 1,
	PT_DYNAMIC = 2,
	PT_INTERP  = 3,
	PT_GNU_STACK = 0x6474e551,
} SegmentType;

typedef struct {
	int32_t d_tag;
	uint32_t d_val;
} DynamicEntry32;

typedef struct {
	int64_t d_tag;
	uint64_t d_val;
} DynamicEntry64;

typedef union {
	DynamicEntry32 class32;
	DynamicEntry64 class64;
} DynamicEntry;

typedef enum {
	DT_STRTAB  = 5,
	DT_RPATH   = 15,
	DT_RUNPATH = 29
} DynamicType;

#define ELF_IDENT(header, index) ((header).class32.e_ident[(index)])
#define ELF_CLASS(header) ELF_IDENT(header, 4)
#define IS_CLASS32(header) (ELF_CLASS(header) == 1)
#define IS_CLASS64(header) (ELF_CLASS(header) == 2)

#define ELF_FIELD(header, field) \
	(IS_CLASS64(header) ? (header).class64.e_##field : (header).class32.e_##field)

#define PROGRAM_FIELD(ehdr, phdr, field) \
	(IS_CLASS64(ehdr) ? (phdr).class64.p_##field : (phdr).class32.p_##field)

#define DYNAMIC_FIELD(ehdr, dynent, field) \
	(IS_CLASS64(ehdr) ? (dynent).class64.d_##field : (dynent).class32.d_##field)

#define KNOWN_PHENTSIZE(header, size) \
	((IS_CLASS32(header) && (size) == sizeof(ProgramHeader32)) || \
	 (IS_CLASS64(header) && (size) == sizeof(ProgramHeader64)))

#define IS_POSITION_INDEPENDANT(elf_header) \
	(ELF_FIELD((elf_header), type) == ET_DYN)

#include "tracee/tracee.h"

extern int open_elf(const char *t_path, ElfHeader *elf_header);
extern bool is_host_elf(const Tracee *tracee, const char *t_path);

typedef int (*program_headers_iterator_t)(
	const ElfHeader *elf_header,
	const ProgramHeader *program_header,
	void *data);

extern int iterate_program_headers(
	const Tracee *tracee,
	int fd,
	const ElfHeader *elf_header,
	program_headers_iterator_t callback,
	void *data);

#endif /* ELF_H */
