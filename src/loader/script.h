#ifndef SCRIPT
#define SCRIPT

#include "arch.h"
#include "attribute.h"

struct load_statement {
	word_t action;

	union {
		struct {
			word_t string_address;
		} open;

		struct {
			word_t addr;
			word_t length;
			word_t prot;
			word_t offset;
			word_t clear_length;
		} mmap;

		struct {
			word_t start;
		} make_stack_exec;

		struct {
			word_t stack_pointer;
			word_t entry_point;
			word_t at_phdr;
			word_t at_phent;
			word_t at_phnum;
			word_t at_entry;
			word_t at_execfn;
		} start;
	};
} PACKED;

typedef struct load_statement LoadStatement;

#define LOAD_STATEMENT_SIZE(statement, type) \
	(sizeof((statement).action) + sizeof((statement).type))

/* Don't use enum, since sizeof(enum) doesn't have to be equal to
 * sizeof(word_t).  Keep values in the same order as their respective
 * actions appear in loader.c to get a change GCC produces a jump
 * table.  */
#define LOAD_ACTION_OPEN_NEXT		0
#define LOAD_ACTION_OPEN		1
#define LOAD_ACTION_MMAP_FILE		2
#define LOAD_ACTION_MMAP_ANON		3
#define LOAD_ACTION_MAKE_STACK_EXEC	4
#define LOAD_ACTION_START_TRACED	5
#define LOAD_ACTION_START		6

#endif /* SCRIPT */
