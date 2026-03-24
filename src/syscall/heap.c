#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "execve/execve.h"
#include "cli/note.h"
#include "compat.h"

#define DEBUG_BRK(...)

static word_t heap_offset = 0;

void translate_brk_enter(Tracee *tracee)
{
	word_t new_brk_address;
	size_t old_heap_size;
	size_t new_heap_size;

	if (tracee->heap->disabled)
		return;

	if (heap_offset == 0) {
		heap_offset = (word_t)sysconf(_SC_PAGE_SIZE);
		if ((ssize_t)heap_offset <= 0)
			heap_offset = 0x1000;
	}

	new_brk_address = peek_reg(tracee, CURRENT, SYSARG_1);
	DEBUG_BRK("brk(0x%lx)\n", new_brk_address);

	if (tracee->heap->base == 0) {
		Sysnum sysnum;
		Mapping *mappings;
		Mapping *bss;

		if (new_brk_address != 0) {
			if (tracee->verbose > 0)
				note(tracee, WARNING, INTERNAL,
					"process %d is doing suspicious brk()",	tracee->pid);
			return;
		}

		mappings = tracee->load_info->mappings;
		bss = &mappings[talloc_array_length(mappings) - 1];
		new_brk_address = bss->addr + bss->length;

		sysnum = detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER
			? PR_mmap2
			: PR_mmap;

		set_sysnum(tracee, sysnum);
		poke_reg(tracee, SYSARG_1, new_brk_address);
		poke_reg(tracee, SYSARG_2, heap_offset);
		poke_reg(tracee, SYSARG_3, PROT_READ | PROT_WRITE);
		poke_reg(tracee, SYSARG_4, MAP_PRIVATE | MAP_ANONYMOUS);
		poke_reg(tracee, SYSARG_5, (word_t)-1);
		poke_reg(tracee, SYSARG_6, 0);

		return;
	}

	if (new_brk_address < tracee->heap->base) {
		set_sysnum(tracee, PR_void);
		return;
	}

	new_heap_size = new_brk_address - tracee->heap->base;
	old_heap_size = tracee->heap->size;

	// 预分配 mremap 参数，避免重复分配
	static word_t mremap_args[5];
	mremap_args[0] = tracee->heap->base - heap_offset;
	mremap_args[1] = old_heap_size + heap_offset;
	mremap_args[2] = new_heap_size + heap_offset;
	mremap_args[3] = 0;
	mremap_args[4] = 0;

	set_sysnum(tracee, PR_mremap);
	poke_reg(tracee, SYSARG_1, mremap_args[0]);
	poke_reg(tracee, SYSARG_2, mremap_args[1]);
	poke_reg(tracee, SYSARG_3, mremap_args[2]);
	poke_reg(tracee, SYSARG_4, mremap_args[3]);
	poke_reg(tracee, SYSARG_5, mremap_args[4]);

	return;
}

void translate_brk_exit(Tracee *tracee)
{
	word_t result;
	word_t sysnum;
	long tracee_errno;

	if (tracee->heap->disabled)
		return;

	assert(heap_offset > 0);

	sysnum = get_sysnum(tracee, MODIFIED);
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	tracee_errno = (long)result;

	switch (sysnum) {
	case PR_void:
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mmap:
	case PR_mmap2:
		if (tracee_errno < 0 && tracee_errno > -4096) {
			poke_reg(tracee, SYSARG_RESULT, 0);
			break;
		}

		tracee->heap->base = result + heap_offset;
		tracee->heap->size = 0;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mremap:
		if ((tracee_errno < 0 && tracee_errno > -4096) ||
		    (tracee->heap->base != result + heap_offset)) {
			poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
			break;
		}

		tracee->heap->size = peek_reg(tracee, MODIFIED, SYSARG_3) - heap_offset;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_brk:
		if (result == peek_reg(tracee, ORIGINAL, SYSARG_1))
			tracee->heap->disabled = true;
		break;

	default:
		assert(0);
	}

	DEBUG_BRK("brk() = 0x%lx\n", peek_reg(tracee, CURRENT, SYSARG_RESULT));
}
