#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <stdatomic.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "syscall/sysnum.h"
#include "execve/execve.h"
#include "cli/note.h"
#include "compat.h"

#define DEBUG_BRK(...)

static atomic_size_t heap_page_size;

void translate_brk_enter(Tracee *tracee)
{
	word_t new_brk;
	size_t old_size, new_size;

	if (tracee->heap->disabled)
		return;

	size_t pg_sz = atomic_load(&heap_page_size);

	// ARMv8.2 页面大小一次初始化
	if (pg_sz == 0) {
		long pg = sysconf(_SC_PAGE_SIZE);
		pg_sz = (pg > 0) ? (size_t)pg : 0x1000;
		atomic_store(&heap_page_size, pg_sz);
	}

	new_brk = peek_reg(tracee, CURRENT, SYSARG_1);
	DEBUG_BRK("brk(0x%lx)\n", new_brk);

	// 第一次初始化 heap
	if (tracee->heap->base == 0) {
		Sysnum sysnum;
		Mapping *mappings;
		Mapping *bss;

		if (new_brk != 0) {
			if (tracee->verbose > 0)
				note(tracee, WARNING, INTERNAL, "suspicious brk() from pid %d", tracee->pid);
			return;
		}

		mappings = tracee->load_info->mappings;
		bss = &mappings[talloc_array_length(mappings) - 1];
		new_brk = bss->addr + bss->length;

		// ARM64 优先 mmap
		sysnum = (detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER) ? PR_mmap2 : PR_mmap;

		set_sysnum(tracee, sysnum);
		poke_reg(tracee, SYSARG_1, new_brk);
		poke_reg(tracee, SYSARG_2, pg_sz);
		poke_reg(tracee, SYSARG_3, PROT_READ | PROT_WRITE);
		poke_reg(tracee, SYSARG_4, MAP_PRIVATE | MAP_ANONYMOUS);
		poke_reg(tracee, SYSARG_5, (word_t)-1);
		poke_reg(tracee, SYSARG_6, 0);
		return;
	}

	// 地址低于基址 → 直接忽略
	if (new_brk < tracee->heap->base) {
		set_sysnum(tracee, PR_void);
		return;
	}

	old_size = tracee->heap->size;
	new_size = new_brk - tracee->heap->base;

	// 替换为 mremap 扩容（ARM64 高效）
	set_sysnum(tracee, PR_mremap);
	poke_reg(tracee, SYSARG_1, tracee->heap->base - pg_sz);
	poke_reg(tracee, SYSARG_2, old_size + pg_sz);
	poke_reg(tracee, SYSARG_3, new_size + pg_sz);
	poke_reg(tracee, SYSARG_4, 0);
	poke_reg(tracee, SYSARG_5, 0);
}

void translate_brk_exit(Tracee *tracee)
{
	word_t result;
	Sysnum sysnum;
	long err;

	if (tracee->heap->disabled)
		return;

	size_t pg_sz = atomic_load(&heap_page_size);
	assert(pg_sz != 0);

	sysnum = get_sysnum(tracee, MODIFIED);
	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	err = (long)result;

	switch (sysnum) {
	case PR_void:
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_mmap:
	case PR_mmap2:
		// 错误则返回 0
		if (err < 0 && err > -4096) {
			poke_reg(tracee, SYSARG_RESULT, 0);
			break;
		}

		tracee->heap->base = result + pg_sz;
		tracee->heap->size = 0;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base);
		break;

	case PR_mremap:
		// 失败或地址不匹配 → 保持原状
		if ((err < 0 && err > -4096) || (tracee->heap->base != result + pg_sz)) {
			poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
			break;
		}

		tracee->heap->size = peek_reg(tracee, MODIFIED, SYSARG_3) - pg_sz;
		poke_reg(tracee, SYSARG_RESULT, tracee->heap->base + tracee->heap->size);
		break;

	case PR_brk:
		// 内核直接处理 → 禁用模拟
		if (result == peek_reg(tracee, ORIGINAL, SYSARG_1))
			tracee->heap->disabled = true;
		break;

	default:
		assert(0);
	}

	DEBUG_BRK("brk() => 0x%lx\n", peek_reg(tracee, CURRENT, SYSARG_RESULT));
}
