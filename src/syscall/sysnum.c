/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2026 scicat
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <assert.h>
#include <stddef.h>

#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/abi.h"
#include "tracee/reg.h"
#include "arch.h"
#include "cli/note.h"

#include SYSNUMS_HEADER1
#ifdef SYSNUMS_HEADER2
# include SYSNUMS_HEADER2
#endif
#ifdef SYSNUMS_HEADER3
# include SYSNUMS_HEADER3
#endif

typedef struct {
    const Sysnum *table;
    size_t       length;
    word_t       offset;
} Sysnums;

static void get_sysnums(Abi abi, Sysnums *sysnums)
{
    switch (abi) {
        case ABI_DEFAULT:
            sysnums->table  = SYSNUMS_ABI1;
            sysnums->length = sizeof(SYSNUMS_ABI1) / sizeof(Sysnum);
            sysnums->offset = 0;
            break;

#ifdef SYSNUMS_ABI2
        case ABI_2:
            sysnums->table  = SYSNUMS_ABI2;
            sysnums->length = sizeof(SYSNUMS_ABI2) / sizeof(Sysnum);
            sysnums->offset = 0;
            break;
#endif

#ifdef SYSNUMS_ABI3
        case ABI_3:
            sysnums->table  = SYSNUMS_ABI3;
            sysnums->length = sizeof(SYSNUMS_ABI3) / sizeof(Sysnum);
            sysnums->offset = 0x40000000; /* x32 */
            break;
#endif

        default:
            assert(!"invalid ABI");
            sysnums->table  = NULL;
            sysnums->length = 0;
            sysnums->offset = 0;
            break;
    }
}

Sysnum translate_sysnum(Abi abi, word_t sysnum)
{
    Sysnums sysnums;
    size_t index;

    get_sysnums(abi, &sysnums);

    if (sysnum < sysnums.offset)
        return PR_void;

    index = sysnum - sysnums.offset;
    if (index >= sysnums.length)
        return PR_void;

    return sysnums.table[index];
}

word_t detranslate_sysnum(Abi abi, Sysnum sysnum)
{
    Sysnums sysnums;
    size_t i;

    if (sysnum == PR_void)
        return SYSCALL_AVOIDER;

    get_sysnums(abi, &sysnums);

    for (i = 0; i < sysnums.length; i++) {
        if (sysnums.table[i] == sysnum)
            return i + sysnums.offset;
    }

    return SYSCALL_AVOIDER;
}

Sysnum get_sysnum(const Tracee *tracee, RegVersion version)
{
    return translate_sysnum(get_abi(tracee), peek_reg(tracee, version, SYSARG_NUM));
}

void set_sysnum(Tracee *tracee, Sysnum sysnum)
{
    word_t arch_num = detranslate_sysnum(get_abi(tracee), sysnum);
    poke_reg(tracee, SYSARG_NUM, arch_num);
}

const char *stringify_sysnum(Sysnum sysnum)
{
#define SYSNUM(item) [PR_##item] = #item,
    static const char *names[] = {
#include "syscall/sysnums.list"
    };
#undef SYSNUM

    if (sysnum == PR_void)
        return "void";
    if (sysnum >= PR_NB_SYSNUM)
        return "";

    return names[sysnum];
}
