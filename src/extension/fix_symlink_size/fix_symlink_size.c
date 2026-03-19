/*
 * Copyright (C) 2026 Scicat
 *
 * This file is part of proot-scicat.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "path/path.h"
#include "arch.h"
#include "attribute.h"

#define PREFIX ".proot.l2s."
#define DELETED_SUFFIX " (deleted)"

/**
 * Make fake hard links look like real ones regarding link count and inode.
 * Return -errno on error, 0 otherwise.
 */
static int handle_sysexit_end(Tracee *tracee)
{
    word_t sysnum = get_sysnum(tracee, ORIGINAL);

    switch (sysnum) {
    case PR_lstat64:
    case PR_lstat: {
        word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if (result != 0)
            return 0;

        char original[PATH_MAX];
        ssize_t size = read_string(tracee, original, peek_reg(tracee, MODIFIED, SYSARG_1), PATH_MAX);
        if (size < 0)
            return size;
        if (size >= PATH_MAX)
            return -ENAMETOOLONG;

        struct stat statl;
        if (lstat(original, &statl) < 0)
            return -errno;

        if (!S_ISLNK(statl.st_mode))
            return 0;

        char intermediate[PATH_MAX];
        size = readlink(original, intermediate, PATH_MAX);
        if (size < 0)
            return -errno;

        read_data(tracee, &statl, peek_reg(tracee, ORIGINAL, SYSARG_2), sizeof(statl));
        statl.st_size = (off_t)size;
        return write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), &statl, sizeof(statl));
    }

    default:
        return 0;
    }
}

/**
 * Extension callback: fix st_size for symlinks.
 */
int fix_symlink_size_callback(Extension *extension, ExtensionEvent event,
                              intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        static FilteredSysnum filtered_sysnums[] = {
            { PR_lstat,     FILTER_SYSEXIT },
            { PR_lstat64,   FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_EXIT_END:
        return handle_sysexit_end(TRACEE(extension));

    default:
        return 0;
    }
}
