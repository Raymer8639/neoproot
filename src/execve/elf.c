/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of proot-scicat.
 *
 * Copyright (C) 2026 scicat
 *
 * This program is free software; you can redistribute it/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <talloc.h>

#include "execve/elf.h"
#include "tracee/tracee.h"
#include "cli/note.h"
#include "arch.h"
#include "compat.h"
#include "attribute.h"

static inline bool check_elf_ident(const ElfHeader *hdr)
{
    return (ELF_IDENT(*hdr, 0) == 0x7F
            && ELF_IDENT(*hdr, 1) == 'E'
            && ELF_IDENT(*hdr, 2) == 'L'
            && ELF_IDENT(*hdr, 3) == 'F');
}

int open_elf(const char *t_path, ElfHeader *elf_header)
{
    if (!t_path || !elf_header)
        return -EINVAL;

    size_t path_len = strlen(t_path);
    if (path_len >= PATH_MAX)
        return -ENAMETOOLONG;

    int fd = open(t_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    ssize_t nb = read(fd, elf_header, sizeof(ElfHeader));
    if (nb < 0) {
        close(fd);
        return -errno;
    }

    if ((size_t)nb < sizeof(ElfHeader) || !check_elf_ident(elf_header)) {
        close(fd);
        return -ENOEXEC;
    }

    if (!IS_CLASS32(*elf_header) && !IS_CLASS64(*elf_header)) {
        close(fd);
        return -ENOEXEC;
    }

    return fd;
}

int iterate_program_headers(const Tracee *tracee, int fd, const ElfHeader *elf_header,
                           program_headers_iterator_t callback, void *data)
{
    if (!elf_header || !callback)
        return -EINVAL;

    uint64_t phoff = ELF_FIELD(*elf_header, phoff);
    uint16_t phentsize = ELF_FIELD(*elf_header, phentsize);
    uint16_t phnum = ELF_FIELD(*elf_header, phnum);

    if (phnum >= 0xFFFF) {
        note(tracee, WARNING, INTERNAL, "big program header tables not supported");
        return -ENOTSUP;
    }

    if (!KNOWN_PHENTSIZE(*elf_header, phentsize)) {
        note(tracee, WARNING, INTERNAL, "unsupported program header size");
        return -ENOTSUP;
    }

    if (lseek(fd, phoff, SEEK_SET) < 0)
        return -errno;

    for (uint16_t i = 0; i < phnum; i++) {
        ProgramHeader ph;
        ssize_t nb = read(fd, &ph, phentsize);

        if (nb != phentsize)
            return (nb < 0) ? -errno : -ENOTSUP;

        int ret = callback(elf_header, &ph, data);
        if (ret != 0)
            return ret;
    }

    return 0;
}

bool is_host_elf(const Tracee *tracee, const char *host_path)
{
    static int cached_force_foreign = -1;
    if (cached_force_foreign < 0)
        cached_force_foreign = (getenv("PROOT_FORCE_FOREIGN_BINARY") != NULL);

    if (cached_force_foreign || !tracee->qemu)
        return false;

    static char cached_path[PATH_MAX] = { 0 };
    static bool cached_result = false;

    if (host_path && strcmp(host_path, cached_path) == 0)
        return cached_result;

    if (!host_path || strlen(host_path) >= PATH_MAX) {
        cached_path[0] = '\0';
        cached_result = false;
        return false;
    }

    ElfHeader hdr;
    int fd = open_elf(host_path, &hdr);
    if (fd < 0) {
        strncpy(cached_path, host_path, PATH_MAX - 1);
        cached_result = false;
        return false;
    }
    close(fd);

    uint16_t machine = ELF_FIELD(hdr, machine);
    bool match = false;

    // 修复：HOST_ELF_MACHINE 展开为 {x,0}，必须用数组形式
    const int host_machines[] = HOST_ELF_MACHINE;
    for (int i = 0; host_machines[i] != 0; i++) {
        if (host_machines[i] == machine) {
            match = true;
            break;
        }
    }

    strncpy(cached_path, host_path, PATH_MAX - 1);
    cached_result = match;
    return match;
}
