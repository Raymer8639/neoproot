#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <talloc.h>

#include "execve/elf.h"
#include "tracee/tracee.h"
#include "cli/note.h"
#include "arch.h"
#include "compat.h"

/* 精简版字符串函数，Bionic/ARM64 专用 */
static inline size_t fast_strnlen(const char *s, size_t maxlen)
{
    size_t len = 0;
    while (len < maxlen && s[len])
        len++;
    return len;
}

static inline int fast_strcmp(const char *a, const char *b)
{
    while (*a && *b && *a == *b)
        a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}

static inline void fast_strcpy(char *dst, const char *src, size_t max)
{
    size_t i;
    for (i = 0; i < max-1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = 0;
}

/* ELF 魔数校验 */
static inline bool check_elf_ident(const ElfHeader *hdr)
{
    return (ELF_IDENT(*hdr, 0) == 0x7F
            && ELF_IDENT(*hdr, 1) == 'E'
            && ELF_IDENT(*hdr, 2) == 'L'
            && ELF_IDENT(*hdr, 3) == 'F');
}

/* 打开并校验 ELF（仅支持 AArch64-64） */
int open_elf(const char *t_path, ElfHeader *elf_header)
{
    if (!t_path || !elf_header)
        return -EINVAL;

    if (fast_strnlen(t_path, PATH_MAX) >= PATH_MAX)
        return -ENAMETOOLONG;

    int fd = open(t_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    ssize_t nb = read(fd, elf_header, sizeof(ElfHeader));
    if (nb < (ssize_t)sizeof(ElfHeader)) {
        close(fd);
        return nb < 0 ? -errno : -ENOEXEC;
    }

    if (!check_elf_ident(elf_header) || !IS_CLASS64(*elf_header)) {
        close(fd);
        return -ENOEXEC;
    }

    return fd;
}

/* 遍历 program header（AArch64  phentsize 固定） */
int iterate_program_headers(const Tracee *tracee, int fd, const ElfHeader *elf_header,
                            program_headers_iterator_t callback, void *data)
{
    uint64_t phoff     = ELF_FIELD(*elf_header, phoff);
    uint16_t phentsize = ELF_FIELD(*elf_header, phentsize);
    uint16_t phnum     = ELF_FIELD(*elf_header, phnum);

    if (phnum == 0 || phentsize != sizeof(ProgramHeader))
        return -ENOTSUP;

    if (lseek(fd, phoff, SEEK_SET) < 0)
        return -errno;

    for (uint16_t i = 0; i < phnum; i++) {
        ProgramHeader ph;
        ssize_t nb = read(fd, &ph, sizeof(ph));

        if (nb != sizeof(ph))
            return nb < 0 ? -errno : -ENOTSUP;

        int ret = callback(elf_header, &ph, data);
        if (ret != 0)
            return ret;
    }

    return 0;
}

/* 判断是否为本机 ARM64 ELF（带轻量缓存） */
bool is_host_elf(const Tracee *tracee, const char *host_path)
{
    static const int host_machines[] = HOST_ELF_MACHINE;
    static int force_foreign = -1;
    static char cache_path[PATH_MAX];
    static bool cache_res;

    if (force_foreign < 0)
        force_foreign = getenv("PROOT_FORCE_FOREIGN_BINARY") != NULL;

    if (force_foreign || !tracee->qemu || !host_path)
        return false;

    /* 快速缓存命中 */
    if (fast_strcmp(host_path, cache_path) == 0)
        return cache_res;

    /* 缓存失效 */
    fast_strcpy(cache_path, host_path, PATH_MAX);

    ElfHeader hdr;
    int fd = open_elf(host_path, &hdr);
    if (fd < 0)
        return cache_res = false;
    close(fd);

    uint16_t machine = ELF_FIELD(hdr, machine);
    bool match = false;

    for (int i = 0; host_machines[i] != 0; i++) {
        if (host_machines[i] == machine) {
            match = true;
            break;
        }
    }

    return cache_res = match;
}
