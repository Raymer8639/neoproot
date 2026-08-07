#include <sys/types.h>
#include <limits.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <arm_neon.h>
#include <arm_acle.h>

#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"

#define STAT_CACHE_SIZE      64
#define STAT_CACHE_MASK      (STAT_CACHE_SIZE - 1)
#define STAT_CACHE_PROBE     8
#define CACHE_ALIGN          __attribute__((aligned(64)))
#define NEON_VEC_BYTES        16

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

typedef struct CACHE_ALIGN {
    char     path[PATH_MAX];
    struct   stat st;
    uint32_t crc;
    unsigned valid    : 1;
    unsigned lru_time : 31;
} StatCacheEntry;

static StatCacheEntry stat_cache[STAT_CACHE_SIZE] CACHE_ALIGN;
static unsigned int   stat_cache_clock = 0;

static ALWAYS_INLINE size_t neon_strlen_fast(const char *s) {
    if (UNLIKELY(!s || !*s)) return 0;
    const uint8_t *p = (const uint8_t *)s;
    uint8x16_t zero = vdupq_n_u8(0);
    size_t i = 0;
    for (; (uintptr_t)(p + i) % NEON_VEC_BYTES != 0; i++)
        if (UNLIKELY(!p[i])) return i;
    for (;; i += NEON_VEC_BYTES) {
        uint8x16_t v = vld1q_u8(p + i);
        uint8x16_t mask = vceqq_u8(v, zero);
        if (vmaxvq_u8(mask)) {
            for (size_t j = 0; j < NEON_VEC_BYTES; j++)
                if (UNLIKELY(!p[i + j])) return i + j;
        }
    }
}

static ALWAYS_INLINE int neon_strcmp_fast(const char *a, const char *b) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    size_t i = 0;
    /* 逐字节对齐到 16 字节边界（短字符串如 "."、".."、组件名在此即返回） */
    for (; (uintptr_t)(pa + i) % NEON_VEC_BYTES != 0; i++) {
        unsigned char ca = pa[i], cb = pb[i];
        if (UNLIKELY(ca != cb)) return ca - cb;
        if (UNLIKELY(ca == '\0')) return 0;
    }
    uint8x16_t zero = vdupq_n_u8(0);
    for (;; i += NEON_VEC_BYTES) {
        uint8x16_t va = vld1q_u8(pa + i);
        uint8x16_t vb = vld1q_u8(pb + i);
        uint8x16_t eq  = vceqq_u8(va, vb);           /* 相等 → 0xFF */
        uint8x16_t za  = vceqq_u8(va, zero);         /* a 结束 → 0xFF（相等时 b 同步结束） */
        uint8x16_t stop = vmaxq_u8(vmvnq_u8(eq), za); /* 不等 或 a 结束 */
        if (vmaxvq_u8(stop) != 0) {
            for (size_t j = 0; j < NEON_VEC_BYTES; j++) {
                unsigned char ca = pa[i + j], cb = pb[i + j];
                if (UNLIKELY(ca != cb)) return ca - cb;
                if (UNLIKELY(ca == '\0')) return 0;
            }
        }
    }
}

/* 复制 C 字符串（含终止符），不做尾部清零（比 memset PATH_MAX 快得多） */
static ALWAYS_INLINE void neon_strcpy_fast(char *restrict d, const char *restrict s) {
    size_t i = 0;
    for (;; i += NEON_VEC_BYTES) {
        uint8x16_t v = vld1q_u8((const uint8_t *)(s + i));
        vst1q_u8((uint8_t *)(d + i), v);
        if (vmaxvq_u8(vceqq_u8(v, vdupq_n_u8(0))) != 0)
            return;  /* 已复制终止符 */
    }
}

/* 复制已知长度的组件（含终止符） */
static ALWAYS_INLINE void copy_component(char *restrict d, const char *restrict s, size_t len) {
    size_t i = 0;
    for (; i + NEON_VEC_BYTES <= len; i += NEON_VEC_BYTES)
        vst1q_u8((uint8_t *)(d + i), vld1q_u8((const uint8_t *)(s + i)));
    for (; i < len; i++) d[i] = s[i];
    d[len] = '\0';
}

static ALWAYS_INLINE uint32_t crc32_path(const char *s, size_t len) {
    uint32_t crc = 0xFFFFFFFFU;
    const uint8_t *p = (const uint8_t *)s;
    while (len >= 4) {
        crc = __crc32w(crc, *(const uint32_t *)p);
        p += 4; len -= 4;
    }
    while (len >= 1) {
        crc = __crc32b(crc, *p);
        p += 1; len -= 1;
    }
    return crc;
}

static int stat_cache_lookup(const char *restrict path, struct stat *restrict out_st) {
    size_t len = neon_strlen_fast(path);
    uint32_t h = crc32_path(path, len);
    unsigned slot = h & STAT_CACHE_MASK;
    /* crc32 直接索引 + 短线性探测；空槽终止（插入保证连续性） */
    for (unsigned i = 0; i < STAT_CACHE_PROBE; i++) {
        StatCacheEntry *e = &stat_cache[(slot + i) & STAT_CACHE_MASK];
        if (UNLIKELY(!e->valid)) return -ENOENT;
        if (e->crc != h) continue;
        if (LIKELY(neon_strcmp_fast(e->path, path) == 0)) {
            *out_st = e->st;
            e->lru_time = ++stat_cache_clock;
            return 0;
        }
    }
    return -ENOENT;
}

static void stat_cache_insert(const char *restrict path, const struct stat *restrict st) {
    size_t len = neon_strlen_fast(path);
    uint32_t h = crc32_path(path, len);
    unsigned slot = h & STAT_CACHE_MASK;
    for (unsigned i = 0; i < STAT_CACHE_PROBE; i++) {
        StatCacheEntry *e = &stat_cache[(slot + i) & STAT_CACHE_MASK];
        if (UNLIKELY(!e->valid)) {
            neon_strcpy_fast(e->path, path);
            e->st = *st;
            e->crc = h;
            e->valid = 1;
            e->lru_time = ++stat_cache_clock;
            return;
        }
    }
    /* 探测窗口全满：替换窗口内最老的项 */
    StatCacheEntry *victim = &stat_cache[slot & STAT_CACHE_MASK];
    for (unsigned i = 1; i < STAT_CACHE_PROBE; i++) {
        StatCacheEntry *e = &stat_cache[(slot + i) & STAT_CACHE_MASK];
        if (e->lru_time < victim->lru_time)
            victim = e;
    }
    neon_strcpy_fast(victim->path, path);
    victim->st = *st;
    victim->crc = h;
    victim->valid = 1;
    victim->lru_time = ++stat_cache_clock;
}

static ALWAYS_INLINE void pop_component(char *restrict path) {
    if (UNLIKELY(!path || *path != '/')) return;
    int len = neon_strlen_fast(path) - 1;
    if (len <= 0) return;
    while (len > 1 && path[len] == '/') len--;
    while (len > 1 && path[len] != '/') len--;
    path[len] = '\0';
}

static ALWAYS_INLINE Finality next_component(char component[NAME_MAX], const char **restrict cursor) {
    if (UNLIKELY(!component || !cursor || !*cursor)) return FINAL_NORMAL;
    while (**cursor == '/') (*cursor)++;
    const char *start = *cursor;
    while (**cursor && **cursor != '/') (*cursor)++;
    size_t len = *cursor - start;
    if (UNLIKELY(len >= NAME_MAX)) return -ENAMETOOLONG;
    copy_component(component, start, len);
    int want_dir = (**cursor == '/');
    while (**cursor == '/') (*cursor)++;
    if (!**cursor) return want_dir ? FINAL_SLASH : FINAL_NORMAL;
    return NOT_FINAL;
}

static int substitute_binding_stat(Tracee *restrict tracee, Finality finality,
                                   unsigned int recursion_level,
                                   const char guest_path[PATH_MAX],
                                   char host_path[PATH_MAX]) {
    struct stat statl;
    int res;
    neon_strcpy_fast(host_path, guest_path);
    res = substitute_binding(tracee, GUEST, host_path);
    if (UNLIKELY(res < 0)) return res;
    if (tracee->glue_type == 0) {
        res = notify_extensions(tracee, HOST_PATH, (intptr_t)host_path,
                                IS_FINAL(finality) && recursion_level == 0);
        if (UNLIKELY(res < 0)) return res;
    }
    if (LIKELY(stat_cache_lookup(host_path, &statl) == 0)) {
        res = 0;
    } else if (should_skip_file_access_due_to_f2fs_bug(tracee, host_path)) {
        res = -ENOENT;
    } else {
        res = lstat(host_path, &statl);
        if (UNLIKELY(res < 0 && errno == EACCES)) {
            if (neon_strcmp_fast(host_path, "/linkerconfig") == 0 ||
                neon_strcmp_fast(host_path, "/system")     == 0 ||
                neon_strcmp_fast(host_path, "/vendor")     == 0) {
                res = 0;
                statl.st_mode = S_IFDIR | 0755;
            }
        }
        if (LIKELY(res == 0))
            stat_cache_insert(host_path, &statl);
    }
    if (UNLIKELY(res < 0 && tracee->glue_type != 0)) {
        statl.st_mode = build_glue(tracee, guest_path, host_path, finality);
        if (UNLIKELY(statl.st_mode == 0)) return -1;
        res = 0;
    }
    if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode) && !S_ISLNK(statl.st_mode))
        return res < 0 ? -ENOENT : -ENOTDIR;
    return S_ISLNK(statl.st_mode) ? 1 : 0;
}

int canonicalize(Tracee *restrict tracee, const char *restrict user_path,
                 bool deref_final, char guest_path[PATH_MAX],
                 unsigned int recursion_level) {
    char scratch_path[PATH_MAX];
    Finality fin;
    const char *cursor;
    int res;
    if (UNLIKELY(recursion_level > MAXSYMLINKS)) return -ELOOP;
    if (UNLIKELY(!user_path || !guest_path)) return -EINVAL;
    if (UNLIKELY(neon_strlen_fast(user_path) >= PATH_MAX)) return -ENAMETOOLONG;
    if (user_path[0] != '/') {
        if (guest_path[0] != '/') {
            if (recursion_level == 0) {
                guest_path[0] = '/'; guest_path[1] = 0;
            } else return -EINVAL;
        }
    } else {
        guest_path[0] = '/'; guest_path[1] = 0;
    }
    cursor = user_path;
    fin = NOT_FINAL;
    while (!IS_FINAL(fin)) {
        char comp[NAME_MAX];
        char host_path[PATH_MAX];
        fin = next_component(comp, &cursor);
        if (UNLIKELY((int)fin < 0)) return (int)fin;
        if (neon_strcmp_fast(comp, ".") == 0) {
            if (IS_FINAL(fin)) fin = FINAL_DOT;
            continue;
        }
        if (neon_strcmp_fast(comp, "..") == 0) {
            pop_component(guest_path);
            if (IS_FINAL(fin)) fin = FINAL_SLASH;
            continue;
        }
        res = join_paths(2, scratch_path, guest_path, comp);
        if (UNLIKELY(res < 0)) return res;
        res = substitute_binding_stat(tracee, fin, recursion_level, scratch_path, host_path);
        if (UNLIKELY(res < 0)) return res;
        if (res <= 0 || (fin == FINAL_NORMAL && !deref_final)) {
            neon_strcpy_fast(scratch_path, guest_path);
            res = join_paths(2, guest_path, scratch_path, comp);
            if (UNLIKELY(res < 0)) return res;
            continue;
        }
        Comparison cmp = compare_paths("/proc", guest_path);
        if (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX) {
            res = readlink_proc(tracee, scratch_path, guest_path, comp, cmp);
            if (res == CANONICALIZE) goto canon_symlink;
            if (res == DONT_CANONICALIZE) {
                if (fin == FINAL_NORMAL) {
                    neon_strcpy_fast(guest_path, scratch_path);
                    return 0;
                }
            } else if (UNLIKELY(res < 0)) return res;
        }
        res = readlink(host_path, scratch_path, PATH_MAX - 1);
        if (UNLIKELY(res < 0)) return res;
        if (UNLIKELY((size_t)res >= PATH_MAX)) return -ENAMETOOLONG;
        scratch_path[res] = '\0';
        res = detranslate_path(tracee, scratch_path, host_path);
        if (UNLIKELY(res < 0)) return res;
canon_symlink:
        res = canonicalize(tracee, scratch_path, true, guest_path, recursion_level + 1);
        if (UNLIKELY(res < 0)) return res;
        res = substitute_binding_stat(tracee, fin, recursion_level, guest_path, host_path);
        if (UNLIKELY(res < 0)) return res;
    }
    if (recursion_level == 0) {
        switch (fin) {
            case FINAL_SLASH:
                join_paths(2, scratch_path, guest_path, "");
                neon_strcpy_fast(guest_path, scratch_path);
                break;
            case FINAL_DOT:
                join_paths(2, scratch_path, guest_path, ".");
                neon_strcpy_fast(guest_path, scratch_path);
                break;
            default: break;
        }
    }
    return 0;
}