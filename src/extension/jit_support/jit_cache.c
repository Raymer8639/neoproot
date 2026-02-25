#include "jit_cache.h"
#include <stdlib.h>
#include <string.h>

#define JIT_CACHE_MAX 1024
static JitCacheEntry *cache_head = NULL;
static size_t cache_count = 0;

void jit_cache_init(void)
{
    cache_head = NULL;
    cache_count = 0;
}

JitCacheEntry *jit_cache_lookup(void *addr)
{
    JitCacheEntry *e;
    for (e = cache_head; e; e = e->next) {
        if (e->addr == addr)
            return e;
    }
    return NULL;
}

void jit_cache_insert(void *addr, const void *code, size_t size)
{
    if (!code || size == 0 || cache_count >= JIT_CACHE_MAX)
        return;

    JitCacheEntry *exist = jit_cache_lookup(addr);
    if (exist) {
        if (exist->size == size)
            return;
        free(exist->code);
        exist->code = malloc(size);
        exist->size = size;
        memcpy(exist->code, code, size);
        return;
    }

    JitCacheEntry *e = malloc(sizeof(*e));
    if (!e) return;

    e->addr = addr;
    e->code = malloc(size);
    e->size = size;
    memcpy(e->code, code, size);
    e->next = cache_head;
    cache_head = e;
    cache_count++;
}
