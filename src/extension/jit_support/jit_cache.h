#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct JitCacheEntry {
    void *addr;
    uint8_t *code;
    size_t size;
    struct JitCacheEntry *next;
} JitCacheEntry;

void jit_cache_init(void);
JitCacheEntry *jit_cache_lookup(void *addr);
void jit_cache_insert(void *addr, const void *code, size_t size);
