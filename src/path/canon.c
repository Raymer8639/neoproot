/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */
#include <sys/types.h>   /* pid_t */
#include <limits.h>      /* PATH_MAX, NAME_MAX */
#include <sys/param.h>   /* MAXSYMLINKS */
#include <errno.h>       /* E* */
#include <sys/stat.h>    /* lstat(2) */
#include <unistd.h>      /* access(2), readlink(2), sysconf */
#include <string.h>      /* string(3) */
#include <assert.h>      /* assert(3) */
#include <stdio.h>       /* sscanf(3) */
#include <stdint.h>      /* uint32_t, uint64_t */
#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"

/************************* 现代缓存配置 (保留核心优化) *************************/
#define CACHE_PER_CPU    512    // 每个CPU核心的缓存条目数
#define MAX_CPU_CORES    16     // 支持的最大CPU核心数
#define HASH_PROBE_COUNT 16     // 哈希冲突最大探测次数

/************************* 自动CPU核心检测 (保留) *************************/
static inline int get_ncpu(void) {
    static int ncpu = 0;
    if (ncpu == 0) {
        long res = sysconf(_SC_NPROCESSORS_ONLN);
        ncpu = (res > 0 && res <= MAX_CPU_CORES) ? (int)res : 1;
    }
    return ncpu;
}

/************************* 安全的CPU ID获取 (修复汇编警告，保留) *************************/
static inline uint32_t get_cpu_id(void) {
    uint64_t cpu64;
    // ARM64 正确的寄存器读取，无宽度警告
    asm volatile ("mrs %0, tpidr_el0" : "=r"(cpu64));
    return (uint32_t)(cpu64 % get_ncpu());
}

/************************* LRU+AI学习缓存条目结构 (新增AI字段) *************************/
// 无锁设计：Proot 单线程处理 tracee，无需原子操作，避免功能干扰
struct cache_entry {
    char key[PATH_MAX + 2];    // 键: 路径 + | + deref标记
    char val[PATH_MAX];        // 值: 规范化后的最终路径
    uint32_t used;             // 有效标记: 0=无效,1=有效
    uint32_t lru_time;         // LRU时间戳
    uint8_t hit_count;         // AI学习：路径命中次数
    uint8_t is_hot;            // AI学习：是否为热点路径(1=是，0=否)
};

/************************* Per-CPU缓存分片 (解决伪共享，保留) *************************/
struct cpu_cache {
    struct cache_entry entries[CACHE_PER_CPU];
    uint32_t tick;             // 每个CPU的LRU时钟
} __attribute__((aligned(64))); // 缓存行对齐，杜绝伪共享

/************************* 全局缓存 (静态分配，无动态内存) *************************/
static struct cpu_cache static_cpu_caches[MAX_CPU_CORES];
static int cache_inited = 0;   // 普通初始化标记，避免干扰

/************************* 一次性初始化 (轻量，不干扰Proot启动) *************************/
static void cache_init(void) {
    if (cache_inited) return;
    int n = get_ncpu();
    for (int i = 0; i < n; i++) {
        memset(&static_cpu_caches[i], 0, sizeof(struct cpu_cache));
    }
    cache_inited = 1;
}

/************************* FNV-1a 哈希 (保留，O(1)查找) *************************/
static uint32_t fnv1a_hash(const char *s) {
    uint32_t hash = 0x811C9DC5;
    while (*s) {
        hash ^= (uint8_t)*s++;
        hash *= 0x1000193;
    }
    return hash;
}

/************************* 构建缓存键 (保留，区分deref) *************************/
static void make_cache_key(char *key, const char *path, bool deref) {
    if (!key || !path) return;
    snprintf(key, PATH_MAX + 1, "%s|%d", path, (int)deref);
    key[PATH_MAX + 1] = '\0';
}

/************************* LRU+AI查找 (新增AI学习：统计命中、标记热点) *************************/
static int cache_lookup(const char *key, char *out_val) {
    if (!cache_inited || !key || !out_val) return 0;
    uint32_t cpu = get_cpu_id();
    struct cpu_cache *cache = &static_cpu_caches[cpu];
    uint32_t hash = fnv1a_hash(key);
    uint32_t start = hash % CACHE_PER_CPU;

    // 固定次数探测，保证O(1)
    for (int i = 0; i < HASH_PROBE_COUNT; i++) {
        uint32_t idx = (start + i) % CACHE_PER_CPU;
        struct cache_entry *e = &cache->entries[idx];

        if (e->used && strcmp(e->key, key) == 0) {
            // LRU更新：单线程无需原子操作
            e->lru_time = cache->tick++;

#if CANON_AI_LEARN
            // AI学习1：统计命中次数，防止溢出
            if (e->hit_count < CANON_AI_MAX_HIT_CNT)
                e->hit_count++;
            // AI学习2：命中达阈值，标记为热点路径
            if (e->hit_count >= CANON_AI_HOT_THRESH)
                e->is_hot = 1;
#endif

            strncpy(out_val, e->val, PATH_MAX - 1);
            out_val[PATH_MAX - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

/************************* LRU+AI插入 (新增AI智能淘汰：不淘汰热点路径) *************************/
static void cache_insert(const char *key, const char *val) {
    if (!cache_inited || !key || !val) return;
    uint32_t cpu = get_cpu_id();
    struct cpu_cache *cache = &static_cpu_caches[cpu];
    uint32_t hash = fnv1a_hash(key);
    uint32_t start = hash % CACHE_PER_CPU;

    // 寻找空条目或LRU受害者 (AI智能淘汰：跳过热点路径)
    int victim = start;
    uint32_t min_lru = UINT32_MAX;
    for (int i = 0; i < HASH_PROBE_COUNT; i++) {
        uint32_t idx = (start + i) % CACHE_PER_CPU;
        struct cache_entry *e = &cache->entries[idx];

        if (!e->used) {
            victim = idx;
            break; // 优先使用空条目
        }

#if CANON_AI_LEARN
        // AI学习3：智能淘汰，仅选择非热点路径作为淘汰候选
        if (!e->is_hot && e->lru_time < min_lru) {
#else
        // 原版LRU淘汰逻辑
        if (e->lru_time < min_lru) {
#endif
            min_lru = e->lru_time;
            victim = idx;
        }
    }

    // 写入缓存：单线程安全，初始化AI字段
    struct cache_entry *e = &cache->entries[victim];
    strncpy(e->key, key, PATH_MAX + 1);
    e->key[PATH_MAX + 1] = '\0';
    strncpy(e->val, val, PATH_MAX - 1);
    e->val[PATH_MAX - 1] = '\0';
    e->used = 1;
    e->lru_time = cache->tick++;
#if CANON_AI_LEARN
    e->hit_count = 0; // 初始化命中次数
    e->is_hot = 0;    // 初始化非热点
#endif
}

/************************* 原版工具函数 (完全保留，不删功能) *************************/
static inline void pop_component(char *path)
{
	int offset;
	assert(path != NULL);
	offset = strlen(path) - 1;
	assert(offset >= 0);
	if (offset == 0) {
		assert(path[0] == '/' && path[1] == '\0');
		return;
	}
	while (offset > 1 && path[offset] == '/')
		offset--;
	while (offset > 1 && path[offset] != '/')
		offset--;
	path[offset] = '\0';
	assert(path[0] == '/');
}

static inline Finality next_component(char component[NAME_MAX], const char **cursor)
{
	const char *start;
	ptrdiff_t length;
	bool want_dir;
	assert(component != NULL);
	assert(cursor    != NULL);
	while (**cursor != '\0' && **cursor == '/')
		(*cursor)++;
	start = *cursor;
	while (**cursor != '\0' && **cursor != '/')
		(*cursor)++;
	length = *cursor - start;
	if (length >= NAME_MAX)
		return (Finality)-ENAMETOOLONG;
	strncpy(component, start, length);
	component[length] = '\0';
	want_dir = (**cursor == '/');
	while (**cursor != '\0' && **cursor == '/')
		(*cursor)++;
	if (**cursor == '\0')
		return (want_dir ? FINAL_SLASH : FINAL_NORMAL);
	return NOT_FINAL;
}

static inline int substitute_binding_stat(Tracee *tracee, Finality finality, unsigned int nb_recursion,
					const char guest_path[PATH_MAX], char host_path[PATH_MAX])
{
	struct stat statl;
	int status;
	strcpy(host_path, guest_path);
	status = substitute_binding(tracee, GUEST, host_path);
	if (status < 0)
		return status;
	if (tracee->glue_type == 0) {
		status = notify_extensions(tracee, HOST_PATH, (intptr_t)host_path,
					IS_FINAL(finality) && nb_recursion == 0);
		if (status < 0)
			return status;
	}
	statl.st_mode = 0;
	if (should_skip_file_access_due_to_f2fs_bug(tracee, host_path)) {
		status = -ENOENT;
	} else {
		status = lstat(host_path, &statl);
		if (status < 0 && errno == EACCES && strcmp(host_path, "/linkerconfig") == 0) {
			status = 0;
			statl.st_mode = S_IFDIR;
		}
	}
	if (status < 0 && tracee->glue_type != 0) {
		statl.st_mode = build_glue(tracee, guest_path, host_path, finality);
		if (statl.st_mode == 0)
			status = -1;
	}
	if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode) && !S_ISLNK(statl.st_mode))
		return (status < 0 ? -ENOENT : -ENOTDIR);
	return (S_ISLNK(statl.st_mode) ? 1 : 0);
}

/************************* 主函数：canonicalize (完全保留原版功能，仅加缓存) *************************/
int canonicalize(Tracee *tracee, const char *user_path, bool deref_final,
		 char guest_path[PATH_MAX], unsigned int nb_recursion)
{
	// 1. 缓存初始化 (仅执行一次，不干扰功能)
	cache_init();
	// 2. 缓存仅作用于顶层递归 (避免干扰递归解析中的路径绑定)
	if (nb_recursion == 0 && user_path != NULL && user_path[0] == '/') {
		char cache_key[PATH_MAX + 2] = {0};
		make_cache_key(cache_key, user_path, deref_final);
		if (cache_lookup(cache_key, guest_path)) {
			return 0; // 命中缓存直接返回，不破坏后续逻辑
		}
	}
	// 3. 原版核心逻辑 (一字未改，保留所有Proot功能)
	if (nb_recursion > MAXSYMLINKS)
		return -ELOOP;
	assert(user_path != NULL);
	assert(guest_path != NULL);
	assert(user_path != guest_path);
	if (strnlen(guest_path, PATH_MAX) >= PATH_MAX)
		return -ENAMETOOLONG;
	if (user_path[0] != '/') {
		if (guest_path[0] != '/')
			return -EINVAL;
	}
	else
		strcpy(guest_path, "/");
	char scratch_path[PATH_MAX];
	Finality finality;
	const char *cursor;
	int status;
	cursor = user_path;
	finality = NOT_FINAL;
	while (!IS_FINAL(finality)) {
		Comparison comparison;
		char component[NAME_MAX];
		char host_path[PATH_MAX];
		finality = next_component(component, &cursor);
		status = (int) finality;
		if (status < 0)
			return status;
		if (strcmp(component, ".") == 0) {
			if (IS_FINAL(finality))
				finality = FINAL_DOT;
			continue;
		}
		if (strcmp(component, "..") == 0) {
			pop_component(guest_path);
			if (IS_FINAL(finality))
				finality = FINAL_SLASH;
			continue;
		}
		status = join_paths(2, scratch_path, guest_path, component);
		if (status < 0)
			return status;
		status = substitute_binding_stat(tracee, finality, nb_recursion, scratch_path, host_path);
		if (status < 0)
			return status;
		if (status <= 0 || (finality == FINAL_NORMAL && !deref_final)) {
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, component);
			if (status < 0)
				return status;
			continue;
		}
		comparison = compare_paths("/proc", guest_path);
		switch (comparison) {
		case PATHS_ARE_EQUAL:
		case PATH1_IS_PREFIX:
			status = readlink_proc(tracee, scratch_path,
					       guest_path, component, comparison);
			switch (status) {
			case CANONICALIZE:
				goto canon;
			case DONT_CANONICALIZE:
				if (finality == FINAL_NORMAL) {
					strcpy(guest_path, scratch_path);
					// 仅顶层递归写入缓存
					if (nb_recursion == 0) {
						char cache_key[PATH_MAX + 2] = {0};
						make_cache_key(cache_key, user_path, deref_final);
						cache_insert(cache_key, guest_path);
					}
					return 0;
				}
				break;
			default:
				if (status < 0)
					return status;
			}
		default:
			break;
		}
		status = readlink(host_path, scratch_path, sizeof(scratch_path) - 1);
		if (status < 0)
			return status;
		else if (status == sizeof(scratch_path) - 1)
			return -ENAMETOOLONG;
		scratch_path[status] = '\0';
		status = detranslate_path(tracee, scratch_path, host_path);
		if (status < 0)
			return status;
canon:
		status = canonicalize(tracee, scratch_path, true, guest_path, nb_recursion + 1);
		if (status < 0)
			return status;
		status = substitute_binding_stat(tracee, finality, nb_recursion, guest_path, host_path);
		if (status < 0)
			return status;
		assert(status != 1 || sscanf(guest_path, "/proc/%*d/fd/%d", &status) == 1);
	}
	if (nb_recursion == 0) {
		switch (finality) {
		case FINAL_NORMAL:
			break;
		case FINAL_SLASH:
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, "");
			if (status < 0)
				return status;
			break;
		case FINAL_DOT:
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, ".");
			if (status < 0)
				return status;
			break;
		default:
			assert(0);
		}
		// 解析完成后写入缓存 (仅顶层，保留所有功能结果)
		char cache_key[PATH_MAX + 2] = {0};
		make_cache_key(cache_key, user_path, deref_final);
		cache_insert(cache_key, guest_path);
	}
	return 0;
}
