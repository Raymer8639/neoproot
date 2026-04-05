#include <sys/types.h>
#include <limits.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"

#define STAT_CACHE_SIZE 64

typedef struct {
    char path[PATH_MAX];
    struct stat st;
    int valid;
    unsigned int lru_time;
} StatCacheEntry;

static StatCacheEntry stat_cache[STAT_CACHE_SIZE];
static unsigned int stat_cache_clock = 0;

static inline int fast_strcmp(const char *s1, const char *s2)
{
    while (*s1 != '\0' && *s2 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}


static inline char *fast_strncpy(char *dest, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

static inline size_t fast_strnlen(const char *s, size_t maxlen)
{
    size_t len = 0;
    while (len < maxlen && s[len] != '\0')
        len++;
    return len;
}

static int stat_cache_lookup(const char *path, struct stat *out_st) {
    for (int i = 0; i < STAT_CACHE_SIZE; ++i) {
        StatCacheEntry *e = &stat_cache[i];
        if (e->valid && fast_strcmp(e->path, path) == 0) {
            *out_st = e->st;
            e->lru_time = ++stat_cache_clock;
            return 0;
        }
    }
    return -ENOENT;
}

static void stat_cache_insert(const char *path, const struct stat *st) {
    StatCacheEntry *victim = &stat_cache[0];
    for (int i = 1; i < STAT_CACHE_SIZE; ++i) {
        if (stat_cache[i].lru_time < victim->lru_time)
            victim = &stat_cache[i];
    }

    fast_strncpy(victim->path, path, PATH_MAX - 1);
    victim->st = *st;
    victim->valid = 1;
    victim->lru_time = ++stat_cache_clock;
}

static inline void pop_component(char *path)
{
    int offset;

    if (!path || *path != '/')
        return;

    offset = fast_strnlen(path, PATH_MAX) - 1;
    if (offset <= 0)
        return;

    while (offset > 1 && path[offset] == '/')
        offset--;

    while (offset > 1 && path[offset] != '/')
        offset--;

    path[offset] = '\0';
}

static inline Finality next_component(char component[NAME_MAX], const char **cursor)
{
    const char *start;
    ptrdiff_t length;
    bool want_dir;

    if (!component || !cursor || !*cursor)
        return FINAL_NORMAL;

    while (**cursor != '\0' && **cursor == '/')
        (*cursor)++;

    start = *cursor;
    while (**cursor != '\0' && **cursor != '/')
        (*cursor)++;
    length = *cursor - start;

    if (length >= NAME_MAX)
        return -ENAMETOOLONG;

    fast_strncpy(component, start, length);
    component[length] = '\0';

    want_dir = (**cursor == '/');

    while (**cursor != '\0' && **cursor == '/')
        (*cursor)++;

    if (**cursor == '\0')
        return want_dir ? FINAL_SLASH : FINAL_NORMAL;

    return NOT_FINAL;
}

static inline int substitute_binding_stat(Tracee *tracee, Finality finality, unsigned int recursion_level,
					const char guest_path[PATH_MAX], char host_path[PATH_MAX])
{
	struct stat statl;
	int status;

	if (!guest_path || !host_path)
		return -EINVAL;

	fast_strncpy(host_path, guest_path, PATH_MAX - 1);
	status = substitute_binding(tracee, GUEST, host_path);
	if (status < 0)
		return status;

	if (tracee->glue_type == 0) {
		status = notify_extensions(tracee, HOST_PATH, (intptr_t)host_path,
					IS_FINAL(finality) && recursion_level == 0);
		if (status < 0)
			return status;
	}

	memset(&statl, 0, sizeof(statl));

	if (stat_cache_lookup(host_path, &statl) == 0) {
		status = 0;
	} else if (should_skip_file_access_due_to_f2fs_bug(tracee, host_path)) {
		status = -ENOENT;
	} else {
		status = lstat(host_path, &statl);
		if (status < 0 && errno == EACCES) {
			if (fast_strcmp(host_path, "/linkerconfig") == 0 ||
			    fast_strcmp(host_path, "/system") == 0 ||
			    fast_strcmp(host_path, "/vendor") == 0)
			{
				status = 0;
				statl.st_mode = S_IFDIR | 0755;
			}
		}
		if (status == 0) {
			stat_cache_insert(host_path, &statl);
		}
	}

	if (status < 0 && tracee->glue_type != 0) {
		statl.st_mode = build_glue(tracee, guest_path, host_path, finality);
		if (statl.st_mode == 0)
			status = -1;
	}

	if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode) && !S_ISLNK(statl.st_mode))
		return status < 0 ? -ENOENT : -ENOTDIR;

	return S_ISLNK(statl.st_mode) ? 1 : 0;
}

int canonicalize(Tracee *tracee, const char *user_path, bool deref_final,
		 char guest_path[PATH_MAX], unsigned int recursion_level)
{
	char scratch_path[PATH_MAX];
	Finality finality;
	const char *cursor;
	int status;

	if (recursion_level > MAXSYMLINKS)
		return -ELOOP;

	if (!user_path || !guest_path)
		return -EINVAL;

	if (fast_strnlen(user_path, PATH_MAX) >= PATH_MAX)
		return -ENAMETOOLONG;

	if (user_path[0] != '/') {
		if (guest_path[0] != '/') {
			if (recursion_level == 0)
				fast_strncpy(guest_path, "/", PATH_MAX - 1);
			else
				return -EINVAL;
		}
	} else {
		fast_strncpy(guest_path, "/", PATH_MAX - 1);
	}

	cursor = user_path;
	finality = NOT_FINAL;

	while (!IS_FINAL(finality)) {
		Comparison comparison;
		char component[NAME_MAX];
		char host_path[PATH_MAX];

		finality = next_component(component, &cursor);
		status = (int)finality;
		if (status < 0)
			return status;

		if (fast_strcmp(component, ".") == 0) {
			if (IS_FINAL(finality))
				finality = FINAL_DOT;
			continue;
		}

		if (fast_strcmp(component, "..") == 0) {
			pop_component(guest_path);
			if (IS_FINAL(finality))
				finality = FINAL_SLASH;
			continue;
		}

		status = join_paths(2, scratch_path, guest_path, component);
		if (status < 0)
			return status;

		status = substitute_binding_stat(tracee, finality, recursion_level, scratch_path, host_path);
		if (status < 0)
			return status;

		if (status <= 0 || (finality == FINAL_NORMAL && !deref_final)) {
			fast_strncpy(scratch_path, guest_path, PATH_MAX - 1);
			status = join_paths(2, guest_path, scratch_path, component);
			if (status < 0)
				return status;
			continue;
		}

		comparison = compare_paths("/proc", guest_path);
		if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX) {
			status = readlink_proc(tracee, scratch_path, guest_path, component, comparison);
			if (status == CANONICALIZE)
				goto canon;
			if (status == DONT_CANONICALIZE) {
				if (finality == FINAL_NORMAL) {
					fast_strncpy(guest_path, scratch_path, PATH_MAX - 1);
					return 0;
				}
			} else if (status < 0) {
				return status;
			}
		}

		status = readlink(host_path, scratch_path, PATH_MAX - 1);
		if (status < 0)
			return status;
		if ((size_t)status >= PATH_MAX)
			return -ENAMETOOLONG;
		scratch_path[status] = '\0';

		status = detranslate_path(tracee, scratch_path, host_path);
		if (status < 0)
			return status;

canon:
		status = canonicalize(tracee, scratch_path, true, guest_path, recursion_level + 1);
		if (status < 0)
			return status;

		status = substitute_binding_stat(tracee, finality, recursion_level, guest_path, host_path);
		if (status < 0)
			return status;
	}

	if (recursion_level == 0) {
		switch (finality) {
			case FINAL_NORMAL:
				break;
			case FINAL_SLASH:
				fast_strncpy(scratch_path, guest_path, PATH_MAX - 1);
				status = join_paths(2, guest_path, scratch_path, "");
				if (status < 0) return status;
				break;
			case FINAL_DOT:
				fast_strncpy(scratch_path, guest_path, PATH_MAX - 1);
				status = join_paths(2, guest_path, scratch_path, ".");
				if (status < 0) return status;
				break;
			default:
				break;
		}
	}

	return 0;
}
