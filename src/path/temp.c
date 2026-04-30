#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <talloc.h>
#include <limits.h>

#include "cli/note.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

static TALLOC_CTX *g_temp_talloc_ctx = NULL;

static ALWAYS_INLINE TALLOC_CTX *get_global_temp_ctx(void) {
    if (UNLIKELY(!g_temp_talloc_ctx)) {
        g_temp_talloc_ctx = talloc_new(NULL);
        if (UNLIKELY(!g_temp_talloc_ctx)) {
            note(NULL, ERROR, INTERNAL, "failed to create global temp ctx");
            abort();
        }
    }
    return g_temp_talloc_ctx;
}

void free_global_temp_ctx(void) {
    if (LIKELY(g_temp_talloc_ctx)) {
        talloc_free(g_temp_talloc_ctx);
        g_temp_talloc_ctx = NULL;
    }
}

const char *get_temp_directory(void) {
    static const char *temp_dir = NULL;
    if (LIKELY(temp_dir))
        return temp_dir;
    const char *env_tmp = getenv("PROOT_TMP_DIR");
    if (UNLIKELY(!env_tmp))
        env_tmp = P_tmpdir;
    TALLOC_CTX *ctx = get_global_temp_ctx();
    temp_dir = talloc_strdup(ctx, env_tmp);
    if (UNLIKELY(!temp_dir)) {
        note(NULL, ERROR, INTERNAL, "failed to allocate temp directory");
        abort();
    }
    return temp_dir;
}

static ALWAYS_INLINE int remove_temp_directory2(const char *restrict path) {
    struct stat st;
    if (UNLIKELY(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)))
        return -1;
    chmod(path, 0700);
    rmdir(path);
    return 0;
}

static ALWAYS_INLINE int remove_temp_file(char *restrict path) {
    if (LIKELY(path))
        unlink(path);
    return 0;
}

static ALWAYS_INLINE int remove_temp_directory(char *restrict path) {
    if (LIKELY(path))
        remove_temp_directory2(path);
    return 0;
}

char *create_temp_name(TALLOC_CTX *restrict context, const char *restrict prefix) {
    static pid_t cached_pid = 0;
    if (UNLIKELY(cached_pid == 0))
        cached_pid = getpid();
    const char *tmp = get_temp_directory();
    TALLOC_CTX *ctx = context ? context : get_global_temp_ctx();
    return talloc_asprintf(ctx, "%s/%s-%d-XXXXXX", tmp, prefix, cached_pid);
}

const char *create_temp_directory(TALLOC_CTX *restrict context, const char *restrict prefix) {
    char *name = create_temp_name(context, prefix);
    if (UNLIKELY(!name))
        return NULL;
    if (LIKELY(mkdtemp(name))) {
        talloc_set_destructor(name, remove_temp_directory);
        return name;
    }
    note(NULL, ERROR, SYSTEM, "mkdtemp failed for %s", name);
    talloc_free(name);
    return NULL;
}

const char *create_temp_file(TALLOC_CTX *restrict context, const char *restrict prefix) {
    char *name = create_temp_name(context, prefix);
    if (UNLIKELY(!name))
        return NULL;
    int fd = mkstemp(name);
    if (LIKELY(fd >= 0)) {
        close(fd);
        talloc_set_destructor(name, remove_temp_file);
        return name;
    }
    note(NULL, ERROR, SYSTEM, "mkstemp failed for %s", name);
    talloc_free(name);
    return NULL;
}

FILE *open_temp_file(TALLOC_CTX *restrict context, const char *restrict prefix) {
    char *name = create_temp_name(context, prefix);
    if (UNLIKELY(!name))
        return NULL;
    int fd = mkstemp(name);
    if (UNLIKELY(fd < 0)) {
        talloc_free(name);
        return NULL;
    }
    FILE *f = fdopen(fd, "w+");
    if (UNLIKELY(!f)) {
        close(fd);
        unlink(name);
        talloc_free(name);
        return NULL;
    }
    talloc_set_destructor(name, remove_temp_file);
    return f;
}