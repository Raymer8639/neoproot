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

static TALLOC_CTX *g_temp_talloc_ctx = NULL;

static inline TALLOC_CTX *get_global_temp_ctx(void)
{
    if (!g_temp_talloc_ctx) {
        g_temp_talloc_ctx = talloc_new(NULL);
        if (!g_temp_talloc_ctx) {
            note(NULL, ERROR, INTERNAL, "failed to create global temp ctx");
            abort();
        }
    }
    return g_temp_talloc_ctx;
}

void free_global_temp_ctx(void)
{
    if (g_temp_talloc_ctx) {
        talloc_free(g_temp_talloc_ctx);
        g_temp_talloc_ctx = NULL;
    }
}

const char *get_temp_directory(void)
{
    static char *temp_dir = NULL;
    TALLOC_CTX *ctx = get_global_temp_ctx();

    if (temp_dir)
        return temp_dir;

    const char *env_tmp = getenv("PROOT_TMP_DIR");
    if (!env_tmp)
        env_tmp = P_tmpdir;

    // 不依赖 realpath，避免 /proc 与 proot 路径混乱
    temp_dir = talloc_strdup(ctx, env_tmp);
    return temp_dir;
}

/* 简化版清理：不递归 chdir，避免 proot 下卡死 */
static int remove_temp_directory2(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0 || !S_ISDIR(st.st_mode))
        return -1;

    chmod(path, 0700);

    // 简单 rmdir，不递归清理内容（proot 环境更稳定）
    rmdir(path);
    return 0;
}

static int remove_temp_file(char *path)
{
    if (path)
        unlink(path);
    return 0;
}

static int remove_temp_directory(char *path)
{
    if (path)
        remove_temp_directory2(path);
    return 0;
}

char *create_temp_name(TALLOC_CTX *context, const char *prefix)
{
    const char *tmp = get_temp_directory();
    TALLOC_CTX *ctx = context ? context : get_global_temp_ctx();
    return talloc_asprintf(ctx, "%s/%s-%d-XXXXXX", tmp, prefix, getpid());
}

const char *create_temp_directory(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (!name)
        return NULL;

    if (mkdtemp(name)) {
        talloc_set_destructor(name, remove_temp_directory);
        return name;
    }

    note(NULL, ERROR, SYSTEM, "mkdtemp failed for %s", name);
    talloc_free(name);
    return NULL;
}

const char *create_temp_file(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (!name)
        return NULL;

    int fd = mkstemp(name);
    if (fd >= 0) {
        close(fd);
        talloc_set_destructor(name, remove_temp_file);
        return name;
    }

    note(NULL, ERROR, SYSTEM, "mkstemp failed for %s", name);
    talloc_free(name);
    return NULL;
}

FILE *open_temp_file(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (!name)
        return NULL;

    int fd = mkstemp(name);
    if (fd < 0) {
        talloc_free(name);
        return NULL;
    }

    FILE *f = fdopen(fd, "w+");
    if (!f) {
        close(fd);
        unlink(name);
        talloc_free(name);
        return NULL;
    }

    talloc_set_destructor(name, remove_temp_file);
    return f;
}