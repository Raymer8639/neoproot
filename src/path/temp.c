#include <sys/types.h>  /* stat(2), opendir(3), */
#include <sys/stat.h>   /* stat(2), chmod(2), */
#include <unistd.h>     /* stat(2), rmdir(2), unlink(2), readlink(2), getpid(2), */
#include <errno.h>      /* errno(2), */
#include <dirent.h>     /* readdir(3), opendir(3), */
#include <string.h>     /* strcmp(3), strlen(3), */
#include <stdlib.h>     /* free(3), getenv(3), */
#include <stdio.h>      /* P_tmpdir, FILE*, fopen(3), fclose(3) */
#include <talloc.h>     /* talloc(3), */
#include <limits.h>     /* PATH_MAX */

#include "cli/note.h"

// 全局单例临时上下文：唯一管理所有临时内存
static TALLOC_CTX *g_temp_talloc_ctx = NULL;

/**
 * 初始化全局临时 talloc 上下文（唯一入口）
 */
static inline TALLOC_CTX *get_global_temp_ctx()
{
    if (g_temp_talloc_ctx == NULL) {
        g_temp_talloc_ctx = talloc_new(NULL);
        if (g_temp_talloc_ctx == NULL) {
            note(NULL, ERROR, INTERNAL, "failed to create global temp talloc context");
            abort();
        }
    }
    return g_temp_talloc_ctx;
}

/**
 * 释放全局临时上下文
 */
void free_global_temp_ctx()
{
    if (g_temp_talloc_ctx != NULL) {
        talloc_free(g_temp_talloc_ctx);
        g_temp_talloc_ctx = NULL;
    }
}

/**
 * Return the path to a directory where temporary files should be created.
 */
const char *get_temp_directory()
{
    static char *temp_directory = NULL;
    char realpath_buf[PATH_MAX] = {0};
    TALLOC_CTX *ctx = get_global_temp_ctx();

    if (temp_directory != NULL)
        return temp_directory;

    const char *env_tmp = getenv("PROOT_TMP_DIR");
    if (env_tmp == NULL)
        env_tmp = P_tmpdir;

    if (realpath(env_tmp, realpath_buf) != NULL)
        temp_directory = talloc_strdup(ctx, realpath_buf);
    else
        temp_directory = talloc_strdup(ctx, env_tmp);

    return temp_directory;
}

/**
 * Remove recursively the content of the current working directory.
 */
static int clean_temp_cwd()
{
    const char *temp_directory = get_temp_directory();
    size_t temp_len = strlen(temp_directory);
    int nb_errors = 0;
    DIR *dir = NULL;
    int status;

    char prefix[PATH_MAX] = {0};
    status = readlink("/proc/self/cwd", prefix, sizeof(prefix) - 1);
    if (status < 0) {
        note(NULL, WARNING, SYSTEM, "can't readlink '/proc/self/cwd'");
        nb_errors++;
        goto end;
    }
    prefix[status] = '\0';

    if (strlen(prefix) < temp_len || strncmp(prefix, temp_directory, temp_len) != 0) {
        note(NULL, ERROR, INTERNAL,
             "trying to remove a directory outside of '%s'", temp_directory);
        nb_errors++;
        goto end;
    }

    dir = opendir(".");
    if (dir == NULL) {
        note(NULL, WARNING, SYSTEM, "can't open '.'");
        nb_errors++;
        goto end;
    }

    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        struct stat st;
        if (stat(entry->d_name, &st) == 0 && (st.st_mode & 0700) != 0700)
            chmod(entry->d_name, 0700);

        if (entry->d_type == DT_DIR) {
            if (chdir(entry->d_name) == 0) {
                nb_errors += clean_temp_cwd();
                chdir("..");
                rmdir(entry->d_name);
            } else {
                nb_errors++;
            }
        } else {
            unlink(entry->d_name);
        }
    }

    if (errno != 0 && errno != ECHILD) {
        note(NULL, WARNING, SYSTEM, "can't readdir '.'");
        nb_errors++;
    }

end:
    if (dir != NULL)
        closedir(dir);
    return nb_errors;
}

/**
 * Remove recursively @path.
 */
static int remove_temp_directory2(const char *path)
{
    int result = 0;
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL)
        return -1;

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;

    chmod(path, 0700);

    if (chdir(path) == 0) {
        clean_temp_cwd();
        chdir(cwd);
        rmdir(path);
    } else {
        result = -1;
    }

    return result;
}

/**
 * talloc destructor: remove directory + free
 */
static int remove_temp_directory(char *path)
{
    if (path)
        remove_temp_directory2(path);
    return 0;
}

/**
 * talloc destructor: remove file + free
 */
static int remove_temp_file(char *path)
{
    if (path)
        unlink(path);
    return 0;
}

/**
 * Create a path name: "/tmp/@prefix-$PID-XXXXXX"
 */
char *create_temp_name(TALLOC_CTX *context, const char *prefix)
{
    const char *temp_dir = get_temp_directory();
    TALLOC_CTX *ctx = context ? context : get_global_temp_ctx();

    return talloc_asprintf(ctx, "%s/%s-%d-XXXXXX", temp_dir, prefix, getpid());
}

/**
 * Create a temporary directory (auto-removed)
 */
const char *create_temp_directory(TALLOC_CTX *context, const char *prefix)
{
    char *name = create_temp_name(context, prefix);
    if (!name)
        return NULL;

    if (mkdtemp(name)) {
        talloc_set_destructor(name, remove_temp_directory);
        return name;
    }

    note(NULL, ERROR, SYSTEM, "can't create temporary directory");
    talloc_free(name);
    return NULL;
}

/**
 * Create a temporary file (auto-removed)
 */
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

    note(NULL, ERROR, SYSTEM, "can't create temporary file");
    talloc_free(name);
    return NULL;
}

/**
 * Open a temporary file (auto-removed)
 */
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

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(name);
        talloc_free(name);
        return NULL;
    }

    talloc_set_destructor(name, remove_temp_file);
    return f;
}

/* 自动初始化 / 释放全局上下文 */
__attribute__((constructor))
static void temp_ctx_init(void)
{
    get_global_temp_ctx();
}

__attribute__((destructor))
static void temp_ctx_fini(void)
{
    free_global_temp_ctx();
}
