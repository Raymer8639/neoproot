#ifndef PATH_H
#define PATH_H

#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>

#include "tracee/tracee.h"

#define PATH_MAX 4096

typedef enum {
    REGULAR,
    SYMLINK,
} Type;

typedef enum {
    GUEST,
    HOST,
    PENDING,
} Side;

typedef struct {
    char path[PATH_MAX];
    size_t length;
    Side side;
} Path;

typedef enum {
    NOT_FINAL,
    FINAL_NORMAL,
    FINAL_SLASH,
    FINAL_DOT
} Finality;

#define IS_FINAL(a) ((a) != NOT_FINAL)

typedef enum Comparison {
    PATHS_ARE_EQUAL,
    PATH1_IS_PREFIX,
    PATH2_IS_PREFIX,
    PATHS_ARE_NOT_COMPARABLE,
} Comparison;

void safe_strcat(char *dest, size_t *dest_len, const char *src, size_t src_len);
int  safe_strcpy(char *dest, const char *src, size_t size);

int which(Tracee *tracee, const char *paths, char host_path[PATH_MAX], const char *command);
int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path, bool deref_final);
int getcwd2(Tracee *tracee, char guest_path[PATH_MAX]);
void chop_finality(char *path);

int translate_path(Tracee *tracee, char host_path[PATH_MAX],
                   int dir_fd, const char *guest_path, bool deref_final);

int detranslate_path(Tracee *tracee, char path[PATH_MAX], const char t_referrer[PATH_MAX]);
bool belongs_to_guestfs(const Tracee *tracee, const char *path);

int join_paths(int number_paths, char result[PATH_MAX], ...);
int list_open_fd(const Tracee *tracee);

Comparison compare_paths(const char *path1, const char *path2);
Comparison compare_paths2(const char *path1, size_t length1, const char *path2, size_t length2);

size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_length,
                              const char *new_prefix, size_t new_prefix_length);

int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX]);

#define AT_FD(dirfd, path) ((dirfd) != AT_FDCWD && ((path) != NULL && (path)[0] != '/'))

#endif /* PATH_H */
