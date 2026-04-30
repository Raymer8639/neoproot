#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <linux/limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>

#include "path/temp.h"
#include "tracee/tracee.h"
#include "cli/note.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline)) inline

static ALWAYS_INLINE int fast_strcmp(const char *a, const char *b) {
    return __builtin_strcmp(a, b);
}

static bool probe_f2fs_bug(const Tracee *tracee) {
    VERBOSE(tracee, 6, "Checking for f2fs case sensitivity bug");
    const char *base = get_temp_directory();
    char tmp[PATH_MAX];
    int len = snprintf(tmp, sizeof(tmp), "%s/proot_f2fsbug_XXXXXX", base);
    if (UNLIKELY(len < 0 || (size_t)len >= sizeof(tmp)))
        return false;

    if (UNLIKELY(!mkdtemp(tmp)))
        return false;

    char f1[PATH_MAX], f2[PATH_MAX], f3[PATH_MAX];
    snprintf(f1, sizeof(f1), "%s/aa", tmp);
    snprintf(f2, sizeof(f2), "%s/Aa", tmp);
    snprintf(f3, sizeof(f3), "%s/aA", tmp);

    int fd = open(f1, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (UNLIKELY(fd < 0)) {
        rmdir(tmp);
        return false;
    }
    close(fd);

    fd = open(f2, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (UNLIKELY(fd < 0)) {
        unlink(f1);
        rmdir(tmp);
        return false;
    }
    close(fd);

    bool result = false;
    if (LIKELY(access(f3, F_OK) != 0)) {
        int ws = 0;
        pid_t pid = fork();
        if (pid == 0) {
            fd = open(f3, O_WRONLY | O_CREAT, 0600);
            _exit((fd < 0 && errno == EEXIST) ? 1 : 0);
        }
        if (pid != -1) {
            waitpid(pid, &ws, 0);
            if (WIFEXITED(ws) && WEXITSTATUS(ws) == 1)
                result = true;
        }
    } else {
        result = true;
    }

    unlink(f1);
    unlink(f2);
    unlink(f3);
    rmdir(tmp);
    return result;
}

bool should_skip_file_access_due_to_f2fs_bug(const Tracee *tracee, const char *path) {
    static bool probed = false;
    static bool detected = false;

    if (UNLIKELY(!probed)) {
        const char *e = getenv("PROOT_F2FS_WORKAROUND");
        if (LIKELY(e))
            detected = (fast_strcmp(e, "1") == 0);
        else
            detected = probe_f2fs_bug(tracee);
        probed = true;
    }

    if (UNLIKELY(!detected))
        return false;

    char buf[PATH_MAX];
    strlcpy(buf, path, sizeof(buf));
    char *d = dirname(buf);
    DIR *dir = opendir(d);
    if (UNLIKELY(!dir))
        return false;

    char *b = basename(buf);
    struct dirent *ent;
    bool found = false;
    while ((ent = readdir(dir))) {
        if (fast_strcmp(ent->d_name, b) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return !found;
}