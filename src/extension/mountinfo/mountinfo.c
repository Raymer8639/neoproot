#include "extension/extension.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/temp.h"
#include "tracee/tracee.h"
#include "syscall/sysnum.h"
#include <limits.h>
#include <linux/limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))
#define ALIGNED __attribute__((aligned(8)))

static const char PROC_PREFIX[] = "/proc/";
static const char MOUNTINFO_SUFFIX[] = "/mountinfo";
static const size_t PROC_PREFIX_LEN = sizeof(PROC_PREFIX) - 1;
static const size_t MOUNTINFO_SUFFIX_LEN = sizeof(MOUNTINFO_SUFFIX) - 1;
static const size_t MIN_PATH_LEN = PROC_PREFIX_LEN + 1 + MOUNTINFO_SUFFIX_LEN;

static ALWAYS_INLINE int ends_with(const char *str, size_t str_len, const char *suffix, size_t suffix_len) {
    if (UNLIKELY(str_len < suffix_len)) return 0;
    return memcmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

static void write_mountinfo_path(FILE *fake, const char *path) {
    const unsigned char *p = (const unsigned char *)path;
    for (; *p != '\0'; ++p) {
        switch (*p) {
        case ' ':  fputs("\\040", fake); break;
        case '\\': fputs("\\134", fake); break;
        case '\t': fputs("\\011", fake); break;
        case '\n': fputs("\\012", fake); break;
        default:   fputc(*p, fake); break;
        }
    }
}

static ALWAYS_INLINE void mountinfo_check_open_path(Tracee *restrict tracee, char *restrict path) {
    if (UNLIKELY(!tracee || !path)) return;
    size_t path_len = strlen(path);
    if (UNLIKELY(path_len < MIN_PATH_LEN)) return;
    if (UNLIKELY(memcmp(path, PROC_PREFIX, PROC_PREFIX_LEN) != 0)) return;
    if (UNLIKELY(!ends_with(path, path_len, MOUNTINFO_SUFFIX, MOUNTINFO_SUFFIX_LEN))) return;

    const char *pid_start = path + PROC_PREFIX_LEN;
    char *pid_end = NULL;
    long pid = strtol(pid_start, &pid_end, 10);
    if (UNLIKELY(pid_end != path + path_len - MOUNTINFO_SUFFIX_LEN)) return;
    if (UNLIKELY(pid <= 0 || pid > INT_MAX)) return;

    Tracee *target = get_tracee(tracee, (pid_t)pid, false);
    if (UNLIKELY(!target)) return;

    char root_host[PATH_MAX] ALIGNED = {0};
    if (translate_path(target, root_host, AT_FDCWD, "/", true) < 0) return;
    if (UNLIKELY(root_host[0] == '\0')) return;

    Comparison cmp = compare_paths(root_host, "/data");
    if (cmp != PATH2_IS_PREFIX && cmp != PATHS_ARE_EQUAL) return;

    FILE *real = fopen(path, "r");
    if (UNLIKELY(!real)) return;

    const char *temp_path = create_temp_file(tracee->ctx, "mountinfo");
    if (UNLIKELY(!temp_path)) {
        fclose(real);
        return;
    }

    FILE *fake = fopen(temp_path, "w");
    if (UNLIKELY(!fake)) {
        fclose(real);
        return;
    }

    char *line = NULL;
    size_t line_sz = 0;
    ssize_t n;
    bool found = false;
    unsigned int root_mount_id = 0;

    while ((n = getline(&line, &line_sz, real)) > 0) {
        char *p = line;
        int col;
        for (col = 0; col < 4; ++col) {
            p = strchr(p, ' ');
            if (UNLIKELY(!p)) goto next1;
            ++p;
        }
        char *end = strchr(p, ' ');
        if (UNLIKELY(!end)) goto next1;
        size_t slen = end - p;
        if (slen == 5 && memcmp(p, "/data", 5) == 0) {
            char *id_end = NULL;
            unsigned long parsed_id = strtoul(line, &id_end, 10);
            if (id_end != line && parsed_id > 0 && parsed_id <= UINT_MAX)
                root_mount_id = (unsigned int)parsed_id;
            fwrite(line, 1, p - line, fake);
            fputc('/', fake);
            fwrite(end, 1, line + n - end, fake);
            found = true;
            break;
        }
    next1:;
    }

    if (LIKELY(found)) {
        rewind(real);
        while ((n = getline(&line, &line_sz, real)) > 0) {
            char *p = line;
            int col;

            for (col = 0; col < 4; ++col) {
                p = strchr(p, ' ');
                if (UNLIKELY(!p)) goto next2;
                ++p;
            }
            char *end = strchr(p, ' ');
            if (UNLIKELY(!end)) goto next2;
            size_t slen = end - p;
            if ((slen == 4 && memcmp(p, "/dev", 4) == 0) ||
                (slen >= 5 && memcmp(p, "/dev/", 5) == 0) ||
                (slen == 5 && memcmp(p, "/proc", 5) == 0) ||
                (slen == 4 && memcmp(p, "/sys", 4) == 0) ||
                (slen >= 5 && memcmp(p, "/sys/", 5) == 0) ||
                (slen == 4 && memcmp(p, "/tmp", 4) == 0)) {
                fwrite(line, 1, n, fake);
            }
        next2:;
        }
    }

    if (LIKELY(found && root_mount_id != 0)) {
        Binding *binding;
        unsigned int mount_id = 100000;

        rewind(real);
        while ((n = getline(&line, &line_sz, real)) > 0) {
            char *id_end = NULL;
            unsigned long parsed_id;
            errno = 0;
            parsed_id = strtoul(line, &id_end, 10);
            if (id_end != line && errno == 0 && parsed_id < UINT_MAX &&
                parsed_id >= mount_id)
                mount_id = (unsigned int)parsed_id + 1;
        }

        /* mount(2) is represented by PRoot bindings, so expose those
         * guest mount points to programs that verify /proc/self/mountinfo. */
        for (binding = CIRCLEQ_FIRST(target->fs->bindings.guest);
             binding != (void *) target->fs->bindings.guest;
             binding = CIRCLEQ_NEXT(binding, link.guest)) {
            if (strcmp(binding->guest.path, "/") == 0 ||
                strcmp(binding->guest.path, "/dev") == 0 ||
                strcmp(binding->guest.path, "/proc") == 0 ||
                strcmp(binding->guest.path, "/sys") == 0 ||
                strcmp(binding->guest.path, "/tmp") == 0)
                continue;
            fprintf(fake, "%u %u 0:1 / ", mount_id++, root_mount_id);
            write_mountinfo_path(fake, binding->guest.path);
            fputs(" rw - none none rw\n", fake);
        }

        /* A user-space tmpfs has a host backing directory.  Procfd exposes
         * that directory, so publish the same mountpoint in mountinfo. */
        for (binding = CIRCLEQ_FIRST(target->fs->bindings.guest);
             binding != (void *) target->fs->bindings.guest;
             binding = CIRCLEQ_NEXT(binding, link.guest)) {
            Binding *seen;
            bool duplicate = false;

            if (binding->mount_kind != BINDING_MOUNT_TMPFS)
                continue;

            for (seen = CIRCLEQ_FIRST(target->fs->bindings.guest);
                 seen != binding;
                 seen = CIRCLEQ_NEXT(seen, link.guest)) {
                if (seen->mount_kind == BINDING_MOUNT_TMPFS &&
                    strcmp(seen->host.path, binding->host.path) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate)
                continue;

            fprintf(fake, "%u %u 0:1 / ", mount_id++, root_mount_id);
            write_mountinfo_path(fake, binding->host.path);
            fputs(" rw - tmpfs tmpfs rw\n", fake);
        }
    }

    free(line);
    fclose(fake);
    fclose(real);

    if (LIKELY(found)) {
        strncpy(path, temp_path, PATH_MAX - 1);
        path[PATH_MAX - 1] = '\0';
    }
}

HOT
int mountinfo_callback(Extension *restrict ext, ExtensionEvent ev, intptr_t data1, intptr_t data2) {
    (void)data2;
    if (UNLIKELY(!ext)) return -EINVAL;
    if (LIKELY(ev == TRANSLATED_PATH)) {
        Tracee *t = TRACEE(ext);
        if (UNLIKELY(!t)) return 0;
        Sysnum num = get_sysnum(t, ORIGINAL);
        if (num == PR_open || num == PR_openat || num == PR_openat2)
            mountinfo_check_open_path(t, (char *)data1);
        return 0;
    }
    return 0;
}
