#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <talloc.h>

#include "path/binding.h"
#include "path/path.h"
#include "path/temp.h"
#include "cli/note.h"
#include "compat.h"

static int remove_placeholder(char *path) {
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;

    if (S_ISDIR(st.st_mode))
        rmdir(path);
    else if (st.st_size == 0)
        unlink(path);
    return 0;
}

static void set_placeholder_destructor(TALLOC_CTX *parent, const char *path) {
    char *copy = talloc_strdup(parent, path);
    if (copy)
        talloc_set_destructor(copy, remove_placeholder);
}

mode_t build_glue(Tracee *tracee, const char *guest_path, char host_path[PATH_MAX], Finality finality) {
    int status;
    mode_t type, mode;
    Comparison cmp;
    bool in_glue;

    assert(tracee && guest_path && host_path && tracee->glue_type);

    if (!tracee->glue) {
        tracee->glue = create_temp_directory(tracee, tracee->tool_name);
        if (!tracee->glue) {
            note(tracee, ERROR, INTERNAL, "failed to create glue rootfs");
            return 0;
        }
        talloc_set_name_const(tracee->glue, "$glue");
    }

    cmp = compare_paths(tracee->glue, host_path);
    in_glue = (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX);

    if (IS_FINAL(finality)) {
        type = tracee->glue_type;
        mode = in_glue ? 0755 : 0;
    } else {
        type = S_IFDIR;
        mode = 0755;
    }

    if (getenv("PROOT_DONT_POLLUTE_ROOTFS") && !in_glue)
        goto bind;

    if (S_ISDIR(type))
        status = mkdir(host_path, mode);
    else
        status = mknod(host_path, mode | type, 0);

    if (status == 0 && !in_glue)
        set_placeholder_destructor(tracee, host_path);

    if (status == 0 || errno == EEXIST || IS_FINAL(finality))
        return type;

    if (in_glue) {
        note(tracee, WARNING, SYSTEM, "failed to create glue path");
        return 0;
    }

bind:
    if (strlen(tracee->glue) >= PATH_MAX || strlen(guest_path) >= PATH_MAX) {
        note(tracee, WARNING, INTERNAL, "path too long");
        return 0;
    }

    if (!insort_binding3(tracee, tracee->glue, tracee->glue, guest_path))
        return 0;

    return type;
}
