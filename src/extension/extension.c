#include <assert.h>
#include <talloc.h>
#include <sys/queue.h>
#include <string.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "build.h"
#include "compat.h"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))

static int remove_extension(Extension *restrict extension) {
    if (UNLIKELY(extension == NULL))
        return -1;

    LIST_REMOVE(extension, link);
    extension->callback(extension, REMOVED, 0, 0);

    memset(extension, 0, sizeof(Extension));
    return 0;
}

static ALWAYS_INLINE Extension *new_extension(Tracee *restrict tracee, extension_callback_t callback) {
    if (UNLIKELY(tracee == NULL || callback == NULL))
        return NULL;

    if (UNLIKELY(tracee->extensions == NULL)) {
        Extensions *exts = talloc_zero(tracee, Extensions);
        if (UNLIKELY(exts == NULL))
            return NULL;
        tracee->extensions = exts;
    }

    Extension *ext = talloc_zero(tracee->extensions, Extension);
    if (UNLIKELY(ext == NULL))
        return NULL;

    ext->callback = callback;
    LIST_INSERT_HEAD(tracee->extensions, ext, link);
    talloc_set_destructor(ext, remove_extension);
    return ext;
}

Extension *get_extension(Tracee *restrict tracee, extension_callback_t callback) {
    if (UNLIKELY(tracee == NULL || tracee->extensions == NULL || callback == NULL))
        return NULL;

    Extension *ext;
    LIST_FOREACH(ext, tracee->extensions, link) {
        if (ext->callback == callback)
            return ext;
    }
    return NULL;
}

int initialize_extension(Tracee *restrict tracee, extension_callback_t callback, const char *restrict cli) {
    if (UNLIKELY(tracee == NULL || callback == NULL))
        return -1;

    Extension *ext = new_extension(tracee, callback);
    if (UNLIKELY(ext == NULL)) {
        note(tracee, WARNING, INTERNAL, "failed to create extension");
        return -1;
    }

    int status = ext->callback(ext, INITIALIZATION, (intptr_t)cli, 0);
    if (UNLIKELY(status < 0)) {
        TALLOC_FREE(ext);
        return status;
    }
    return 0;
}

void inherit_extensions(Tracee *restrict child, Tracee *restrict parent, word_t clone_flags) {
    if (UNLIKELY(parent == NULL || child == NULL || parent->extensions == NULL))
        return;

    assert(child->extensions == NULL || clone_flags == CLONE_RECONF);

    Extension *parent_ext;
    LIST_FOREACH(parent_ext, parent->extensions, link) {
        int inherit_mode = parent_ext->callback(parent_ext, INHERIT_PARENT,
                                                (intptr_t)child, clone_flags);
        if (UNLIKELY(inherit_mode < 0))
            continue;

        Extension *child_ext = new_extension(child, parent_ext->callback);
        if (UNLIKELY(child_ext == NULL)) {
            note(parent, WARNING, INTERNAL,
                 "cannot create extension for child %d", child->pid);
            continue;
        }

        if (inherit_mode == 0) {
            child_ext->config = talloc_reference(child_ext, parent_ext->config);
        } else {
            child_ext->callback(child_ext, INHERIT_CHILD,
                                (intptr_t)parent_ext, clone_flags);
        }
    }
}