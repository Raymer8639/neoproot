#ifndef EXTENSION_H
#define EXTENSION_H

#include <sys/queue.h>
#include <stdint.h>

#include "tracee/tracee.h"
#include "syscall/seccomp.h"

/*
 * Extension events.
 */
typedef enum {
	GUEST_PATH,
	HOST_PATH,
	TRANSLATED_PATH,

	SYSCALL_ENTER_START,
	SYSCALL_ENTER_END,
	SYSCALL_EXIT_START,
	SYSCALL_EXIT_END,

	NEW_STATUS,

	INHERIT_PARENT,
	INHERIT_CHILD,

	SYSCALL_CHAINED_ENTER,
	SYSCALL_CHAINED_EXIT,

	INITIALIZATION,
	REMOVED,

	PRINT_CONFIG,
	PRINT_USAGE,

	SIGSYS_OCC,

	LINK2SYMLINK_RENAME,
	LINK2SYMLINK_UNLINK,

	STATX_SYSCALL,

	EXT_EVENT_COUNT  // <--- 只加这一行（事件总数）
} ExtensionEvent;

#define CLONE_RECONF ((word_t)-1)

struct extension;
typedef int (*extension_callback_t)(struct extension *extension, ExtensionEvent event,
				     intptr_t data1, intptr_t data2);

typedef struct extension {
	extension_callback_t callback;
	TALLOC_CTX         *config;
	const FilteredSysnum *filtered_sysnums;
	LIST_ENTRY(extension) link;
} Extension;

typedef LIST_HEAD(extensions, extension) Extensions;

/* Public API */
extern int initialize_extension(Tracee *tracee, extension_callback_t callback, const char *cli);
extern void inherit_extensions(Tracee *child, Tracee *parent, word_t clone_flags);
extern Extension *get_extension(Tracee *tracee, extension_callback_t callback);

/**
 * Notify all extensions of @tracee that an event occurred.
 */
static inline int notify_extensions(Tracee *tracee, ExtensionEvent event,
				    intptr_t data1, intptr_t data2)
{
	Extension *ext;

	if (tracee->extensions == NULL)
		return 0;

	LIST_FOREACH(ext, tracee->extensions, link) {
		int status = ext->callback(ext, event, data1, data2);
		if (status != 0)
			return status;
	}

	return 0;
}

/* Built-in extensions */
extern int kompat_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int fake_id0_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int hidden_files_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int port_switch_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int link2symlink_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int fix_symlink_size_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int ashmem_memfd_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);
extern int mountinfo_callback(Extension *extension, ExtensionEvent event, intptr_t d1, intptr_t d2);

#endif /* EXTENSION_H */
