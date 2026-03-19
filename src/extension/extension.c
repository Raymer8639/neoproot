/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot / proot-scicat
 *
 * Copyright (C) 2015 STMicroelectronics
 * Copyright (C) 2026 Scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 */

#include <assert.h>
#include <talloc.h>
#include <sys/queue.h>
#include <string.h>

#include "extension/extension.h"
#include "cli/note.h"
#include "build.h"
#include "compat.h"

/**
 * Talloc destructor: remove an extension from its tracee's list
 * and send REMOVED event.
 */
static int remove_extension(Extension *extension)
{
	if (extension == NULL)
		return -1;

	LIST_REMOVE(extension, link);
	extension->callback(extension, REMOVED, 0, 0);

	memset(extension, 0, sizeof(Extension));
	return 0;
}

/**
 * Allocate a new Extension and attach it to @tracee's extension list.
 */
static Extension *new_extension(Tracee *tracee, extension_callback_t callback)
{
	Extensions *exts;
	Extension *ext;

	if (tracee == NULL || callback == NULL)
		return NULL;

	/* Lazy initialize the extension list head */
	if (tracee->extensions == NULL) {
		exts = talloc_zero(tracee, Extensions);
		if (exts == NULL)
			return NULL;
		tracee->extensions = exts;
	}

	ext = talloc_zero(tracee->extensions, Extension);
	if (ext == NULL)
		return NULL;

	ext->callback = callback;
	LIST_INSERT_HEAD(tracee->extensions, ext, link);

	talloc_set_destructor(ext, remove_extension);
	return ext;
}

/**
 * Get the extension attached to @tracee by its callback function.
 */
Extension *get_extension(Tracee *tracee, extension_callback_t callback)
{
	Extension *ext;

	if (tracee == NULL || tracee->extensions == NULL || callback == NULL)
		return NULL;

	LIST_FOREACH(ext, tracee->extensions, link) {
		if (ext->callback == callback)
			return ext;
	}

	return NULL;
}

/**
 * Create and initialize a new extension from CLI.
 */
int initialize_extension(Tracee *tracee, extension_callback_t callback, const char *cli)
{
	Extension *ext;
	int status;

	if (tracee == NULL || callback == NULL)
		return -1;

	ext = new_extension(tracee, callback);
	if (ext == NULL) {
		note(tracee, WARNING, INTERNAL, "failed to create extension");
		return -1;
	}

	status = ext->callback(ext, INITIALIZATION, (intptr_t)cli, 0);
	if (status < 0) {
		TALLOC_FREE(ext);
		return status;
	}

	return 0;
}

/**
 * Inherit extensions from @parent to @child according to clone_flags.
 */
void inherit_extensions(Tracee *child, Tracee *parent, word_t clone_flags)
{
	Extension *parent_ext;
	Extension *child_ext;
	int inherit_mode;

	if (parent == NULL || child == NULL || parent->extensions == NULL)
		return;

	/* Only allowed during reconf or fresh child */
	assert(child->extensions == NULL || clone_flags == CLONE_RECONF);

	LIST_FOREACH(parent_ext, parent->extensions, link) {
		inherit_mode = parent_ext->callback(parent_ext, INHERIT_PARENT,
						   (intptr_t)child, clone_flags);
		if (inherit_mode < 0)
			continue; /* not inheritable */

		child_ext = new_extension(child, parent_ext->callback);
		if (child_ext == NULL) {
			note(parent, WARNING, INTERNAL,
			     "cannot create extension for child %d", child->pid);
			continue;
		}

		if (inherit_mode == 0) {
			/* Share config (reference) */
			child_ext->config = talloc_reference(child_ext, parent_ext->config);
		} else {
			/* Let extension handle child inheritance */
			child_ext->callback(child_ext, INHERIT_CHILD,
					    (intptr_t)parent_ext, clone_flags);
		}
	}
}
