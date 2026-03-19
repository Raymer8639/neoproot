/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <sys/types.h>
#include <limits.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "path/f2fs-bug.h"
#include "extension/extension.h"

static inline void pop_component(char *path)
{
	int offset;

	if (!path || *path != '/')
		return;

	offset = strlen(path) - 1;
	if (offset <= 0)
		return;

	while (offset > 1 && path[offset] == '/')
		offset--;

	while (offset > 1 && path[offset] != '/')
		offset--;

	path[offset] = '\0';
}

static inline Finality next_component(char component[NAME_MAX], const char **cursor)
{
	const char *start;
	ptrdiff_t length;
	bool want_dir;

	if (!component || !cursor || !*cursor)
		return FINAL_NORMAL;

	while (**cursor != '\0' && **cursor == '/')
		(*cursor)++;

	start = *cursor;
	while (**cursor != '\0' && **cursor != '/')
		(*cursor)++;
	length = *cursor - start;

	if (length >= NAME_MAX)
		return -ENAMETOOLONG;

	strncpy(component, start, length);
	component[length] = '\0';

	want_dir = (**cursor == '/');

	while (**cursor != '\0' && **cursor == '/')
		(*cursor)++;

	if (**cursor == '\0')
		return want_dir ? FINAL_SLASH : FINAL_NORMAL;

	return NOT_FINAL;
}

static inline int substitute_binding_stat(Tracee *tracee, Finality finality, unsigned int recursion_level,
					const char guest_path[PATH_MAX], char host_path[PATH_MAX])
{
	struct stat statl;
	int status;

	if (!guest_path || !host_path)
		return -EINVAL;

	strcpy(host_path, guest_path);
	status = substitute_binding(tracee, GUEST, host_path);
	if (status < 0)
		return status;

	if (tracee->glue_type == 0) {
		status = notify_extensions(tracee, HOST_PATH, (intptr_t)host_path,
					IS_FINAL(finality) && recursion_level == 0);
		if (status < 0)
			return status;
	}

	memset(&statl, 0, sizeof(statl));
	if (should_skip_file_access_due_to_f2fs_bug(tracee, host_path)) {
		status = -ENOENT;
	} else {
		status = lstat(host_path, &statl);
		if (status < 0 && errno == EACCES && strcmp(host_path, "/linkerconfig") == 0) {
			status = 0;
			statl.st_mode = S_IFDIR;
		}
	}

	if (status < 0 && tracee->glue_type != 0) {
		statl.st_mode = build_glue(tracee, guest_path, host_path, finality);
		if (statl.st_mode == 0)
			status = -1;
	}

	if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode) && !S_ISLNK(statl.st_mode))
		return status < 0 ? -ENOENT : -ENOTDIR;

	return S_ISLNK(statl.st_mode) ? 1 : 0;
}

int canonicalize(Tracee *tracee, const char *user_path, bool deref_final,
		 char guest_path[PATH_MAX], unsigned int recursion_level)
{
	char scratch_path[PATH_MAX];
	Finality finality;
	const char *cursor;
	int status;

	if (recursion_level > MAXSYMLINKS)
		return -ELOOP;

	if (!user_path || !guest_path || user_path == guest_path)
		return -EINVAL;

	if (strnlen(user_path, PATH_MAX) >= PATH_MAX)
		return -ENAMETOOLONG;

	// ===================== 安全修复：保证 guest_path 始终以 / 开头 =====================
	if (user_path[0] != '/') {
		if (guest_path[0] != '/') {
			if (recursion_level == 0)
				strcpy(guest_path, "/");
			else
				return -EINVAL;
		}
	} else {
		strcpy(guest_path, "/");
	}

	cursor = user_path;
	finality = NOT_FINAL;

	while (!IS_FINAL(finality)) {
		Comparison comparison;
		char component[NAME_MAX];
		char host_path[PATH_MAX];

		finality = next_component(component, &cursor);
		status = (int)finality;
		if (status < 0)
			return status;

		if (strcmp(component, ".") == 0) {
			if (IS_FINAL(finality))
				finality = FINAL_DOT;
			continue;
		}

		if (strcmp(component, "..") == 0) {
			pop_component(guest_path);
			if (IS_FINAL(finality))
				finality = FINAL_SLASH;
			continue;
		}

		status = join_paths(2, scratch_path, guest_path, component);
		if (status < 0)
			return status;

		status = substitute_binding_stat(tracee, finality, recursion_level, scratch_path, host_path);
		if (status < 0)
			return status;

		if (status <= 0 || (finality == FINAL_NORMAL && !deref_final)) {
			strcpy(scratch_path, guest_path);
			status = join_paths(2, guest_path, scratch_path, component);
			if (status < 0)
				return status;
			continue;
		}

		comparison = compare_paths("/proc", guest_path);
		if (comparison == PATHS_ARE_EQUAL || comparison == PATH1_IS_PREFIX) {
			status = readlink_proc(tracee, scratch_path, guest_path, component, comparison);
			if (status == CANONICALIZE)
				goto canon;
			if (status == DONT_CANONICALIZE) {
				if (finality == FINAL_NORMAL) {
					strcpy(guest_path, scratch_path);
					return 0;
				}
			} else if (status < 0) {
				return status;
			}
		}

		status = readlink(host_path, scratch_path, sizeof(scratch_path));
		if (status < 0)
			return status;
		if ((size_t)status >= sizeof(scratch_path))
			return -ENAMETOOLONG;
		scratch_path[status] = '\0';

		status = detranslate_path(tracee, scratch_path, host_path);
		if (status < 0)
			return status;

canon:
		status = canonicalize(tracee, scratch_path, true, guest_path, recursion_level + 1);
		if (status < 0)
			return status;

		status = substitute_binding_stat(tracee, finality, recursion_level, guest_path, host_path);
		if (status < 0)
			return status;
	}

	if (recursion_level == 0) {
		switch (finality) {
			case FINAL_NORMAL:
				break;
			case FINAL_SLASH:
				strcpy(scratch_path, guest_path);
				status = join_paths(2, guest_path, scratch_path, "");
				if (status < 0) return status;
				break;
			case FINAL_DOT:
				strcpy(scratch_path, guest_path);
				status = join_paths(2, guest_path, scratch_path, ".");
				if (status < 0) return status;
				break;
			default:
				break;
		}
	}

	return 0;
}
