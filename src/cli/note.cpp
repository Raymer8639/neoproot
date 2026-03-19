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
 */

#include <cerrno>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <climits>

#ifdef __cplusplus
extern "C" {
#endif

#include "cli/note.h"
#include "tracee/tracee.h"

#ifdef __cplusplus
}
#endif

int global_verbose_level;
const char *global_tool_name;

extern "C" void note(
    const Tracee *tracee,
    Severity severity,
    Origin origin,
    const char *message,
    ...
) {
    const char *tool_name;
    int verbose_level;

    if (tracee == nullptr) {
        verbose_level = global_verbose_level;
        tool_name     = global_tool_name ?: "";
    } else {
        verbose_level = tracee->verbose;
        tool_name     = tracee->tool_name;
    }

    if (verbose_level < 0 && severity != ERROR)
        return;

    switch (severity) {
        case WARNING:
            fprintf(stderr, "%s warning: ", tool_name);
            break;
        case ERROR:
            fprintf(stderr, "%s error: ", tool_name);
            break;
        case INFO:
        default:
            fprintf(stderr, "%s info: ", tool_name);
            break;
    }

    if (origin == TALLOC)
        fprintf(stderr, "talloc: ");

    va_list extra_params;
    va_start(extra_params, message);
    vfprintf(stderr, message, extra_params);
    va_end(extra_params);

    switch (origin) {
        case SYSTEM:
            fprintf(stderr, ": ");
            perror(NULL);
            break;
        case TALLOC:
            break;
        case INTERNAL:
        case USER:
        default:
            fprintf(stderr, "\n");
            break;
    }
}
