/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot / proot-scicat
 *
 * Copyright (C) 2026 scicat
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#ifndef TEMP_H
#define TEMP_H

#include <talloc.h>

extern char *create_temp_name(TALLOC_CTX *context, const char *prefix);
extern const char *create_temp_directory(TALLOC_CTX *context, const char *prefix);
extern const char *create_temp_file(TALLOC_CTX *context, const char *prefix);
extern FILE* open_temp_file(TALLOC_CTX *context, const char *prefix);
extern const char *get_temp_directory();

#endif /* TEMP_H */
