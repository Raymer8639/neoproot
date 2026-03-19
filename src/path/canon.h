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

#ifndef CANON_H
#define CANON_H

#include <stdbool.h>
#include <limits.h>

#include "tracee/tracee.h"

// 统一参数命名，消除歧义，编译器优化更精准
extern int canonicalize(Tracee *tracee, const char *user_path, bool deref_final,
			char guest_path[PATH_MAX], unsigned int recursion_level);

extern int canonicalize_safe(Tracee *tracee, const char *user_path, bool deref_final,
			char guest_path[PATH_MAX], unsigned int recursion_level);

#endif /* CANON_H */
