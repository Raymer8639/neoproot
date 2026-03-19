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

#ifndef GLUE_H
#define GLUE_H

#include <limits.h> /* PATH_MAX, */

#include "tracee/tracee.h"
#include "path.h"

extern mode_t build_glue(Tracee *tracee, const char *guest_path, char host_path[PATH_MAX],
			Finality finality);

#endif /* GLUE_H */
