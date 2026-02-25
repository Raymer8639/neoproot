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

#ifndef CANON_H
#define CANON_H

#include <stdbool.h>
#include <limits.h>

#include "tracee/tracee.h"

// AI智能学习缓存开关 & 阈值配置
#define CANON_AI_LEARN        1    // 开启AI学习功能
#define CANON_AI_HOT_THRESH   8    // 命中≥8次标记为热点路径
#define CANON_AI_MAX_HIT_CNT  255  // 命中次数上限，防止溢出

extern int canonicalize(Tracee *tracee, const char *user_path, bool deref_final,
			char guest_path[PATH_MAX], unsigned int nb_recursion);

#endif /* CANON_H */
