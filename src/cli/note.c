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

#include <errno.h>  /* errno */
#include <stdarg.h> /* va_start, va_end, va_list */
#include <stdio.h>  /* vfprintf, fprintf, perror */

#include "cli/note.h"
#include "tracee/tracee.h"

/* 全局变量显式初始化，消除未定义行为与编译器警告 */
int global_verbose_level = 0;
const char *global_tool_name = NULL;

/**
 * Print @message to the standard error stream according to its
 * @severity and @origin.
 * 优化：修复errno污染bug、减少IO系统调用、空指针防护、精简重复逻辑
 */
void note(const Tracee *tracee, Severity severity, Origin origin, const char *message, ...)
{
	const char *tool_name;
	const char *severity_str;
	va_list extra_params;
	int verbose_level;
	int saved_errno = errno; /* 提前保存原始errno，修复vfprintf修改errno的bug */

	/* 前置判断：不需要输出时直接返回，避免所有不必要的操作 */
	if (tracee == NULL) {
		verbose_level = global_verbose_level;
		tool_name = (global_tool_name != NULL) ? global_tool_name : "";
	} else {
		verbose_level = tracee->verbose;
		tool_name = (tracee->tool_name != NULL) ? tracee->tool_name : "";
	}
	if (verbose_level < 0 && severity != ERROR)
		return;

	/* 统一生成严重级别字符串，替代原switch-case重复代码 */
	switch (severity) {
	case WARNING:
		severity_str = "warning";
		break;
	case ERROR:
		severity_str = "error";
		break;
	case INFO:
	default:
		severity_str = "info";
		break;
	}

	/* 合并前缀输出，减少fprintf调用次数 */
	fprintf(stderr, "%s %s: ", tool_name, severity_str);
	if (origin == TALLOC)
		fprintf(stderr, "talloc: ");

	/* 空指针防护，避免NULL传入vfprintf导致崩溃 */
	if (message != NULL) {
		va_start(extra_params, message);
		vfprintf(stderr, message, extra_params);
		va_end(extra_params);
	}

	/* 按来源处理结尾输出，恢复原始errno确保系统错误信息准确 */
	switch (origin) {
	case SYSTEM:
		errno = saved_errno; /* 恢复原始errno，修复污染bug */
		fprintf(stderr, ": ");
		perror(NULL);
		break;
	case TALLOC:
		fprintf(stderr, "\n");
		break;
	case INTERNAL:
	case USER:
	default:
		fprintf(stderr, "\n");
		break;
	}
}
