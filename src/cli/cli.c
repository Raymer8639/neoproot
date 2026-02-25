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

#include <stdio.h>         /* printf(3), fprintf(3), snprintf(3) */
#include <stdbool.h>       /* bool, true, false */
#include <linux/limits.h>  /* ARG_MAX, PATH_MAX */
#include <string.h>        /* str*(3), mem*(3) */
#include <talloc.h>        /* talloc_* */
#include <stdlib.h>        /* exit(3), EXIT_*, strtol(3), {g,s}etenv(3) */
#include <assert.h>        /* assert(3) */
#include <sys/types.h>     /* getpid(2) */
#include <unistd.h>        /* getpid(2), getcwd(2) */
#include <errno.h>         /* errno */
#include <libgen.h>        /* basename(3) */
#include <stddef.h>        /* ptrdiff_t, size_t */
#include <inttypes.h>      /* INT32_MAX, INT32_MIN */
#include <stdint.h>        /* 标准整数类型 */
#ifdef __GLIBC__
#include <execinfo.h>      /* backtrace_symbols(3) */
#endif

#include "cli/cli.h"
#include "cli/note.h"
#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/event.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/path.h"
#include "extension/sysvipc/sysvipc.h"
#include "build.h"

/* 全局变量，与头文件extern声明完全一致 */
bool exit_failure = true;

/* 安全宏定义：多行宏用do-while(0)包裹，避免语法陷阱 */
#define DETAIL(a) do { if (detailed) { a; } } while(0)
#define SAFE_APPEND(dst, dst_size, src) do { \
	size_t _dst_len = strlen(dst); \
	size_t _src_len = strlen(src); \
	if (_dst_len + _src_len < (dst_size)) { \
		memcpy(dst + _dst_len, src, _src_len + 1); \
	} \
} while(0)

/**
 * 内联工具函数：安全的字符串拷贝，确保零终止，无缓冲区溢出
 */
static inline void safe_strcpy(char *dst, const char *src, size_t dst_size)
{
	if (dst == NULL || src == NULL || dst_size == 0)
		return;
	strncpy(dst, src, dst_size - 1);
	dst[dst_size - 1] = '\0';
}

/**
 * Print a (@detailed) usage of PRoot.
 * 优化：缓存字符串长度、减少循环冗余、安全输出、消除未使用变量
 */
void print_usage(Tracee *tracee, const Cli *cli, bool detailed)
{
	const char *current_class = "none";
	const Option *options;
	size_t i;

	if (cli == NULL)
		return;

	options = cli->options;
	DETAIL(printf("%s %s: %s.\n\n", cli->name, cli->version, cli->subtitle));
	printf("Usage:\n  %s\n", cli->synopsis);
	DETAIL(printf("\n"));

	for (i = 0; options[i].class != NULL; i++) {
		const Option *option = &options[i];
		const Argument *first_arg = &option->arguments[0];
		size_t alias_count = 0;

		/* 先统计别名数量，避免循环内重复计算 */
		for (alias_count = 0; option->arguments[alias_count].name != NULL; alias_count++);

		/* 输出分类标题 */
		if (strcmp(option->class, current_class) != 0) {
			current_class = option->class;
			printf("\n%s:\n", current_class);
		}

		/* 输出所有别名 */
		printf("  %s", first_arg->name);
		for (size_t k = 1; k < alias_count; k++) {
			const Argument *arg = &option->arguments[k];
			if (!detailed)
				break;
			printf(", %s", arg->name);
		}

		/* 输出参数格式 */
		if (first_arg->separator != '\0' && first_arg->value != NULL)
			printf("%c*%s*", first_arg->separator, first_arg->value);
		else if (!detailed)
			printf("\t");

		/* 输出描述与详情 */
		DETAIL(printf("\n"));
		printf("\t%s\n", option->description);
		if (detailed && option->detail[0] != '\0')
			printf("\n%s\n\n", option->detail);
		else if (detailed)
			printf("\n");
	}

	notify_extensions(tracee, PRINT_USAGE, detailed, 0);
	if (detailed)
		printf("%s\n", cli->colophon);
}

/**
 * Print the version of PRoot.
 * 优化：精简逻辑，保持功能不变
 */
void print_version(const Cli *cli)
{
	if (cli == NULL)
		return;

	printf("%s %s\n\n", cli->logo, cli->version);
	printf("built-in accelerators: process_vm = %s, seccomp_filter = %s\n",
#if defined(HAVE_PROCESS_VM)
		"yes",
#else
		"no",
#endif
#if defined(HAVE_SECCOMP_FILTER)
		"yes"
#else
		"no"
#endif
		);
}

/**
 * Print execve error help information.
 * 优化：缓存getenv结果，避免重复系统调用，空指针防护
 */
static void print_execve_help(const Tracee *tracee, const char *argv0, int status)
{
	const char *ld_preload = getenv("LD_PRELOAD");
	const char *no_seccomp = getenv("PROOT_NO_SECCOMP");

	if (tracee == NULL)
		return;

	note(tracee, ERROR, SYSTEM, "execve(\"%s\")", argv0 ? argv0 : "");

	/* Termux-exec兼容提示 */
	if (status == -ENOENT && ld_preload != NULL && strstr(ld_preload, "libtermux-exec.so") != NULL) {
		note(tracee, INFO, USER,
"It seems that termux-exec is active and is prepending /data/data/com.termux/... to executable paths\n"
"If this path is not available inside proot, please \"unset LD_PRELOAD\"");
		return;
	}

	/* Ubuntu内核seccomp bug提示 */
	if (status == -EPERM && no_seccomp == NULL) {
		note(tracee, INFO, USER,
"It seems your kernel contains this bug: https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1202161\n"
"To workaround it, set the env. variable PROOT_NO_SECCOMP to 1.");
		return;
	}

	/* 通用错误原因 */
	note(tracee, INFO, USER, "possible causes:\n"
"  * the program is a script but its interpreter (eg. /bin/sh) was not found;\n"
"  * the program is an ELF but its interpreter (eg. ld-linux.so) was not found;\n"
"  * the program is a foreign binary but qemu was not specified;\n"
"  * qemu does not work correctly (if specified);\n"
"  * the loader was not found or doesn't work.");
}

/**
 * Print option format error.
 * 优化：精简逻辑，保持功能不变
 */
static void print_error_separator(const Tracee *tracee, const Argument *argument)
{
	if (tracee == NULL || argument == NULL)
		return;

	if (argument->separator == '\0')
		note(tracee, ERROR, USER, "option '%s' expects no value.", argument->name);
	else
		note(tracee, ERROR, USER, "option '%s' and its value must be separated by '%c'.",
			argument->name, argument->separator);
}

/**
 * Print argv array to log.
 * 优化：彻底解决缓冲区溢出风险，用snprintf替代strncat，减少重复计算
 */
static void print_argv(const Tracee *tracee, const char *prompt, char *const argv[])
{
	char string[ARG_MAX] = "";
	size_t offset = 0;
	size_t remaining = ARG_MAX;
	int ret;

	if (tracee == NULL || prompt == NULL || argv == NULL)
		return;

	/* 写入前缀 */
	ret = snprintf(string, remaining, "%s =", prompt);
	if (ret < 0 || (size_t)ret >= remaining)
		return;
	offset = ret;
	remaining -= ret;

	/* 遍历写入参数 */
	for (size_t i = 0; argv[i] != NULL; i++) {
		ret = snprintf(string + offset, remaining, " %s", argv[i]);
		if (ret < 0 || (size_t)ret >= remaining)
			break;
		offset += ret;
		remaining -= ret;
	}

	string[ARG_MAX - 1] = '\0';
	note(tracee, INFO, USER, "%s", string);
}

/**
 * Print current PRoot configuration.
 * 优化：空指针校验，精简逻辑
 */
static void print_config(Tracee *tracee, char *const argv[])
{
	if (tracee == NULL || tracee->verbose <= 0)
		return;

	if (tracee->qemu)
		note(tracee, INFO, USER, "host rootfs = %s", HOST_ROOTFS);
	if (tracee->glue)
		note(tracee, INFO, USER, "glue rootfs = %s", tracee->glue);
	if (tracee->exe)
		note(tracee, INFO, USER, "exe = %s", tracee->exe);

	print_argv(tracee, "argv", argv);
	print_argv(tracee, "qemu", tracee->qemu);
	note(tracee, INFO, USER, "initial cwd = %s", tracee->fs->cwd);
	note(tracee, INFO, USER, "verbose level = %d", tracee->verbose);

	notify_extensions(tracee, PRINT_CONFIG, 0, 0);
}

/**
 * Initialize @tracee's current working directory.
 * 优化：彻底解决缓冲区溢出，安全路径拼接，完善错误处理
 */
static int initialize_cwd(Tracee *tracee)
{
	char path2[PATH_MAX] = {0};
	char path[PATH_MAX] = {0};
	int status;

	if (tracee == NULL || tracee->fs == NULL)
		return -1;

	/* 计算基础目录 */
	if (tracee->fs->cwd[0] != '/') {
		status = getcwd2(tracee->reconf.tracee, path);
		if (status < 0) {
			note(tracee, ERROR, INTERNAL, "getcwd: %s", strerror(-status));
			return -1;
		}
	} else {
		safe_strcpy(path, "/", PATH_MAX);
	}

	/* 安全拼接路径，确保结尾.用于目录校验 */
	status = join_paths(3, path2, path, tracee->fs->cwd, ".");
	if (status < 0) {
		note(tracee, ERROR, INTERNAL, "join paths: %s", strerror(-status));
		return -1;
	}

	/* 路径规范化 */
	safe_strcpy(path, "/", PATH_MAX);
	status = canonicalize(tracee, path2, true, path, 0);
	if (status < 0) {
		note(tracee, WARNING, USER, "can't chdir(\"%s\") in the guest rootfs: %s",
			path2, strerror(-status));
		note(tracee, INFO, USER, "default working directory is now \"/\"");
		safe_strcpy(path, "/", PATH_MAX);
	}

	chop_finality(path);

	/* 更新cwd */
	TALLOC_FREE(tracee->fs->cwd);
	tracee->fs->cwd = talloc_strdup(tracee->fs, path);
	if (tracee->fs->cwd == NULL)
		return -1;
	talloc_set_name_const(tracee->fs->cwd, "$cwd");

	/* 同步PWD环境变量 */
	setenv("PWD", path, 1);
	return 0;
}

/**
 * Initialize @tracee->exe from @exe, canonicalized from guest view.
 * 优化：空指针校验，安全字符串操作
 */
static int initialize_exe(Tracee *tracee, const char *exe)
{
	char path[PATH_MAX] = {0};
	int status;

	if (tracee == NULL)
		return -1;

	/* 查找可执行文件路径 */
	status = which(tracee, tracee->reconf.paths, path, exe ?: "/bin/sh");
	if (status < 0)
		return -1;

	/* 转换为guest路径 */
	status = detranslate_path(tracee, path, NULL);
	if (status < 0)
		return -1;

	/* 保存exe路径 */
	tracee->exe = talloc_strdup(tracee, path);
	if (tracee->exe == NULL)
		return -1;
	talloc_set_name_const(tracee->exe, "$exe");

	return 0;
}

/**
 * Configure @tracee according to command-line arguments.
 * Returns index of command to launch, -1 on error.
 * 优化：循环扁平化，减少嵌套，缓存字符串长度，完善错误处理，消除未初始化变量
 */
static int parse_config(Tracee *tracee, size_t argc, char *const argv[])
{
	option_handler_t handler = NULL;
	const Option *options;
	const Cli *cli = NULL;
	size_t argc_offset;
	size_t i;
	int status;

	if (tracee == NULL || argv == NULL || argc < 1)
		return -1;

	/* 获取CLI配置 */
	cli = get_proot_cli(tracee->ctx);
	tracee->tool_name = cli->name;

	/* 无参数时打印简易用法 */
	if (argc == 1) {
		print_usage(tracee, cli, false);
		return -1;
	}

	options = cli->options;
	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];
		bool option_found = false;

		/* 处理上一个短选项的参数值 */
		if (handler != NULL) {
			status = handler(tracee, cli, arg);
			if (status < 0)
				return -1;
			handler = NULL;
			continue;
		}

		/* 非选项参数，结束PRoot参数解析 */
		if (arg[0] != '-')
			break;

		/* 遍历所有选项匹配 */
		for (size_t j = 0; options[j].class != NULL; j++) {
			const Option *option = &options[j];
			size_t arg_len = strlen(arg);

			/* 遍历选项别名 */
			for (size_t k = 0; option->arguments[k].name != NULL; k++) {
				const Argument *argument = &option->arguments[k];
				size_t name_len = strlen(argument->name);

				/* 别名不匹配 */
				if (strncmp(arg, argument->name, name_len) != 0)
					continue;

				/* 分隔符不匹配，避免歧义 */
				if (arg_len > name_len && arg[name_len] != argument->separator) {
					print_error_separator(tracee, argument);
					return -1;
				}

				/* 无参数选项 */
				if (!argument->value) {
					status = option->handler(tracee, cli, NULL);
					if (status < 0)
						return -1;
					option_found = true;
					break;
				}

				/* 参数与选项合并 */
				if (argument->separator == arg[name_len]) {
					status = option->handler(tracee, cli, &arg[name_len + 1]);
					if (status < 0)
						return -1;
					option_found = true;
					break;
				}

				/* 分隔符非空格，格式错误 */
				if (argument->separator != ' ') {
					print_error_separator(tracee, argument);
					return -1;
				}

				/* 选项与参数分离，下一个参数为值 */
				handler = option->handler;
				option_found = true;
				break;
			}

			if (option_found)
				break;
		}

		/* 未知选项 */
		if (!option_found) {
			note(tracee, ERROR, USER, "unknown option '%s'.", arg);
			return -1;
		}

		/* 选项需要参数但已到参数末尾 */
		if (handler != NULL && i == argc - 1) {
			note(tracee, ERROR, USER, "missing value for option '%s'.", arg);
			return -1;
		}
	}

	argc_offset = i;

	/* 配置钩子宏，安全do-while结构 */
#define HOOK_CONFIG(callback) do { \
	if (cli->callback != NULL) { \
		status = cli->callback(tracee, cli, argc, argv, i); \
		if (status < 0) \
			return -1; \
		i = status; \
	} \
} while(0)

	/* 初始化绑定 */
	HOOK_CONFIG(pre_initialize_bindings);
	status = initialize_bindings(tracee);
	if (status < 0)
		return -1;
	HOOK_CONFIG(post_initialize_bindings);

	/* 初始化工作目录 */
	HOOK_CONFIG(pre_initialize_cwd);
	status = initialize_cwd(tracee);
	if (status < 0)
		return -1;
	HOOK_CONFIG(post_initialize_cwd);

	/* 初始化可执行文件路径 */
	HOOK_CONFIG(pre_initialize_exe);
	status = initialize_exe(tracee, argv[argc_offset]);
	if (status < 0)
		return -1;
	HOOK_CONFIG(post_initialize_exe);

#undef HOOK_CONFIG

	/* 打印配置信息 */
	print_config(tracee, &argv[argc_offset]);
	return argc_offset;
}

/**
 * PRoot main entry point.
 * 优化：空指针校验，内存泄漏兜底，错误处理完善，全局变量安全加固
 */
int main(int argc, char *const argv[])
{
	Tracee *tracee = NULL;
	int status;
	const char *argv0 = (argc > 0 && argv[0] != NULL) ? basename(argv[0]) : "proot";

	/* 配置talloc内存分配器 */
	talloc_enable_leak_report();
#if defined(TALLOC_VERSION_MAJOR) && TALLOC_VERSION_MAJOR >= 2
	talloc_set_log_stderr();
#endif

	/* 共享内存助手模式 */
	if (argc == 2 && strcmp(argv[1], "--shm-helper") == 0) {
		sysvipc_shm_helper_main();
		exit(EXIT_SUCCESS);
	}

	/* 创建初始tracee */
	tracee = get_tracee(NULL, 0, true);
	if (tracee == NULL)
		goto error;
	tracee->pid = getpid();

	/* 从环境变量初始化verbose级别 */
	{
		const char *verbose_env = getenv("PROOT_VERBOSE");
		if (verbose_env != NULL) {
			tracee->verbose = strtol(verbose_env, NULL, 10);
			global_verbose_level = tracee->verbose;
		}
	}

	/* 解析配置 */
	status = parse_config(tracee, argc, argv);
	if (status < 0)
		goto error;

	/* 初始化mountinfo扩展 */
	if (getenv("PROOT_NO_MOUNTINFO") == NULL)
		initialize_extension(tracee, mountinfo_callback, NULL);

	/* 启动初始进程 */
	status = launch_process(tracee, &argv[status]);
	if (status < 0) {
		print_execve_help(tracee, tracee->exe, status);
		goto error;
	}

	/* 进入事件循环 */
	exit(event_loop());

error:
	/* 错误兜底释放 */
	TALLOC_FREE(tracee);
	if (exit_failure) {
		fprintf(stderr, "fatal error: see `%s --help`.\n", argv0);
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

/**
 * Parse integer option value.
 * 优化：整数溢出防护，完善错误处理，符合C标准
 */
int parse_integer_option(const Tracee *tracee, int *variable, const char *value, const char *option)
{
	char *end_ptr = NULL;
	long val;

	if (tracee == NULL || variable == NULL || value == NULL || option == NULL)
		return -1;

	errno = 0;
	val = strtol(value, &end_ptr, 10);

	/* 转换错误校验 */
	if (errno != 0 || end_ptr == value) {
		note(tracee, ERROR, USER, "option `%s` expects an integer value.", option);
		return -1;
	}

	/* int范围溢出校验 */
	if (val < INT32_MIN || val > INT32_MAX) {
		note(tracee, ERROR, USER, "option `%s` value is out of range.", option);
		return -1;
	}

	*variable = (int)val;
	return 0;
}

/**
 * Expand environment variable at the start of @string.
 * 优化：修复内存泄漏，空指针校验，安全字符串操作
 */
const char *expand_front_variable(TALLOC_CTX *context, const char *string)
{
	const char *suffix;
	char *var_name = NULL;
	const char *var_value;
	char *result;
	ptrdiff_t var_len;

	if (context == NULL || string == NULL || string[0] != '$')
		return string;

	/* 查找路径分隔符 */
	suffix = strchr(string, '/');
	if (suffix == NULL) {
		var_value = getenv(&string[1]);
		return (var_value != NULL) ? var_value : string;
	}

	/* 提取环境变量名 */
	var_len = suffix - string;
	if (var_len <= 1)
		return string;

	var_name = talloc_strndup(context, &string[1], var_len - 1);
	if (var_name == NULL)
		return string;

	/* 获取环境变量值 */
	var_value = getenv(var_name);
	talloc_free(var_name); /* 用完立即释放，修复内存泄漏 */
	if (var_value == NULL)
		return string;

	/* 拼接结果 */
	result = talloc_asprintf(context, "%s%s", var_value, suffix);
	return (result != NULL) ? result : string;
}

/* GCC函数插桩支持，仅在glibc环境下编译，indent_level变量仅在此处使用 */
#ifdef __GLIBC__
/* 仅在插桩功能启用时定义该变量，彻底消除未使用警告 */
static int indent_level = 0;

void __cyg_profile_func_enter(void *this_function, void *call_site) DONT_INSTRUMENT;
void __cyg_profile_func_enter(void *this_function, void *call_site)
{
	void *const pointers[] = { this_function, call_site };
	char **symbols = backtrace_symbols(pointers, 2);

	if (symbols != NULL) {
		fprintf(stderr, "%*s from %s\n",
			(int)strlen(symbols[0]) + indent_level,
			symbols[0], symbols[1]);
		free(symbols);
	}

	if (indent_level < INT_MAX)
		indent_level++;
}

void __cyg_profile_func_exit(void *this_function UNUSED, void *call_site UNUSED) DONT_INSTRUMENT;
void __cyg_profile_func_exit(void *this_function UNUSED, void *call_site UNUSED)
{
	if (indent_level > 0)
		indent_level--;
}
#endif
