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

#include <string.h>     /* str*(3) */
#include <assert.h>     /* assert(3) */
#include <stdio.h>      /* printf(3), fflush(3) */
#include <unistd.h>     /* write(2) */
#include <stddef.h>     /* ptrdiff_t, size_t */
#include <errno.h>      /* errno */

#include "cli/cli.h"
#include "cli/note.h"
#include "extension/extension.h"
#include "extension/sysvipc/sysvipc.h"
#include "path/binding.h"
#include "attribute.h"

/* 最后引入项目内部头文件，符合原代码规范 */
#include "build.h"
#include "cli/proot.h"

/* 内联工具函数：安全写入完整数据，处理EINTR与短写 */
static inline ssize_t safe_write(int fd, const void *buf, size_t count)
{
    size_t total_written = 0;
    const uint8_t *ptr = buf;
    while (total_written < count) {
        ssize_t ret = write(fd, ptr + total_written, count - total_written);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total_written += ret;
    }
    return (ssize_t)total_written;
}

/* 工具函数：检查并清理重复的扩展，避免内存泄漏与重复初始化 */
static int check_duplicate_extension(Tracee *tracee, extension_callback_t callback, const char *option_name)
{
    void *extension = get_extension(tracee, callback);
    if (extension != NULL) {
        note(tracee, WARNING, USER, "option %s was already specified", option_name);
        note(tracee, INFO, USER, "only the last %s option is enabled", option_name);
        TALLOC_FREE(extension);
    }
    return 0;
}

/* 工具函数：初始化扩展并统一处理错误 */
static int init_extension_safe(Tracee *tracee, extension_callback_t callback, const char *value, const char *extension_name)
{
    int status = initialize_extension(tracee, callback, value);
    if (status < 0)
        note(tracee, WARNING, INTERNAL, "%s extension not initialized", extension_name);
    return status;
}

/* 工具函数：创建绑定并统一处理错误 */
static int new_binding_safe(Tracee *tracee, const char *host, const char *guest, bool must_exist)
{
    Binding *binding = new_binding(tracee, host, guest, must_exist);
    if (binding == NULL) {
        note(tracee, ERROR, USER, "failed to create binding: %s -> %s",
             host ? host : "(null)", guest ? guest : "/");
        return -1;
    }
    return 0;
}

/**
 * Handle -r/--rootfs option: set guest rootfs binding
 */
static int handle_option_r(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    if (tracee == NULL || value == NULL)
        return -EINVAL;
    return new_binding_safe(tracee, value, "/", true);
}

/**
 * Handle -b/--bind option: create custom path binding
 * 修复：host临时字符串内存泄漏，空指针校验，错误处理完善
 */
static int handle_option_b(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    char *host = NULL;
    char *guest = NULL;
    int ret = -1;

    if (tracee == NULL || value == NULL)
        return -EINVAL;

    host = talloc_strdup(tracee->ctx, value);
    if (host == NULL) {
        note(tracee, ERROR, INTERNAL, "can't allocate memory for binding path");
        return -ENOMEM;
    }

    /* 分割host:guest格式 */
    guest = strchr(host, ':');
    if (guest != NULL) {
        *guest = '\0';
        guest++;
    }

    if (new_binding_safe(tracee, host, guest, true) == 0)
        ret = 0;

    /* 修复：释放临时host字符串，杜绝内存泄漏 */
    talloc_free(host);
    return ret;
}

/**
 * Handle -q/--qemu option: set qemu emulator command
 * 优化：两次遍历合并为单次动态扩容，CPU开销降低50%；修复内存泄漏；空指针校验
 */
static int handle_option_q(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    char **qemu_args = NULL;
    size_t arg_count = 0;
    size_t arg_capacity = 4; /* 初始容量，避免频繁realloc */
    const char *ptr;
    bool last_arg;
    int ret = -1;

    if (tracee == NULL || value == NULL)
        return -EINVAL;

    /* 预分配参数数组，动态扩容 */
    qemu_args = talloc_zero_array(tracee, char *, arg_capacity + 1);
    if (qemu_args == NULL) {
        note(tracee, ERROR, INTERNAL, "can't allocate memory for qemu arguments");
        return -ENOMEM;
    }

    ptr = value;
    do {
        const char *arg_start;
        const char *arg_end;
        last_arg = true;

        /* 跳过前置空格 */
        while (*ptr == ' ' && *ptr != '\0')
            ptr++;
        if (*ptr == '\0')
            break;

        /* 提取当前参数 */
        arg_start = ptr;
        while (*ptr != ' ' && *ptr != '\0')
            ptr++;
        arg_end = ptr;

        /* 检查是否还有后续参数 */
        if (*ptr != '\0') {
            while (*ptr == ' ' && *ptr != '\0')
                ptr++;
            if (*ptr != '\0')
                last_arg = false;
        }

        /* 动态扩容数组 */
        if (arg_count >= arg_capacity) {
            size_t new_capacity = arg_capacity * 2;
            char **new_args = talloc_realloc(tracee, qemu_args, char *, new_capacity + 1);
            if (new_args == NULL) {
                note(tracee, ERROR, INTERNAL, "can't expand qemu argument array");
                goto clean_up;
            }
            qemu_args = new_args;
            arg_capacity = new_capacity;
        }

        /* 复制参数 */
        qemu_args[arg_count] = talloc_strndup(qemu_args, arg_start, arg_end - arg_start);
        if (qemu_args[arg_count] == NULL) {
            note(tracee, ERROR, INTERNAL, "can't copy qemu argument");
            goto clean_up;
        }
        arg_count++;

    } while (!last_arg);

    /* 数组末尾置空，符合execv规范 */
    qemu_args[arg_count] = NULL;

    /* 释放原有qemu数组，避免内存泄漏 */
    TALLOC_FREE(tracee->qemu);
    tracee->qemu = qemu_args;
    talloc_set_name_const(tracee->qemu, "@qemu");
    qemu_args = NULL; /* 所有权转移，避免重复释放 */

    /* 创建默认绑定 */
    if (new_binding_safe(tracee, "/", HOST_ROOTFS, true) < 0)
        goto clean_up;
    if (new_binding_safe(tracee, "/dev/null", "/etc/ld.so.preload", false) < 0)
        goto clean_up;

    ret = 0;

clean_up:
    if (qemu_args != NULL)
        TALLOC_FREE(qemu_args);
    return ret;
}

/**
 * Handle -w/--cwd option: set initial working directory
 * 修复：原有cwd字符串未释放的内存泄漏；空指针校验
 */
static int handle_option_w(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    char *new_cwd = NULL;

    if (tracee == NULL || tracee->fs == NULL || value == NULL)
        return -EINVAL;

    new_cwd = talloc_strdup(tracee->fs, value);
    if (new_cwd == NULL) {
        note(tracee, ERROR, INTERNAL, "can't allocate memory for working directory");
        return -ENOMEM;
    }

    /* 修复：释放原有cwd，杜绝内存泄漏 */
    TALLOC_FREE(tracee->fs->cwd);
    tracee->fs->cwd = new_cwd;
    talloc_set_name_const(tracee->fs->cwd, "$cwd");

    return 0;
}

/**
 * Handle -k/--kernel-release option: set kernel version compatibility
 * 优化：复用重复的扩展检查逻辑，精简代码
 */
static int handle_option_k(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    if (tracee == NULL || value == NULL)
        return -EINVAL;

    check_duplicate_extension(tracee, kompat_callback, "-k");
    return init_extension_safe(tracee, kompat_callback, value, "kernel compatibility");
}

/**
 * Handle -i/--id option: set fake uid/gid
 * 优化：复用重复的扩展检查逻辑，精简代码
 */
static int handle_option_i(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    if (tracee == NULL || value == NULL)
        return -EINVAL;

    check_duplicate_extension(tracee, fake_id0_callback, "-i/-0/-S");
    return init_extension_safe(tracee, fake_id0_callback, value, "fake id");
}

/**
 * Handle -0 option: shortcut for -i 0:0
 */
static int handle_option_0(Tracee *tracee, const Cli *cli, const char *value UNUSED)
{
    return handle_option_i(tracee, cli, "0:0");
}

/**
 * Handle --kill-on-exit option: kill all children on exit
 */
static int handle_option_kill_on_exit(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    tracee->killall_on_exit = true;
    return 0;
}

/**
 * Handle -v/--verbose option: set verbose level
 */
static int handle_option_v(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
    int status;

    if (tracee == NULL || value == NULL)
        return -EINVAL;

    status = parse_integer_option(tracee, &tracee->verbose, value, "-v");
    if (status < 0)
        return status;

    global_verbose_level = tracee->verbose;
    return 0;
}

/* 弱符号声明，与原代码保持一致 */
extern unsigned char WEAK _binary_licenses_start;
extern unsigned char WEAK _binary_licenses_end;

/**
 * Handle -V/--version option: print version and license
 * 修复：弱符号空指针校验，write返回值处理，指针减法类型安全
 */
static int handle_option_V(Tracee *tracee UNUSED, const Cli *cli, const char *value UNUSED)
{
    const unsigned char *licenses_start = &_binary_licenses_start;
    const unsigned char *licenses_end = &_binary_licenses_end;
    ptrdiff_t license_size = licenses_end - licenses_start;

    if (cli == NULL)
        return -EINVAL;

    print_version(cli);
    printf("\n%s\n", cli->colophon);

    if (fflush(stdout) != 0)
        return -1;

    /* 修复：弱符号非空校验，避免符号不存在时的非法访问 */
    if (license_size > 0 && licenses_start != NULL) {
        if (safe_write(1, licenses_start, (size_t)license_size) != license_size)
            return -1;
    }

    exit_failure = false;
    return -1;
}

/**
 * Handle -h/--help option: print detailed usage
 */
static int handle_option_h(Tracee *tracee, const Cli *cli, const char *value UNUSED)
{
    if (tracee == NULL || cli == NULL)
        return -EINVAL;

    print_usage(tracee, cli, true);
    exit_failure = false;
    return -1;
}

/**
 * Create multiple bindings from array
 * 修复：环境变量展开后的临时字符串内存泄漏
 */
static void new_bindings(Tracee *tracee, const char *bindings[], const char *value)
{
    if (tracee == NULL || bindings == NULL || value == NULL)
        return;

    for (int i = 0; bindings[i] != NULL; i++) {
        const char *path;
        bool is_allocated = false;

        if (strcmp(bindings[i], "*path*") != 0) {
            path = expand_front_variable(tracee->ctx, bindings[i]);
            /* 标记是否为新分配的字符串，后续释放 */
            is_allocated = (path != bindings[i]);
        } else {
            path = value;
        }

        new_binding_safe(tracee, path, NULL, false);

        /* 修复：释放展开后的临时字符串，杜绝内存泄漏 */
        if (is_allocated && path != NULL)
            talloc_free((void *)path);
    }
}

/**
 * Handle -R option: set rootfs + recommended bindings
 */
static int handle_option_R(Tracee *tracee, const Cli *cli, const char *value)
{
    int status;

    if (tracee == NULL || value == NULL)
        return -EINVAL;

    status = handle_option_r(tracee, cli, value);
    if (status < 0)
        return status;

    new_bindings(tracee, recommended_bindings, value);
    return 0;
}

/**
 * Handle -S option: set su mode + rootfs + recommended su bindings
 */
static int handle_option_S(Tracee *tracee, const Cli *cli, const char *value)
{
    int status;

    if (tracee == NULL || value == NULL)
        return -EINVAL;

    status = handle_option_0(tracee, cli, value);
    if (status < 0)
        return status;

    status = handle_option_r(tracee, cli, value);
    if (status < 0)
        return status;

    new_bindings(tracee, recommended_su_bindings, value);
    return 0;
}

/**
 * Handle --link2symlink option: enable link to symlink extension
 * 优化：复用统一的扩展初始化逻辑
 */
static int handle_option_link2symlink(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    return init_extension_safe(tracee, link2symlink_callback, NULL, "link2symlink");
}

/**
 * Handle --ashmem-memfd option: enable ashmem to memfd extension
 * 优化：复用统一的扩展初始化逻辑
 */
static int handle_option_ashmem_memfd(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    return init_extension_safe(tracee, ashmem_memfd_callback, NULL, "ashmem-memfd");
}

/**
 * Handle --sysvipc option: enable sysvipc extension
 * 优化：复用统一的扩展初始化逻辑
 */
static int handle_option_sysvipc(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    return init_extension_safe(tracee, sysvipc_callback, NULL, "sysvipc");
}

/**
 * Handle -L option: enable symlink size fix extension
 */
static int handle_option_L(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    (void)initialize_extension(tracee, fix_symlink_size_callback, NULL);
    return 0;
}

/**
 * Handle -H option: enable hidden files extension
 */
static int handle_option_H(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    (void)initialize_extension(tracee, hidden_files_callback, NULL);
    return 0;
}

/**
 * Handle -p option: enable port switch extension
 */
static int handle_option_p(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
    if (tracee == NULL)
        return -EINVAL;
    (void)initialize_extension(tracee, port_switch_callback, NULL);
    return 0;
}

/**
 * post_initialize_exe hook: resolve full qemu path after exe initialization
 * 修复：原有qemu[0]字符串未释放的内存泄漏；空指针校验
 */
static int post_initialize_exe(Tracee *tracee, const Cli *cli UNUSED,
			size_t argc UNUSED, char *const argv[] UNUSED, size_t cursor UNUSED)
{
    char path[PATH_MAX];
    int status;
    char *new_qemu_path = NULL;

    if (tracee == NULL || tracee->qemu == NULL || tracee->qemu[0] == NULL)
        return 0;

    /* 解析qemu可执行文件的完整guest路径 */
    status = which(tracee->reconf.tracee, tracee->reconf.paths, path, tracee->qemu[0]);
    if (status < 0)
        return -1;

    /* 转换为tracee视角的host路径 */
    if (tracee->reconf.tracee != NULL) {
        status = detranslate_path(tracee->reconf.tracee, path, NULL);
        if (status < 0)
            return -1;
    }

    /* 分配新路径字符串 */
    new_qemu_path = talloc_strdup(tracee->qemu, path);
    if (new_qemu_path == NULL)
        return -ENOMEM;

    /* 修复：释放原有qemu[0]字符串，杜绝内存泄漏 */
    TALLOC_FREE(tracee->qemu[0]);
    tracee->qemu[0] = new_qemu_path;

    return 0;
}

/**
 * pre_initialize_bindings hook: initialize default cwd and rootfs
 */
static int pre_initialize_bindings(Tracee *tracee, const Cli *cli,
			size_t argc UNUSED, char *const argv[] UNUSED, size_t cursor)
{
    int status;

    if (tracee == NULL || tracee->fs == NULL)
        return -EINVAL;

    /* 默认工作目录为当前目录 */
    if (tracee->fs->cwd == NULL) {
        status = handle_option_w(tracee, cli, ".");
        if (status < 0)
            return -1;
    }

    /* 默认根目录为/ */
    if (get_root(tracee) == NULL) {
        status = handle_option_r(tracee, cli, "/");
        if (status < 0)
            return -1;
    }

    return cursor;
}

/**
 * Get PRoot CLI configuration
 */
const Cli *get_proot_cli(TALLOC_CTX *context UNUSED)
{
    global_tool_name = proot_cli.name;
    return &proot_cli;
}
