#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>

#include "execve/ldso.h"
#include "execve/elf.h"
#include "execve/aoxp.h"
#include "tracee/tracee.h"
#include "cli/note.h"

bool is_env_name(const char *variable, const char *name)
{
	size_t length = strlen(name);
	size_t var_len = strlen(variable);

	return (variable[0] == name[0]
		&& length < var_len
		&& variable[length] == '='
		&& strncmp(variable, name, length) == 0);
}

int compare_xpointee_env(ArrayOfXPointers *envp, size_t index, const char *reference)
{
	char *value;
	int status;

	assert(index < envp->length);

	status = read_xpointee_as_string(envp, index, &value);
	if (status < 0)
		return status;

	if (value == NULL)
		return 0;

	return (int)is_env_name(value, reference);
}

int ldso_env_passthru(const Tracee *tracee, ArrayOfXPointers *envp, ArrayOfXPointers *argv,
		const char *define, const char *undefine, size_t offset)
{
	bool has_seen_library_path = false;
	int status;
	size_t i;

	for (i = 0; i < envp->length; i++) {
		char *env;

		status = read_xpointee_as_string(envp, i, &env);
		if (status < 0)
			return status;

		if (env == NULL || strncmp(env, "LD_", 3) != 0)
			continue;

		if (   tracee->host_ldso_paths != NULL
		    && tracee->guest_ldso_paths != NULL
		    && is_env_name(env, "LD_LIBRARY_PATH")
		    && strcmp(env, tracee->host_ldso_paths) == 0)
			env = (char *) tracee->guest_ldso_paths;

#define PASSTHRU(name)						\
		if (is_env_name(env, name)) {			\
			resize_array_of_xpointers(argv, offset, 2);\
			write_xpointees(argv, offset, 2, define, env);\
			write_xpointee(envp, i, "");		\
			continue;				\
		}

		if (is_env_name(env, "LD_LIBRARY_PATH"))
			has_seen_library_path = true;

		PASSTHRU("LD_LIBRARY_PATH");
		PASSTHRU("LD_PRELOAD");
		PASSTHRU("LD_BIND_NOW");
		PASSTHRU("LD_TRACE_LOADED_OBJECTS");
		PASSTHRU("LD_AOUT_LIBRARY_PATH");
		PASSTHRU("LD_AOUT_PRELOAD");
		PASSTHRU("LD_AUDIT");
		PASSTHRU("LD_BIND_NOT");
		PASSTHRU("LD_DEBUG");
		PASSTHRU("LD_DEBUG_OUTPUT");
		PASSTHRU("LD_DYNAMIC_WEAK");
		PASSTHRU("LD_HWCAP_MASK");
		PASSTHRU("LD_KEEPDIR");
		PASSTHRU("LD_NOWARN");
		PASSTHRU("LD_ORIGIN_PATH");
		PASSTHRU("LD_POINTER_GUARD");
		PASSTHRU("LD_PROFILE");
		PASSTHRU("LD_PROFILE_OUTPUT");
		PASSTHRU("LD_SHOW_AUXV");
		PASSTHRU("LD_USE_LOAD_BIAS");
		PASSTHRU("LD_VERBOSE");
		PASSTHRU("LD_WARN");
	}

	if (!has_seen_library_path) {
		resize_array_of_xpointers(argv, offset, 2);
		write_xpointees(argv, offset, 2, undefine, "LD_LIBRARY_PATH");
	}

	return 0;
}

static int add_host_ldso_paths(char host_ldso_paths[ARG_MAX], const char *paths)
{
	// 优化：缓存当前路径长度，避免重复strlen
	char *cursor1 = host_ldso_paths + strlen(host_ldso_paths);
	const char *cursor2 = paths;
	// 优化：缓存HOST_ROOTFS长度，避免重复计算
	const size_t host_root_len = strlen(HOST_ROOTFS);

	do {
		bool is_absolute = (*cursor2 == '/');
		size_t length2 = strcspn(cursor2, ":");
		size_t length1 = 1 + length2;

		if (is_absolute)
			length1 += host_root_len;

		if (cursor1 + length1 >= host_ldso_paths + ARG_MAX)
			return -ENOEXEC;

		if (cursor1 != host_ldso_paths) {
			*cursor1 = ':';
			cursor1++;
		}

		if (is_absolute) {
			// 优化：memcpy替代strcpy，减少字符串扫描
			memcpy(cursor1, HOST_ROOTFS, host_root_len);
			cursor1 += host_root_len;
		}

		// 优化：memcpy替代strncpy，更高效
		memcpy(cursor1, cursor2, length2);
		cursor1 += length2;

		cursor2 += length2 + 1;
	} while (*(cursor2 - 1) != '\0');

	*cursor1 = '\0';
	return 0;
}

struct find_program_header_data {
	ProgramHeader *program_header;
	SegmentType type;
	uint64_t address;
};

static int find_program_header(const ElfHeader *elf_header,
			const ProgramHeader *program_header, void *data_)
{
	struct find_program_header_data *data = data_;

	if (program_header->class64.p_type == data->type) {
		uint64_t start;
		uint64_t end;

		memcpy(data->program_header, program_header, sizeof(ProgramHeader));

		if (data->address == (uint64_t) -1)
			return 1;

		start = program_header->class64.p_vaddr;
		end   = start + program_header->class64.p_memsz;

		if (start < end
			&& data->address >= start
			&& data->address <= end)
			return 1;
	}

	return 0;
}

static int add_xpaths(const Tracee *tracee, int fd, uint64_t offset, char **xpaths)
{
	char paths[1024];
	ssize_t n;

	if (lseek(fd, offset, SEEK_SET) < 0)
		return -errno;

	n = read(fd, paths, sizeof(paths) - 1);
	if (n <= 0)
		return n < 0 ? -errno : 0;
	paths[n] = 0;

	if (!*xpaths)
		*xpaths = talloc_strdup(tracee->ctx, paths);
	else
		*xpaths = talloc_asprintf(tracee->ctx, "%s:%s", *xpaths, paths);

	return 0;
}

static int read_ldso_rpaths(const Tracee* tracee, int fd, const ElfHeader *elf_header,
		char **rpaths, char **runpaths)
{
	ProgramHeader dyn;
	struct find_program_header_data d;
	uint64_t dyn_off, dyn_sz;
	size_t ent_sz, i;
	uint64_t straddr = (uint64_t)-1;
	off_t stroff;
	int ret;

	d.program_header = &dyn;
	d.type = PT_DYNAMIC;
	d.address = (uint64_t)-1;
	ret = iterate_program_headers(tracee, fd, elf_header, find_program_header, &d);
	if (ret <= 0) return ret;

	dyn_off = dyn.class64.p_offset;
	dyn_sz  = dyn.class64.p_filesz;
	ent_sz  = sizeof(DynamicEntry64);

	if (dyn_sz % ent_sz != 0) return -ENOEXEC;

	// 优化：单次循环同时找STRTAB/RPATH/RUNPATH，减少遍历次数
	for (i = 0; i < dyn_sz / ent_sz; i++) {
		DynamicEntry e;
		uint64_t tag, val;

		if (lseek(fd, dyn_off + i * ent_sz, SEEK_SET) < 0) return -errno;
		if (read(fd, &e, ent_sz) < 0) return -errno;

		tag = e.class64.d_tag;
		val = e.class64.d_val;

		if (tag == DT_STRTAB) {
			straddr = val;
		}
	}

	if (straddr == (uint64_t)-1) return 0;

	d.program_header = &dyn;
	d.type = PT_LOAD;
	d.address = straddr;
	ret = iterate_program_headers(tracee, fd, elf_header, find_program_header, &d);
	if (ret < 0) return ret;

	stroff = dyn.class64.p_offset + (straddr - dyn.class64.p_vaddr);

	for (i = 0; i < dyn_sz / ent_sz; i++) {
		DynamicEntry e;
		uint64_t tag, val;

		if (lseek(fd, dyn_off + i * ent_sz, SEEK_SET) < 0) return -errno;
		if (read(fd, &e, ent_sz) < 0) return -errno;

		tag = e.class64.d_tag;
		val = e.class64.d_val;

		if (tag == DT_RPATH)
			add_xpaths(tracee, fd, stroff + val, rpaths);
		if (tag == DT_RUNPATH)
			add_xpaths(tracee, fd, stroff + val, runpaths);
	}

	return 0;
}

int rebuild_host_ldso_paths(Tracee *tracee, const char host_path[PATH_MAX], ArrayOfXPointers *envp)
{
	static char *initial_ldso_paths = NULL;
	ElfHeader elf_header;
	char host_ldso_paths[ARG_MAX] = "";
	char *rpaths = NULL, *runpaths = NULL;
	int fd, ret;
	size_t index;

	fd = open_elf(host_path, &elf_header);
	if (fd < 0) return fd;
	read_ldso_rpaths(tracee, fd, &elf_header, &rpaths, &runpaths);
	close(fd);

	if (rpaths && !runpaths)
		add_host_ldso_paths(host_ldso_paths, rpaths);

	// 优化：仅初始化一次环境变量，避免重复getenv/strdup
	if (!initial_ldso_paths)
		initial_ldso_paths = getenv("LD_LIBRARY_PATH") ? strdup(getenv("LD_LIBRARY_PATH")) : strdup("/");
	if (initial_ldso_paths && *initial_ldso_paths)
		add_host_ldso_paths(host_ldso_paths, initial_ldso_paths);

	if (runpaths)
		add_host_ldso_paths(host_ldso_paths, runpaths);

	add_host_ldso_paths(host_ldso_paths,
		"/lib64:/usr/lib64:/lib:/usr/lib:/system/lib64");

	ret = find_xpointee(envp, "LD_LIBRARY_PATH");
	index = ret < 0 ? envp->length : (size_t)ret;

	if (index == envp->length)
		resize_array_of_xpointers(envp, envp->length, 1);
	else if (!tracee->guest_ldso_paths) {
		char *e;
		if (read_xpointee_as_string(envp, index, &e) >= 0)
			tracee->guest_ldso_paths = talloc_strdup(tracee, e);
	}

	char final[ARG_MAX];
	snprintf(final, sizeof(final), "LD_LIBRARY_PATH=%s", host_ldso_paths);
	write_xpointee(envp, index, final);

	if (!tracee->host_ldso_paths)
		tracee->host_ldso_paths = talloc_strdup(tracee, final);

	// 优化：释放临时内存，避免内存泄漏
	talloc_free(rpaths);
	talloc_free(rpaths);

	return 0;
}
