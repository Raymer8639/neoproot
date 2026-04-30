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

#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x)  __builtin_expect(!!(x), 1)

bool is_env_name(const char *variable, const char *name)
{
	size_t nlen = strlen(name);
	size_t vlen = strlen(variable);

	return (nlen < vlen
	     && variable[nlen] == '='
	     && !strncmp(variable, name, nlen));
}

int compare_xpointee_env(ArrayOfXPointers *envp, size_t index, const char *reference)
{
	char *value;
	int st;

	if (UNLIKELY(index >= envp->length))
		return -ERANGE;

	st = read_xpointee_as_string(envp, index, &value);
	if (UNLIKELY(st < 0))
		return st;

	return value ? is_env_name(value, reference) : 0;
}

int ldso_env_passthru(const Tracee *tracee, ArrayOfXPointers *envp, ArrayOfXPointers *argv,
		const char *define, const char *undefine, size_t offset)
{
	bool seen = false;
	int st;

	for (size_t i = 0; LIKELY(i < envp->length); i++) {
		char *env;

		st = read_xpointee_as_string(envp, i, &env);
		if (UNLIKELY(st < 0))
			return st;
		if (UNLIKELY(!env || strncmp(env, "LD_", 3)))
			continue;

		if (tracee->host_ldso_paths && tracee->guest_ldso_paths
		 && is_env_name(env, "LD_LIBRARY_PATH")
		 && !strcmp(env, tracee->host_ldso_paths))
			env = (char *)tracee->guest_ldso_paths;

#define PASSTHRU(n) \
		if (is_env_name(env, n)) { \
			resize_array_of_xpointers(argv, offset, 2); \
			write_xpointees(argv, offset, 2, define, env); \
			write_xpointee(envp, i, ""); \
			continue; \
		}

		if (is_env_name(env, "LD_LIBRARY_PATH"))
			seen = true;

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

	if (!seen) {
		resize_array_of_xpointers(argv, offset, 2);
		write_xpointees(argv, offset, 2, undefine, "LD_LIBRARY_PATH");
	}

	return 0;
}

static int add_host_ldso_paths(char host[ARG_MAX], const char *paths)
{
	size_t hr = strlen(host);
	char *d = host + hr;
	const char *s = paths;
	const size_t rootlen = strlen(HOST_ROOTFS);

	do {
		bool abs = (*s == '/');
		size_t sl = strcspn(s, ":");
		size_t need = 1 + sl + (abs ? rootlen : 0);

		if (d + need >= host + ARG_MAX)
			return -ENOEXEC;

		if (d != host)
			*d++ = ':';

		if (abs) {
			memcpy(d, HOST_ROOTFS, rootlen);
			d += rootlen;
		}
		memcpy(d, s, sl);
		d += sl;

		s += sl + 1;
	} while (*(s - 1));

	*d = '\0';
	return 0;
}

struct find_phdr_data {
	ProgramHeader *phdr;
	SegmentType type;
	uint64_t addr;
};

static int find_program_header(const ElfHeader *eh,
		const ProgramHeader *ph, void *ud)
{
	(void)eh;

	struct find_phdr_data *d = ud;

	if (ph->class64.p_type != d->type)
		return 0;

	memcpy(d->phdr, ph, sizeof(*ph));

	if (d->addr == (uint64_t)-1)
		return 1;

	uint64_t start = ph->class64.p_vaddr;
	uint64_t end   = start + ph->class64.p_memsz;

	return (start < end && d->addr >= start && d->addr <= end);
}

static int add_xpaths(const Tracee *t, int fd, uint64_t off, char **xp)
{
	char buf[1024];
	ssize_t n;

	if (lseek(fd, off, SEEK_SET) < 0)
		return -errno;

	n = read(fd, buf, sizeof(buf)-1);
	if (n <= 0)
		return n < 0 ? -errno : 0;
	buf[n] = 0;

	if (!*xp)
		*xp = talloc_strdup(t->ctx, buf);
	else
		*xp = talloc_asprintf(t->ctx, "%s:%s", *xp, buf);

	return 0;
}

static int read_ldso_rpaths(const Tracee *t, int fd, const ElfHeader *eh,
		char **rp, char **runp)
{
	ProgramHeader dyn;
	struct find_phdr_data d = {
		.phdr = &dyn,
		.type = PT_DYNAMIC,
		.addr = (uint64_t)-1
	};

	int ret = iterate_program_headers(t, fd, eh, find_program_header, &d);
	if (ret <= 0)
		return ret;

	uint64_t doff = dyn.class64.p_offset;
	uint64_t dsz  = dyn.class64.p_filesz;
	size_t   esz  = sizeof(DynamicEntry64);

	if (dsz % esz != 0)
		return -ENOEXEC;

	uint64_t strtab = (uint64_t)-1;
	for (size_t i = 0; i < dsz / esz; i++) {
		DynamicEntry e;
		if (lseek(fd, doff + i*esz, SEEK_SET) < 0 || read(fd, &e, esz) < 0)
			return -errno;
		if (e.class64.d_tag == DT_STRTAB)
			strtab = e.class64.d_val;
	}

	if (strtab == (uint64_t)-1)
		return 0;

	d.type  = PT_LOAD;
	d.addr  = strtab;
	ret = iterate_program_headers(t, fd, eh, find_program_header, &d);
	if (ret < 0)
		return ret;

	off_t stroff = dyn.class64.p_offset + (strtab - dyn.class64.p_vaddr);

	for (size_t i = 0; i < dsz / esz; i++) {
		DynamicEntry e;
		if (lseek(fd, doff + i*esz, SEEK_SET) < 0 || read(fd, &e, esz) < 0)
			return -errno;

		uint64_t tag = e.class64.d_tag;
		uint64_t val = e.class64.d_val;

		if (tag == DT_RPATH)
			add_xpaths(t, fd, stroff + val, rp);
		if (tag == DT_RUNPATH)
			add_xpaths(t, fd, stroff + val, runp);
	}

	return 0;
}

int rebuild_host_ldso_paths(Tracee *t, const char host_path[PATH_MAX], ArrayOfXPointers *envp)
{
	static char *init_ld = NULL;
	ElfHeader eh;
	char host[ARG_MAX] = "";
	char *rp = NULL, *runp = NULL;
	int fd, ret;

	fd = open_elf(host_path, &eh);
	if (UNLIKELY(fd < 0))
		return fd;

	read_ldso_rpaths(t, fd, &eh, &rp, &runp);
	close(fd);

	if (rp && !runp)
		add_host_ldso_paths(host, rp);

	if (!init_ld) {
		const char *p = getenv("LD_LIBRARY_PATH");
		init_ld = p ? strdup(p) : strdup("/");
	}
	if (init_ld && *init_ld)
		add_host_ldso_paths(host, init_ld);

	if (runp)
		add_host_ldso_paths(host, runp);

	add_host_ldso_paths(host, "/lib64:/usr/lib64:/lib:/usr/lib:/system/lib64");

	ret = find_xpointee(envp, "LD_LIBRARY_PATH");
	size_t idx = ret < 0 ? envp->length : (size_t)ret;

	if (idx == envp->length)
		resize_array_of_xpointers(envp, idx, 1);
	else if (!t->guest_ldso_paths) {
		char *e;
		if (read_xpointee_as_string(envp, idx, &e) >= 0)
			t->guest_ldso_paths = talloc_strdup(t, e);
	}

	char final[ARG_MAX];
	snprintf(final, sizeof(final), "LD_LIBRARY_PATH=%s", host);
	write_xpointee(envp, idx, final);

	if (!t->host_ldso_paths)
		t->host_ldso_paths = talloc_strdup(t, final);

	talloc_free(rp);
	talloc_free(runp);

	return 0;
}
