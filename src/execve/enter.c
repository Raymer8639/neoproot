#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <talloc.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "execve/execve.h"
#include "execve/shebang.h"
#include "execve/aoxp.h"
#include "execve/ldso.h"
#include "execve/elf.h"
#include "path/path.h"
#include "path/temp.h"
#include "path/binding.h"
#include "tracee/tracee.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "arch.h"
#include "cli/note.h"

#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x)  __builtin_expect(!!(x), 1)
#define PAGE_SIZE_DEFAULT 0x1000

static TALLOC_CTX *g_loader_ctx = NULL;

static void loader_ctx_cleanup(void)
{
	if (g_loader_ctx) {
		talloc_free(g_loader_ctx);
		g_loader_ctx = NULL;
	}
}

__attribute__((constructor))
static void loader_ctx_init(void)
{
	if (!g_loader_ctx) {
		g_loader_ctx = talloc_new(NULL);
		if (g_loader_ctx)
			atexit(loader_ctx_cleanup);
	}
}

static int map_segment(LoadInfo *info, const ProgramHeader *ph)
{
	size_t n;
	word_t page_size, page_mask;
	word_t vaddr, fsz, msz, off, flags;
	word_t start, end;
	Mapping *m;

	static word_t cached_ps = 0;
	static word_t cached_pm = 0;

	if (cached_ps == 0) {
		cached_ps = sysconf(_SC_PAGE_SIZE);
		if (cached_ps <= 0)
			cached_ps = PAGE_SIZE_DEFAULT;
		cached_pm = ~(cached_ps - 1);
	}
	page_size = cached_ps;
	page_mask = cached_pm;

	n = info->mappings ? talloc_array_length(info->mappings) : 0;

	info->mappings = talloc_realloc(info, info->mappings, Mapping, n + 1);
	if (UNLIKELY(!info->mappings))
		return -ENOMEM;

	vaddr = ph->class64.p_vaddr;
	fsz   = ph->class64.p_filesz;
	msz   = ph->class64.p_memsz;
	off   = ph->class64.p_offset;
	flags = ph->class64.p_flags;

	start = vaddr & page_mask;
	end   = (vaddr + fsz + page_size) & page_mask;

	m = &info->mappings[n];
	m->fd        = -1;
	m->offset    = off & page_mask;
	m->addr      = start;
	m->length    = end - start;
	m->flags     = MAP_PRIVATE | MAP_FIXED;
	m->prot      = 0;
	if (flags & PF_R) m->prot |= PROT_READ;
	if (flags & PF_W) m->prot |= PROT_WRITE;
	if (flags & PF_X) m->prot |= PROT_EXEC;
	m->clear_length = 0;

	if (msz > fsz) {
		size_t n2;
		word_t new_start, new_end;

		m->clear_length = end - vaddr - fsz;
		new_start = end;
		new_end   = (vaddr + msz + page_size) & page_mask;

		if (new_end <= new_start)
			return 0;

		n2 = n + 1;
		info->mappings = talloc_realloc(info, info->mappings, Mapping, n2 + 1);
		if (UNLIKELY(!info->mappings))
			return -ENOMEM;

		m = &info->mappings[n2];
		m->fd        = -1;
		m->offset    = 0;
		m->addr      = new_start;
		m->length    = new_end - new_start;
		m->flags     = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
		m->prot      = info->mappings[n].prot;
		m->clear_length = 0;
	}

	return 0;
}

int translate_and_check_exec(Tracee *tr, char host[PATH_MAX], const char *user)
{
	int ret;
	struct stat st;

	if (user[0] == '\0')
		return -ENOEXEC;

	ret = translate_path(tr, host, AT_FDCWD, user, true);
	if (UNLIKELY(ret < 0))
		return ret;

	if (access(host, F_OK | X_OK) < 0)
		return (errno == ENOENT) ? -ENOENT : -EACCES;

	if (UNLIKELY(lstat(host, &st) < 0))
		return -EPERM;

	return 0;
}

static int add_interp(Tracee *tr, int fd, LoadInfo *info, const ProgramHeader *ph)
{
	char host[PATH_MAX];
	char *user = NULL;
	size_t fsz;
	word_t off;
	int ret;

	if (info->interp)
		return -EINVAL;

	info->interp = talloc_zero(info, LoadInfo);
	if (UNLIKELY(!info->interp))
		return -ENOMEM;

	fsz = ph->class64.p_filesz;
	off = ph->class64.p_offset;

	user = talloc_size(tr->ctx, fsz + 1);
	if (UNLIKELY(!user))
		return -ENOMEM;

	ret = pread(fd, user, fsz, off);
	if (UNLIKELY((size_t)ret != fsz)) {
		TALLOC_FREE(user);
		return -EIO;
	}
	user[fsz] = '\0';

	if (tr->qemu && user[0] == '/') {
		char *new_user = talloc_asprintf(tr->ctx, "%s%s", HOST_ROOTFS, user);
		if (UNLIKELY(!new_user)) {
			TALLOC_FREE(user);
			return -ENOMEM;
		}
		TALLOC_FREE(user);
		user = new_user;
	}

	ret = translate_and_check_exec(tr, host, user);
	if (UNLIKELY(ret < 0)) {
		TALLOC_FREE(user);
		return ret;
	}

	info->interp->host_path = talloc_strdup(info->interp, host);
	info->interp->user_path = talloc_strdup(info->interp, user);
	TALLOC_FREE(user);

	if (UNLIKELY(!info->interp->host_path || !info->interp->user_path))
		return -ENOMEM;

	return 0;
}

struct ph_iter_data {
	Tracee    *tr;
	LoadInfo  *info;
	int        fd;
};

static int ph_callback(const ElfHeader *eh, const ProgramHeader *ph, void *data)
{
	struct ph_iter_data *d = data;
	uint32_t type;
	int ret;

	(void)eh;

	type = ph->class64.p_type;

	switch (type) {
		case PT_LOAD:
			ret = map_segment(d->info, ph);
			break;
		case PT_INTERP:
			ret = add_interp(d->tr, d->fd, d->info, ph);
			break;
		case PT_GNU_STACK:
			d->info->needs_executable_stack = !!(ph->class64.p_flags & PF_X);
			ret = 0;
			break;
		default:
			ret = 0;
	}

	return ret;
}

static int extract_load_info(Tracee *tr, LoadInfo *info)
{
	int fd, ret;
	uint32_t type;
	struct ph_iter_data data;

	assert(info && info->host_path);

	fd = open_elf(info->host_path, &info->elf_header);
	if (UNLIKELY(fd < 0))
		return fd;

	type = info->elf_header.class64.e_type;
	if (UNLIKELY(type != ET_EXEC && type != ET_DYN)) {
		close(fd);
		return -ENOEXEC;
	}

	data.tr   = tr;
	data.info = info;
	data.fd   = fd;

	ret = iterate_program_headers(tr, fd, &info->elf_header, ph_callback, &data);
	close(fd);
	return ret;
}

static void apply_load_base(LoadInfo *info, word_t base)
{
	size_t i, n;
	Mapping *m;

	if (!info->mappings)
		return;

	n = talloc_array_length(info->mappings);
	for (i = 0; LIKELY(i < n); i++) {
		m = &info->mappings[i];
		m->addr += base;
	}

	info->elf_header.class64.e_entry += base;
}

static void compute_load_addresses(Tracee *tr)
{
	LoadInfo *main = tr->load_info;
	LoadInfo *interp;

	if (!main || !main->mappings)
		return;

	if (IS_POSITION_INDEPENDANT(main->elf_header) && main->mappings[0].addr == 0) {
		apply_load_base(main, EXEC_PIC_ADDRESS);
	}

	interp = main->interp;
	if (!interp || !interp->mappings)
		return;

	if (IS_POSITION_INDEPENDANT(interp->elf_header) && interp->mappings[0].addr == 0) {
		apply_load_base(interp, INTERP_PIC_ADDRESS);
	}
}

static int expand_runner(Tracee *tr, char host[PATH_MAX], char user[PATH_MAX])
{
	ArrayOfXPointers *env, *argv;
	char *arg0;
	size_t nq;
	int ret;

	ret = fetch_array_of_xpointers(tr, &env, SYSARG_3, 0);
	if (UNLIKELY(ret < 0))
		return ret;
	env->compare_xpointee = (compare_xpointee_t)compare_xpointee_env;

	if (is_host_elf(tr, host))
		goto patch_env;

	tr->skip_proot_loader = (getenv("PROOT_USE_LOADER_FOR_QEMU") == NULL);

	ret = fetch_array_of_xpointers(tr, &argv, SYSARG_2, 0);
	if (UNLIKELY(ret < 0))
		return ret;

	ret = read_xpointee_as_string(argv, 0, &arg0);
	if (UNLIKELY(ret < 0))
		return ret;

	nq = tr->qemu ? talloc_array_length(tr->qemu) - 1 : 0;
	ret = resize_array_of_xpointers(argv, 1, nq + 2);
	if (UNLIKELY(ret < 0)) {
		TALLOC_FREE(arg0);
		return ret;
	}

	for (size_t i = 0; LIKELY(i < nq); i++) {
		ret = write_xpointee(argv, i, tr->qemu[i]);
		if (UNLIKELY(ret < 0)) {
			TALLOC_FREE(arg0);
			return ret;
		}
	}

	ret = write_xpointees(argv, nq, 3, "-0", arg0, user);
	TALLOC_FREE(arg0);
	if (UNLIKELY(ret < 0))
		return ret;

	ret = ldso_env_passthru(tr, env, argv, "-E", "-U", (int)nq);
	if (UNLIKELY(ret < 0))
		return ret;

	ret = push_array_of_xpointers(argv, SYSARG_2);
	if (UNLIKELY(ret < 0))
		return ret;

	snprintf(host, PATH_MAX, "%s", tr->qemu[0]);
	if (tr->skip_proot_loader)
		snprintf(user, PATH_MAX, "%s", host);
	else
		snprintf(user, PATH_MAX, "%s%s", HOST_ROOTFS, host);

patch_env:
	ret = rebuild_host_ldso_paths(tr, host, env);
	if (UNLIKELY(ret < 0))
		return ret;

	return push_array_of_xpointers(env, SYSARG_3);
}

#if !defined(PROOT_UNBUNDLE_LOADER)
extern unsigned char _binary_loader_exe_start;
extern unsigned char _binary_loader_exe_end;

static char *extract_loader(void)
{
	char path[PATH_MAX];
	void *start;
	size_t len;
	int fd;
	FILE *f;
	char *out = NULL;
	ssize_t w;

	if (!g_loader_ctx)
		return NULL;

	f = open_temp_file(NULL, "proot-loader");
	if (!f)
		return NULL;

	fd = fileno(f);

	start = &_binary_loader_exe_start;
	len   = &_binary_loader_exe_end - &_binary_loader_exe_start;

	w = write(fd, start, len);
	if (UNLIKELY((size_t)w != len))
		goto out;

	fchmod(fd, S_IRUSR | S_IXUSR);
	if (UNLIKELY(readlink_proc_pid_fd(getpid(), fd, path) < 0))
		goto out;

	if (UNLIKELY(access(path, X_OK) < 0))
		goto out;

	out = talloc_strdup(g_loader_ctx, path);

out:
	fclose(f);
	return out;
}
#endif

static const char *get_loader_path(const Tracee *tr)
{
	(void)tr;

#if defined(PROOT_UNBUNDLE_LOADER)
	const char *env;
	env = getenv("PROOT_LOADER");
	if (env && access(env, X_OK) == 0)
		return env;
	return PROOT_UNBUNDLE_LOADER "/loader";
#else
	static char *loader = NULL;

	if (!g_loader_ctx)
		return NULL;

	if (!loader) {
		const char *env = getenv("PROOT_LOADER");
		if (env && access(env, X_OK) == 0)
			loader = talloc_strdup(g_loader_ctx, env);
		else
			loader = extract_loader();
	}
	return loader;
#endif
}

int translate_execve_enter(Tracee *tr)
{
	char user[PATH_MAX], host[PATH_MAX], new_exe[PATH_MAX];
	char *raw = NULL;
	const char *loader;
	int ret;

	// 关键：永远不走 ptrace 通知模式，loader 正常工作
	if (IS_NOTIFICATION_PTRACED_LOAD_DONE(tr)) {
		set_sysnum(tr, PR_void);
		return 0;
	}

	ret = get_sysarg_path(tr, user, SYSARG_1);
	if (UNLIKELY(ret < 0))
		return ret;

	raw = talloc_strdup(tr->ctx, user);
	if (UNLIKELY(!raw))
		return -ENOMEM;

	ret = expand_shebang(tr, host, user);
	if (UNLIKELY(ret < 0)) {
		TALLOC_FREE(raw);
		return (ret == -EISDIR) ? -EACCES : ret;
	}

	if (ret == 0 && !tr->qemu) {
		TALLOC_FREE(raw);
		raw = NULL;
	}

	talloc_unlink(tr, tr->host_exe);
	tr->host_exe = talloc_strdup(tr, host);

	snprintf(new_exe, PATH_MAX, "%s", host);
	detranslate_path(tr, new_exe, NULL);
	talloc_unlink(tr, tr->new_exe);
	tr->new_exe = talloc_strdup(tr, new_exe);

	tr->skip_proot_loader = false;
	if (tr->qemu) {
		ret = expand_runner(tr, host, user);
		if (UNLIKELY(ret < 0)) {
			TALLOC_FREE(raw);
			return ret;
		}
	}

	// 正常走 loader，不跳过
	talloc_unlink(tr, tr->load_info);
	tr->load_info = talloc_zero(tr, LoadInfo);
	if (UNLIKELY(!tr->load_info)) {
		TALLOC_FREE(raw);
		return -ENOMEM;
	}

	tr->load_info->host_path = talloc_strdup(tr->load_info, host);
	tr->load_info->user_path = talloc_strdup(tr->load_info, user);
	if (UNLIKELY(!tr->load_info->host_path || !tr->load_info->user_path)) {
		TALLOC_FREE(raw);
		return -ENOMEM;
	}

	if (raw) {
		tr->load_info->raw_path = talloc_reparent(tr->ctx, tr->load_info, raw);
		raw = NULL;
	} else {
		tr->load_info->raw_path = talloc_strdup(tr->load_info, tr->load_info->user_path);
	}

	if (UNLIKELY(!tr->load_info->raw_path))
		return -ENOMEM;

	ret = extract_load_info(tr, tr->load_info);
	if (UNLIKELY(ret < 0))
		return ret;

	if (tr->load_info->interp) {
		ret = extract_load_info(tr, tr->load_info->interp);
		if (UNLIKELY(ret < 0))
			return ret;
		TALLOC_FREE(tr->load_info->interp->interp);
	}

	compute_load_addresses(tr);

	loader = get_loader_path(tr);
	if (UNLIKELY(!loader))
		return -ENOENT;

	ret = set_sysarg_path(tr, loader, SYSARG_1);
	return ret;
}
