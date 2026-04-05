#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <sys/queue.h>
#include <talloc.h>
#include <stdlib.h>

#include "path/binding.h"
#include "path/path.h"
#include "path/canon.h"
#include "cli/note.h"
#include "compat.h"

#define HEAD(tracee, side)						\
	(side == GUEST							\
		? (tracee)->fs->bindings.guest				\
		: (side == HOST						\
			? (tracee)->fs->bindings.host			\
			: (tracee)->fs->bindings.pending))

#define NEXT(binding, side)						\
	(side == GUEST							\
		? CIRCLEQ_NEXT(binding, link.guest)			\
		: (side == HOST						\
			? CIRCLEQ_NEXT(binding, link.host)		\
			: CIRCLEQ_NEXT(binding, link.pending)))

#define CIRCLEQ_FOREACH_(tracee, binding, side)				\
	for (binding = CIRCLEQ_FIRST(HEAD(tracee, side));		\
	     binding != (void *) HEAD(tracee, side);			\
	     binding = NEXT(binding, side))

#define CIRCLEQ_INSERT_AFTER_(tracee, previous, binding, side) do {	\
	switch (side) {							\
	case GUEST: CIRCLEQ_INSERT_AFTER(HEAD(tracee, side), previous, binding, link.guest); break; \
	case HOST:  CIRCLEQ_INSERT_AFTER(HEAD(tracee, side), previous, binding, link.host);  break; \
	default:    CIRCLEQ_INSERT_AFTER(HEAD(tracee, side), previous, binding, link.pending); break; \
	}								\
	(void) talloc_reference(HEAD(tracee, side), binding);		\
} while (0)

#define CIRCLEQ_INSERT_BEFORE_(tracee, next, binding, side) do {	\
	switch (side) {							\
	case GUEST: CIRCLEQ_INSERT_BEFORE(HEAD(tracee, side), next, binding, link.guest); break; \
	case HOST:  CIRCLEQ_INSERT_BEFORE(HEAD(tracee, side), next, binding, link.host);  break; \
	default:    CIRCLEQ_INSERT_BEFORE(HEAD(tracee, side), next, binding, link.pending); break; \
	}								\
	(void) talloc_reference(HEAD(tracee, side), binding);		\
} while (0)

#define CIRCLEQ_INSERT_HEAD_(tracee, binding, side) do {		\
	switch (side) {							\
	case GUEST: CIRCLEQ_INSERT_HEAD(HEAD(tracee, side), binding, link.guest); break; \
	case HOST:  CIRCLEQ_INSERT_HEAD(HEAD(tracee, side), binding, link.host);  break; \
	default:    CIRCLEQ_INSERT_HEAD(HEAD(tracee, side), binding, link.pending); break; \
	}								\
	(void) talloc_reference(HEAD(tracee, side), binding);		\
} while (0)

#define IS_LINKED(binding, link)					\
	((binding)->link.cqe_next != NULL && (binding)->link.cqe_prev != NULL)

#define CIRCLEQ_REMOVE_(tracee, binding, name) do {			\
	CIRCLEQ_REMOVE((tracee)->fs->bindings.name, binding, link.name);\
	(binding)->link.name.cqe_next = NULL;				\
	(binding)->link.name.cqe_prev = NULL;				\
	talloc_unlink((tracee)->fs->bindings.name, binding);		\
} while (0)

/*============================================================================*/
/* 内部缓存：按长度排序的 binding 数组，实现最长前缀优先查找（不遍历全部）*/
/*============================================================================*/

static Binding **cached_guest_bindings = NULL;
static size_t cached_guest_count = 0;
static const char *cached_root = NULL;

static int compare_by_desc_length(const void *a, const void *b) {
	const Binding * const *ba = a;
	const Binding * const *bb = b;
	return ((*bb)->guest.length - (*ba)->guest.length);
}

static void build_guest_binding_cache(Tracee *tracee) {
	if (cached_guest_bindings) return;

	size_t n = 0;
	Binding *b;
	CIRCLEQ_FOREACH_(tracee, b, GUEST) n++;

	if (n == 0) return;

	Binding **tab = talloc_array(tracee->fs, Binding *, n);
	if (!tab) return;

	n = 0;
	CIRCLEQ_FOREACH_(tracee, b, GUEST) tab[n++] = b;

	qsort(tab, n, sizeof(Binding*), compare_by_desc_length);

	cached_guest_bindings = tab;
	cached_guest_count = n;
}

static Binding *find_best_prefix(const char *path) {
	if (!cached_guest_bindings || cached_guest_count == 0)
		return NULL;

	size_t path_len = strlen(path);

	for (size_t i = 0; i < cached_guest_count; i++) {
		Binding *b = cached_guest_bindings[i];
		if (b->guest.length > path_len)
			continue;
		if (strncmp(b->guest.path, path, b->guest.length) == 0)
			return b;
	}
	return NULL;
}

/*============================================================================*/

static void print_bindings(const Tracee *tracee) {
	const Binding *binding;
	if (tracee->fs->bindings.guest == NULL)
		return;
	CIRCLEQ_FOREACH_(tracee, binding, GUEST) {
		if (compare_paths(binding->host.path, binding->guest.path) == PATHS_ARE_EQUAL)
			note(tracee, INFO, USER, "binding = %s", binding->host.path);
		else
			note(tracee, INFO, USER, "binding = %s:%s", binding->host.path, binding->guest.path);
	}
}

Binding *get_binding(const Tracee *tracee, Side side, const char path[PATH_MAX]) {
	if (!tracee || !path || *path != '/')
		return NULL;

	// 优先走缓存：最长前缀优先，不遍历全部
	if (side == GUEST) {
		Binding *b = find_best_prefix(path);
		if (b) return b;
	}

	//  fallback
	Binding *binding;
	size_t path_len = strlen(path);

	CIRCLEQ_FOREACH_(tracee, binding, side) {
		const Path *ref = (side == GUEST) ? &binding->guest : &binding->host;
		Comparison cmp = compare_paths2(ref->path, ref->length, path, path_len);
		if (cmp == PATHS_ARE_EQUAL || cmp == PATH1_IS_PREFIX)
			return binding;
	}

	return NULL;
}

const char *get_path_binding(const Tracee *tracee, Side side, const char path[PATH_MAX]) {
	const Binding *b = get_binding(tracee, side, path);
	if (!b) return NULL;
	return (side == GUEST) ? b->guest.path : b->host.path;
}

const char *get_root(const Tracee* tracee) {
	if (cached_root != NULL)
		return cached_root;

	if (!tracee || !tracee->fs)
		return NULL;

	const Binding *binding;

	if (tracee->fs->bindings.guest == NULL) {
		if (!tracee->fs->bindings.pending || CIRCLEQ_EMPTY(tracee->fs->bindings.pending))
			return NULL;
		binding = CIRCLEQ_LAST(tracee->fs->bindings.pending);
	} else {
		if (CIRCLEQ_EMPTY(tracee->fs->bindings.guest))
			return NULL;
		binding = CIRCLEQ_LAST(tracee->fs->bindings.guest);
	}

	if (compare_paths(binding->guest.path, "/") != PATHS_ARE_EQUAL)
		return NULL;

	cached_root = binding->host.path;
	return cached_root;
}

int substitute_binding(const Tracee *tracee, Side side, char path[PATH_MAX]) {
	const Binding *binding = get_binding(tracee, side, path);
	if (!binding)
		return -ENOENT;
	if (!binding->need_substitution)
		return 0;

	const Path *orig = (side == GUEST) ? &binding->guest : &binding->host;
	const Path *repl = (side == GUEST) ? &binding->host  : &binding->guest;

	substitute_path_prefix(path, orig->length, repl->path, repl->length);
	return 1;
}

void remove_binding_from_all_lists(const Tracee *tracee, Binding *binding) {
	if (IS_LINKED(binding, link.pending))
		CIRCLEQ_REMOVE_(tracee, binding, pending);
	if (IS_LINKED(binding, link.guest))
		CIRCLEQ_REMOVE_(tracee, binding, guest);
	if (IS_LINKED(binding, link.host))
		CIRCLEQ_REMOVE_(tracee, binding, host);
}

static void insort_binding(const Tracee *tracee, Side side, Binding *binding) {
	Binding *iterator, *prev = NULL, *next = CIRCLEQ_FIRST(HEAD(tracee, side));

	CIRCLEQ_FOREACH_(tracee, iterator, side) {
		const Path *bp = (side == GUEST || side == PENDING) ? &binding->guest : &binding->host;
		const Path *ip = (side == GUEST || side == PENDING) ? &iterator->guest : &iterator->host;
		Comparison cmp = compare_paths2(bp->path, bp->length, ip->path, ip->length);

		if (cmp == PATHS_ARE_EQUAL) {
			if (side == HOST) {
				prev = iterator;
				break;
			}
			if (tracee->verbose > 0 && getenv("PROOT_IGNORE_MISSING_BINDINGS") == NULL)
				note(tracee, WARNING, USER, "duplicate binding, keeping last: %s", bp->path);
			CIRCLEQ_INSERT_AFTER_(tracee, iterator, binding, side);
			remove_binding_from_all_lists(tracee, iterator);
			return;
		}
		if (cmp == PATH1_IS_PREFIX)
			prev = iterator;
		if (cmp == PATH2_IS_PREFIX && next == CIRCLEQ_FIRST(HEAD(tracee, side)))
			next = iterator;
	}

	if (prev)
		CIRCLEQ_INSERT_AFTER_(tracee, prev, binding, side);
	else if (next != CIRCLEQ_FIRST(HEAD(tracee, side)))
		CIRCLEQ_INSERT_BEFORE_(tracee, next, binding, side);
	else
		CIRCLEQ_INSERT_HEAD_(tracee, binding, side);
}

static void insort_binding2(const Tracee *tracee, Binding *binding) {
	binding->need_substitution =
		(compare_paths(binding->host.path, binding->guest.path) != PATHS_ARE_EQUAL);
	insort_binding(tracee, GUEST, binding);
	insort_binding(tracee, HOST, binding);
}

Binding *insort_binding3(const Tracee *tracee, const TALLOC_CTX *ctx,
                         const char *host, const char *guest) {
	Binding *b = talloc_zero(ctx, Binding);
	if (!b) return NULL;
	strcpy(b->host.path, host);
	strcpy(b->guest.path, guest);
	b->host.length = strlen(host);
	b->guest.length = strlen(guest);
	insort_binding2(tracee, b);
	return b;
}

static int remove_bindings(Bindings *bindings) {
	Tracee *tracee = TRACEE(bindings);
	Binding *b, *next;

	if (bindings == tracee->fs->bindings.pending) {
		b = CIRCLEQ_FIRST(bindings);
		while (b != (void*)bindings) {
			next = CIRCLEQ_NEXT(b, link.pending);
			CIRCLEQ_REMOVE_(tracee, b, pending);
			b = next;
		}
	} else if (bindings == tracee->fs->bindings.guest) {
		b = CIRCLEQ_FIRST(bindings);
		while (b != (void*)bindings) {
			next = CIRCLEQ_NEXT(b, link.guest);
			CIRCLEQ_REMOVE_(tracee, b, guest);
			b = next;
		}
	} else if (bindings == tracee->fs->bindings.host) {
		b = CIRCLEQ_FIRST(bindings);
		while (b != (void*)bindings) {
			next = CIRCLEQ_NEXT(b, link.host);
			CIRCLEQ_REMOVE_(tracee, b, host);
			b = next;
		}
	}

	bzero(bindings, sizeof(Bindings));
	return 0;
}

Binding *new_binding(Tracee *tracee, const char *host, const char *guest, bool must_exist) {
	if (!tracee->fs->bindings.pending) {
		tracee->fs->bindings.pending = talloc_zero(tracee->fs, Bindings);
		if (!tracee->fs->bindings.pending)
			return NULL;
		CIRCLEQ_INIT(tracee->fs->bindings.pending);
		talloc_set_destructor(tracee->fs->bindings.pending, remove_bindings);
	}

	Binding *b = talloc_zero(tracee->ctx, Binding);
	if (!b) return NULL;

	int st = realpath2(tracee->reconf.tracee, b->host.path, host, true);
	if (st < 0 && must_exist && getenv("PROOT_IGNORE_MISSING_BINDINGS") == NULL) {
		note(tracee, WARNING, INTERNAL, "bad binding: %s", host);
		goto fail;
	}
	b->host.length = strlen(b->host.path);

	if (!guest)
		guest = host;
	char base[PATH_MAX] = "/";
	if (guest[0] != '/') {
		if (getcwd2(tracee->reconf.tracee, base) < 0)
			goto fail;
	}
	if (join_paths(2, b->guest.path, base, guest) < 0)
		goto fail;
	b->guest.length = strlen(b->guest.path);

	insort_binding(tracee, PENDING, b);
	return b;

fail:
	TALLOC_FREE(b);
	return NULL;
}

static void initialize_binding(Tracee *tracee, Binding *b) {
	if (compare_paths(b->guest.path, "/") != PATHS_ARE_EQUAL) {
		char path[PATH_MAX];
		strcpy(path, b->guest.path);
		size_t len = strlen(path);
		int deref = !(len > 0 && path[len-1] == '!');
		if (!deref)
			path[len-1] = 0;

		strcpy(b->guest.path, "/");
		struct stat st;
		if (lstat(b->host.path, &st) == 0)
			tracee->glue_type = (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
				? S_IFREG : (st.st_mode & S_IFMT);

		if (canonicalize(tracee, path, deref, b->guest.path, 0) < 0)
			return;
		chop_finality(b->guest.path);
		tracee->glue_type = 0;
	}
	b->guest.length = strlen(b->guest.path);
	insort_binding2(tracee, b);
}

static void add_induced_bindings(Tracee *tracee, const Binding *new_binding) {
	if (!tracee->reconf.tracee)
		return;

	char path[PATH_MAX];
	strcpy(path, new_binding->host.path);
	if (detranslate_path(tracee->reconf.tracee, path, NULL) < 0)
		return;

	Binding *old;
	CIRCLEQ_FOREACH_(tracee->reconf.tracee, old, GUEST) {
		Comparison cmp = compare_paths(path, old->guest.path);
		if (cmp != PATH1_IS_PREFIX)
			continue;

		size_t pre = strlen(path);
		if (pre == 1)
			pre = 0;

		char path2[PATH_MAX];
		if (join_paths(2, path2, new_binding->guest.path, old->guest.path + pre) < 0)
			continue;

		Binding *ind = talloc_zero(tracee->ctx, Binding);
		if (!ind) continue;
		strcpy(ind->host.path, old->host.path);
		strcpy(ind->guest.path, path2);
		ind->host.length = strlen(ind->host.path);
		ind->guest.length = strlen(ind->guest.path);
		insort_binding2(tracee, ind);
	}
}

int initialize_bindings(Tracee *tracee) {
	assert(get_root(tracee) != NULL);
	assert(tracee->fs->bindings.pending != NULL);

	tracee->fs->bindings.guest = talloc_zero(tracee->fs, Bindings);
	tracee->fs->bindings.host  = talloc_zero(tracee->fs, Bindings);
	if (!tracee->fs->bindings.guest || !tracee->fs->bindings.host)
		return -1;

	CIRCLEQ_INIT(tracee->fs->bindings.guest);
	CIRCLEQ_INIT(tracee->fs->bindings.host);
	talloc_set_destructor(tracee->fs->bindings.guest, remove_bindings);
	talloc_set_destructor(tracee->fs->bindings.host,  remove_bindings);

	Binding *b, *prev;
	for (b = CIRCLEQ_LAST(tracee->fs->bindings.pending);
	     b != (void*)tracee->fs->bindings.pending;
	     b = prev) {
		prev = CIRCLEQ_PREV(b, link.pending);
		initialize_binding(tracee, b);
		add_induced_bindings(tracee, b);
	}

	// 构建最长前缀优先缓存
	build_guest_binding_cache(tracee);

	TALLOC_FREE(tracee->fs->bindings.pending);
	if (tracee->verbose > 0)
		print_bindings(tracee);
	return 0;
}
