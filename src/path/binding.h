#ifndef BINDING_H
#define BINDING_H

#include <limits.h>
#include <stdbool.h>
#include <sys/queue.h>

#include "tracee/tracee.h"
#include "path.h"

typedef struct binding {
	Path host;
	Path guest;

	bool need_substitution;
	bool must_exist;

	struct {
		CIRCLEQ_ENTRY(binding) pending;
		CIRCLEQ_ENTRY(binding) guest;
		CIRCLEQ_ENTRY(binding) host;
	} link;
} Binding;

typedef CIRCLEQ_HEAD(bindings, binding) Bindings;

Binding *insort_binding3(const Tracee *tracee, const TALLOC_CTX *context,
			 const char host_path[PATH_MAX], const char guest_path[PATH_MAX]);

Binding *new_binding(Tracee *tracee, const char *host, const char *guest, bool must_exist);

int initialize_bindings(Tracee *tracee);
const char *__attribute__((pure))
get_path_binding(const Tracee *tracee, Side side, const char path[PATH_MAX]);

Binding *__attribute__((pure))
get_binding(const Tracee *tracee, Side side, const char path[PATH_MAX]);

const char *__attribute__((pure))
get_root(const Tracee *tracee);

int substitute_binding(const Tracee *tracee, Side side, char path[PATH_MAX]);

void remove_binding_from_all_lists(const Tracee *tracee, Binding *binding);

#endif /* BINDING_H */
