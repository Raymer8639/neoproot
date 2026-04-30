#ifndef GLUE_H
#define GLUE_H

#include <limits.h> /* PATH_MAX, */

#include "tracee/tracee.h"
#include "path.h"

extern mode_t build_glue(Tracee *tracee, const char *guest_path, char host_path[PATH_MAX],
			Finality finality);

#endif /* GLUE_H */
