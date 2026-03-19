#ifndef SHEBANG_H
#define SHEBANG_H

#include <linux/limits.h>  /* PATH_MAX, ARG_MAX, */

#include "tracee/tracee.h"

extern int expand_shebang(Tracee *tracee, char host_path[PATH_MAX], char user_path[PATH_MAX]);

#endif /* SHEBANG_H */
