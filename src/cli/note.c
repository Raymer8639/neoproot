#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

#include "cli/note.h"
#include "tracee/tracee.h"

int global_verbose_level = 0;
const char *global_tool_name = NULL;

void note(const Tracee *tracee, Severity severity, Origin origin,
          const char *format, ...)
{
    int verb;
    const char *tool;

    /* Determine verbosity and tool name */
    if (tracee) {
        verb = tracee->verbose;
        tool = tracee->tool_name ? tracee->tool_name : "";
    } else {
        verb = global_verbose_level;
        tool = global_tool_name ? global_tool_name : "";
    }

    if (verb < 0 && severity != ERROR)
        return;

    /* Build message in a temporary buffer */
    char buffer[4096];
    size_t pos = 0;

    /* Add timestamp (optional, to differentiate from original) */
    /* (can be removed if timestamp is not desired) */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                    "[%ld.%03ld] ", ts.tv_sec, ts.tv_nsec / 1000000);

    /* Tool name and severity prefix */
    const char *sev_str;
    switch (severity) {
        case ERROR:   sev_str = "error"; break;
        case WARNING: sev_str = "warning"; break;
        case INFO:    sev_str = "info"; break;
        default:      sev_str = "???"; break;
    }
    pos += snprintf(buffer + pos, sizeof(buffer) - pos,
                    "%s %s: ", tool, sev_str);

    if (origin == TALLOC)
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "talloc: ");

    /* Format user message */
    va_list args;
    va_start(args, format);
    pos += vsnprintf(buffer + pos, sizeof(buffer) - pos, format, args);
    va_end(args);

    /* Add suffix based on origin */
    if (origin == SYSTEM) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, ": %s", strerror(errno));
    }
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n");

    /* Write to stderr */
    fwrite(buffer, 1, pos, stderr);
}