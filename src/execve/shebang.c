#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/binfmts.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <stdbool.h>
#include <string.h>

#include "execve/shebang.h"
#include "execve/execve.h"
#include "execve/aoxp.h"
#include "tracee/tracee.h"
#include "attribute.h"

static int extract_shebang(const Tracee *tracee UNUSED, const char *host_path,
                           char user_path[PATH_MAX], char argument[BINPRM_BUF_SIZE])
{
    char tmp2[2];
    char tmp;
    size_t current_length;
    size_t i;
    int status;
    int fd;

    argument[0] = '\0';

    fd = open(host_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    status = read(fd, tmp2, 2 * sizeof(char));
    if (status < 0) {
        status = -errno;
        goto end;
    }
    if ((size_t)status < 2 * sizeof(char)) {
        status = 0;
        goto end;
    }

    if (tmp2[0] != '#' || tmp2[1] != '!') {
        status = 0;
        goto end;
    }
    current_length = 2;
    user_path[0] = '\0';

    do {
        status = read(fd, &tmp, sizeof(char));
        if (status < 0) {
            status = -errno;
            goto end;
        }
        if ((size_t)status < sizeof(char)) {
            status = -ENOEXEC;
            goto end;
        }
        current_length++;
    } while ((tmp == ' ' || tmp == '\t') && current_length < BINPRM_BUF_SIZE);

    for (i = 0; current_length < BINPRM_BUF_SIZE; current_length++, i++) {
        switch (tmp) {
            case ' ':
            case '\t':
                user_path[i] = '\0';
                break;
            case '\n':
            case '\r':
                user_path[i] = '\0';
                argument[0] = '\0';
                status = 1;
                goto end;
            default:
                if (i > 1 && user_path[i - 1] == '\0')
                    goto argument;
                else
                    user_path[i] = tmp;
                break;
        }

        status = read(fd, &tmp, sizeof(char));
        if (status < 0) {
            status = -errno;
            goto end;
        }
        if ((size_t)status < sizeof(char)) {
            user_path[i] = '\0';
            argument[0] = '\0';
            status = 1;
            goto end;
        }
    }

    user_path[i] = '\0';
    argument[0] = '\0';
    status = 1;
    goto end;

argument:
    for (i = 0; current_length < BINPRM_BUF_SIZE; current_length++, i++) {
        switch (tmp) {
            case '\n':
            case '\r':
                argument[i] = '\0';
                for (i--; i > 0 && (argument[i] == ' ' || argument[i] == '\t'); i--)
                    argument[i] = '\0';
                status = 1;
                goto end;
            default:
                argument[i] = tmp;
                break;
        }

        status = read(fd, &tmp, sizeof(char));
        if (status < 0) {
            status = -errno;
            goto end;
        }
        if ((size_t)status < sizeof(char)) {
            argument[0] = '\0';
            status = 1;
            goto end;
        }
    }

    argument[i] = '\0';
    status = 1;

end:
    close(fd);
    return status;
}

int expand_shebang(Tracee *tracee, char host_path[PATH_MAX], char user_path[PATH_MAX])
{
    ArrayOfXPointers *argv = NULL;
    bool has_shebang = false;
    char argument[BINPRM_BUF_SIZE];
    int status;
    size_t i;

    for (i = 0; i < MAXSYMLINKS; i++) {
        char *old_user_path;

        status = translate_and_check_exec(tracee, host_path, user_path);
        if (status < 0)
            return status;

        old_user_path = talloc_strdup(tracee->ctx, user_path);
        if (!old_user_path)
            return -ENOMEM;

        status = extract_shebang(tracee, host_path, user_path, argument);
        if (status < 0)
            return status;
        if (status == 0)
            break;

        has_shebang = true;

        status = translate_and_check_exec(tracee, host_path, user_path);
        if (status < 0)
            return status;

        if (!argv) {
            status = fetch_array_of_xpointers(tracee, &argv, SYSARG_2, 0);
            if (status < 0)
                return status;
        }

        if (argument[0] != '\0') {
            status = resize_array_of_xpointers(argv, 0, 2);
            if (status < 0) return status;
            status = write_xpointees(argv, 0, 3, user_path, argument, old_user_path);
            if (status < 0) return status;
        } else {
            status = resize_array_of_xpointers(argv, 0, 1);
            if (status < 0) return status;
            status = write_xpointees(argv, 0, 2, user_path, old_user_path);
            if (status < 0) return status;
        }
    }

    if (i == MAXSYMLINKS)
        return -ELOOP;

    if (argv) {
        status = push_array_of_xpointers(argv, SYSARG_2);
        if (status < 0)
            return status;
    }

    return has_shebang ? 1 : 0;
}
