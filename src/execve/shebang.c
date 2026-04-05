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
    char buf[BINPRM_BUF_SIZE];
    int fd = open(host_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    ssize_t n_read = read(fd, buf, sizeof(buf));
    close(fd);

    // 修复：统一转为无符号 size_t，消除符号比较警告
    size_t len = (n_read > 0) ? (size_t)n_read : 0;
    argument[0] = '\0';

    if (len < 2)
        return 0;

    if (buf[0] != '#' || buf[1] != '!')
        return 0;

    size_t pos = 2;
    // 跳过前导空白
    while (pos < len && (buf[pos] == ' ' || buf[pos] == '\t'))
        pos++;

    // 提取解释器路径
    size_t i = 0;
    while (pos < len && i < PATH_MAX-1) {
        char c = buf[pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            break;
        user_path[i++] = c;
        pos++;
    }
    user_path[i] = '\0';

    // 行尾，无参数
    if (pos >= len || buf[pos] == '\n' || buf[pos] == '\r') {
        argument[0] = '\0';
        return 1;
    }

    // 跳过参数前空白
    while (pos < len && (buf[pos] == ' ' || buf[pos] == '\t'))
        pos++;

    // 提取参数
    i = 0;
    while (pos < len && i < BINPRM_BUF_SIZE-1) {
        char c = buf[pos];
        if (c == '\n' || c == '\r')
            break;
        argument[i++] = c;
        pos++;
    }
    argument[i] = '\0';

    // 修剪末尾空白
    while (i > 0 && (argument[i-1] == ' ' || argument[i-1] == '\t'))
        argument[--i] = '\0';

    return 1;
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
