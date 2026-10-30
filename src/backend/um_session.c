/*
 * Persistent UML sessions: everything around the kernel.
 *
 * A session is one booted UML kernel that runs a request loop instead of a
 * single command, plus a host-only daemon that owns the kernel and a control
 * socket.  backend/um_supervisor.c owns the kernel lifecycle; this file owns
 * the rest:
 *
 *   - the guest-side loop, generated into the session's init.sh and run as
 *     PID 1 (hostfs root) or from /um-init (ext4 root),
 *   - the control socket's line protocol and the client side,
 *   - the host-only state directory with its lock and pid validation.
 *
 * The channel between host and guest is a directory inside the session
 * directory the guest already mounts (hostfs root: /<session>/, ext4:
 * /run/neoproot/):
 *
 *     channel/queue/<id>          one request; the guest moves it out to
 *                                 claim it
 *     channel/results/<id>/       created by the guest for a claimed request
 *         request                 the claimed request
 *         stdout, stderr          the command's streams
 *         pid                     the command's pid, also its process group
 *         kill                    written by the host to stop the command
 *         status                  the exit status, published before done
 *         done                    published last; its presence means status
 *                                 is final
 *     channel/ready               written by the loop once it is polling
 *     channel/stop                written by the host to shut the guest down
 *
 * A request is line-framed and newline-free by construction: line 1 is the
 * version marker, line 2 the working directory (empty for the session's), the
 * rest are argv, one per line.  That keeps the guest loop to "read a line, add
 * it to $@" with no quoting rules to get wrong.
 */

#include "backend/um_session_loop.h"
#include "backend/um_supervisor.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define UM_SESSION_OWNER "neoproot-um-session-v1"
#define UM_SESSION_STOP_SECONDS 30.0
#define UM_SESSION_READY_SECONDS 300.0
#define UM_SESSION_CLIENT_MS 50
/* How long a queued request may sit before the guest is declared stuck. */
#define UM_SESSION_CLAIM_SECONDS 30.0

/*
 * A session name becomes a path component, so it is narrowed to what cannot
 * mean anything else: no slash, no leading dot (which would hide it from a
 * directory listing and make a stale-directory check miss it), and no leading
 * dash (which would read as an option).
 */
bool um_session_name_ok(const char *name)
{
    size_t index;
    size_t length;

    if (name == NULL || name[0] == '\0' || name[0] == '.' || name[0] == '-')
        return false;
    length = strlen(name);
    if (length >= UM_SESSION_NAME_LIMIT)
        return false;
    for (index = 0; index < length; index++) {
        char character = name[index];

        if ((character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '_' || character == '-')
            continue;
        return false;
    }
    return true;
}

/*
 * The state directory is host-only and never inside a path the guest can
 * reach by itself: it holds the control socket, the lock and the daemon's log.
 * The guest-visible channel is a separate directory inside the session
 * directory, because that one already exists for the one-shot path.
 */
int um_session_state_path(char *buffer, size_t size, const char *name)
{
    const char *tmpdir = getenv("TMPDIR");
    int written;

    if (!um_session_name_ok(name))
        return -1;
    if (tmpdir == NULL || tmpdir[0] != '/' || strlen(tmpdir) > PATH_MAX - 96)
        tmpdir = "/tmp";
    written = snprintf(buffer, size, "%s/neoproot-um-sessions/%s", tmpdir, name);
    if (written < 0 || (size_t)written >= size)
        return -1;
    return 0;
}

/* Create <tmpdir>/neoproot-um-sessions 0700, refusing anything else there. */
int um_session_state_parent(const char *state_path, char *parent, size_t size)
{
    char *slash;
    struct stat status;

    if (snprintf(parent, size, "%s", state_path) >= (int)size)
        return -1;
    slash = strrchr(parent, '/');
    if (slash == NULL)
        return -1;
    *slash = '\0';
    if (mkdir(parent, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "neoproot-um: cannot create %s: %s\n", parent,
                strerror(errno));
        return -1;
    }
    if (lstat(parent, &status) < 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != getuid() || (status.st_mode & 077) != 0) {
        fprintf(stderr,
                "neoproot-um: %s must be a 0700 directory owned by us\n",
                parent);
        return -1;
    }
    return 0;
}

/* Whether the directory was made by this program and not by something else. */
bool um_session_owned(const char *state_path)
{
    char path[PATH_MAX];
    char line[128];
    FILE *file;
    bool owned = false;

    if (snprintf(path, sizeof(path), "%s/owner", state_path) >=
        (int)sizeof(path))
        return false;
    file = fopen(path, "r");
    if (file == NULL)
        return false;
    if (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        owned = strcmp(line, UM_SESSION_OWNER) == 0;
    }
    fclose(file);
    return owned;
}

int um_session_write_owner(const char *state_path)
{
    char path[PATH_MAX];
    int fd;

    if (snprintf(path, sizeof(path), "%s/owner", state_path) >=
        (int)sizeof(path))
        return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0)
        return -1;
    if (um_write_all(fd, UM_SESSION_OWNER "\n", strlen(UM_SESSION_OWNER) + 1) <
        0) {
        close(fd);
        return -1;
    }
    return close(fd) < 0 ? -1 : 0;
}

/*
 * The lock is what makes a session directory "in use": it is held for the
 * daemon's whole life and released by the kernel when the daemon dies, so a
 * crashed daemon never leaves a lock that a later start cannot take.
 */
int um_session_lock(const char *state_path, bool wait)
{
    char path[PATH_MAX];
    int fd;
    int operation = LOCK_EX | (wait ? 0 : LOCK_NB);

    if (snprintf(path, sizeof(path), "%s/lock", state_path) >=
        (int)sizeof(path))
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    while (flock(fd, operation) < 0) {
        if (errno == EINTR)
            continue;
        close(fd);
        return -1;
    }
    return fd;
}

int um_session_pid_write(const char *state_path, pid_t pid)
{
    char path[PATH_MAX];
    char line[64];
    int fd;
    int written;

    if (snprintf(path, sizeof(path), "%s/pid", state_path) >= (int)sizeof(path))
        return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0)
        return -1;
    written = snprintf(line, sizeof(line), "%ld\n", (long)pid);
    if (um_write_all(fd, line, (size_t)written) < 0) {
        close(fd);
        return -1;
    }
    return close(fd) < 0 ? -1 : 0;
}

pid_t um_session_pid_read(const char *state_path)
{
    char path[PATH_MAX];
    char line[64];
    char *end;
    long pid;
    FILE *file;

    if (snprintf(path, sizeof(path), "%s/pid", state_path) >= (int)sizeof(path))
        return -1;
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);
    errno = 0;
    pid = strtol(line, &end, 10);
    if (errno != 0 || end == line || pid <= 0 || pid > INT_MAX)
        return -1;
    return (pid_t)pid;
}

/* A daemon is alive when its pid exists and is not a zombie. */
bool um_session_daemon_alive(pid_t pid)
{
    char path[64];
    char buffer[512];
    char *state;
    int fd;
    ssize_t length;

    if (pid <= 0)
        return false;
    if (kill(pid, 0) < 0 && errno != EPERM)
        return false;
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >=
        (int)sizeof(path))
        return false;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0)
        return false;
    buffer[length] = '\0';
    /* The state is the field after the parenthesised command name. */
    state = strrchr(buffer, ')');
    if (state == NULL || state[1] != ' ')
        return false;
    return state[2] != 'Z' && state[2] != 'X';
}

/* Remove what this program created, and nothing else. */
void um_session_remove_state(const char *state_path)
{
    static const char *const names[] = {
        "ctl.sock", "pid", "lock", "owner", "log", "meta", "ready", "stop",
        NULL
    };
    char path[PATH_MAX];
    size_t index;

    if (!um_session_owned(state_path))
        return;
    for (index = 0; names[index] != NULL; index++) {
        if (snprintf(path, sizeof(path), "%s/%s", state_path, names[index]) <
            (int)sizeof(path))
            (void)unlink(path);
    }
    (void)rmdir(state_path);
}

/* --- the guest loop ---------------------------------------------------- */

/*
 * Append the guest's command loop to the wrapper being generated.
 *
 * The loop is a shell script (backend/um_session_loop.sh) embedded at build
 * time: it runs inside the guest, so it is written as shell and tested as
 * shell, not as a C string literal that has to escape every quote.
 */
int um_session_write_loop(int fd)
{
    return um_write_all(fd, um_session_loop_text,
                        strlen(um_session_loop_text));
}

/* --- wire protocol ----------------------------------------------------- */

int um_session_send_bytes(int fd, const void *data, size_t length)
{
    const char *cursor = data;

    while (length > 0) {
        ssize_t sent = send(fd, cursor, length, MSG_NOSIGNAL);

        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        cursor += sent;
        length -= (size_t)sent;
    }
    return 0;
}

int um_session_send_line(int fd, const char *line)
{
    char *framed = NULL;
    int printed;
    int result;

    printed = asprintf(&framed, "%s\n", line);
    if (printed < 0 || framed == NULL)
        return -1;
    result = um_session_send_bytes(fd, framed, (size_t)printed);
    free(framed);
    return result;
}

int um_session_send_frame(int fd, const char *kind, const void *data,
                          size_t length)
{
    char header[64];
    int written;

    written = snprintf(header, sizeof(header), "%s %zu\n", kind, length);
    if (written < 0 || (size_t)written >= sizeof(header))
        return -1;
    if (um_session_send_bytes(fd, header, (size_t)written) < 0)
        return -1;
    if (length == 0)
        return 0;
    return um_session_send_bytes(fd, data, length);
}

/*
 * Read exactly count bytes: first whatever the line reader already buffered,
 * then from the socket.  A payload that arrived in the same read() as its
 * header is therefore not lost.
 */
int um_session_read_exact(int fd, UmLineReader *reader, void *data, size_t count)
{
    char *cursor = data;

    if (reader->used > 0) {
        size_t take = reader->used < count ? reader->used : count;

        memcpy(cursor, reader->buffer, take);
        memmove(reader->buffer, reader->buffer + take, reader->used - take);
        reader->used -= take;
        cursor += take;
        count -= take;
    }
    while (count > 0) {
        ssize_t got = recv(fd, cursor, count, 0);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        cursor += got;
        count -= (size_t)got;
    }
    return 0;
}

/*
 * Read one newline-terminated line from a non-blocking socket.  Returns 1 for
 * a line, 0 for "not yet", -1 for EOF or an error.  Whatever follows the
 * newline stays in the reader for the next call.
 */
int um_session_read_line(int fd, UmLineReader *reader, char *buffer, size_t size)
{
    for (;;) {
        char *newline;
        ssize_t got;

        newline = memchr(reader->buffer, '\n', reader->used);
        if (newline != NULL) {
            size_t length = (size_t)(newline - reader->buffer);
            size_t remainder = reader->used - length - 1;

            if (length + 1 > size)
                return -1;
            memcpy(buffer, reader->buffer, length);
            buffer[length] = '\0';
            memmove(reader->buffer, newline + 1, remainder);
            reader->used = remainder;
            return 1;
        }
        if (reader->used >= sizeof(reader->buffer))
            return -1;
        got = read(fd, reader->buffer + reader->used,
                   sizeof(reader->buffer) - reader->used);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
        }
        if (got == 0)
            return -1;
        reader->used += (size_t)got;
    }
}

/* --- client ----------------------------------------------------------- */

static volatile sig_atomic_t um_client_signal;

static void um_client_signal_handler(int signal_number)
{
    um_client_signal = signal_number;
}

static int um_client_connect(const char *state_path, char *error, size_t size)
{
    struct sockaddr_un address;
    int fd;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s/ctl.sock",
                 state_path) >= (int)sizeof(address.sun_path)) {
        snprintf(error, size, "session path is too long");
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(error, size, "socket: %s", strerror(errno));
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        snprintf(error, size, "no running session '%s'", state_path);
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * EXEC <payload length> <timeout ms>\n<payload>
 *
 * The payload is line-framed so the guest can read it line by line:
 *
 *     <cwd>\n<argc>\n(<length>\n<bytes>)*
 */
static int um_client_send_request(int fd, const char *cwd, int argc,
                                  char *const argv[], double timeout)
{
    char *payload = NULL;
    char *header = NULL;
    size_t length = 0;
    size_t capacity = 0;
    long timeout_ms;
    int index;
    int result = -1;

    if (timeout <= 0.0 || timeout > 86400.0 * 365.0)
        timeout_ms = 0;
    else
        timeout_ms = (long)(timeout * 1000.0);

    capacity = 256;
    payload = malloc(capacity);
    if (payload == NULL)
        return -1;
    /*
     * Line 1 of the payload is the working directory (always present, empty
     * for the session's own), then one "<length>\n<bytes>\n" record per
     * argument.  There is no argument count: the guest counts what it reads,
     * and a count that could disagree with the records would only be a new
     * way to get it wrong.
     */
    for (index = -1; index < argc; index++) {
        const char *text = index < 0 ? (cwd != NULL ? cwd : "") : argv[index];
        size_t text_length = strlen(text);
        char prefix[32];
        size_t needed;

        prefix[0] = '\0';
        if (index >= 0)
            snprintf(prefix, sizeof(prefix), "%zu\n", text_length);
        needed = length + strlen(prefix) + text_length + 2;
        if (needed > capacity) {
            char *grown = realloc(payload, needed + 256);

            if (grown == NULL)
                goto done;
            payload = grown;
            capacity = needed + 256;
        }
        if (index < 0) {
            memcpy(payload + length, text, text_length);
            length += text_length;
            payload[length++] = '\n';
            continue;
        }
        memcpy(payload + length, prefix, strlen(prefix));
        length += strlen(prefix);
        memcpy(payload + length, text, text_length);
        length += text_length;
        payload[length++] = '\n';
    }
    if (asprintf(&header, "EXEC %zu %ld\n", length, timeout_ms) < 0)
        goto done;
    if (um_write_all(fd, header, strlen(header)) < 0 ||
        um_write_all(fd, payload, length) < 0)
        goto done;
    result = 0;

done:
    free(header);
    free(payload);
    return result;
}

static int um_client_write_all(int fd, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t written = write(fd, data, length);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        data += written;
        length -= (size_t)written;
    }
    return 0;
}

/*
 * Read exactly count bytes of a frame's payload.
 *
 * A frame is a header line followed by its bytes, and both may arrive in the
 * same read() -- so the payload has to come out of the same buffer the header
 * came from, not straight off the socket.  Reading the socket here would drop
 * whatever the line reader had already buffered, which is a whole stdout
 * chunk when the daemon writes them back to back.
 */
static int um_client_read_payload(int fd, char *buffer, size_t *used,
                                  char *destination, size_t count)
{
    while (count > 0) {
        size_t take;
        ssize_t got;

        if (*used > 0) {
            take = *used < count ? *used : count;
            memcpy(destination, buffer, take);
            memmove(buffer, buffer + take, *used - take);
            *used -= take;
            destination += take;
            count -= take;
            continue;
        }
        got = read(fd, destination, count);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got == 0)
            return -1;
        destination += got;
        count -= (size_t)got;
    }
    return 0;
}

/* Stream frames until EXIT.  Returns the status the client should exit with. */
static int um_client_receive_result(int fd)
{
    char line[256];
    char buffer[1024];
    size_t used = 0;

    for (;;) {
        struct pollfd descriptor = { .fd = fd, .events = POLLIN, .revents = 0 };
        int ready;
        ssize_t got;

        if (um_client_signal != 0) {
            char request[32];

            snprintf(request, sizeof(request), "SIGNAL %d",
                     (int)um_client_signal);
            um_client_signal = 0;
            (void)um_session_send_line(fd, request);
        }
        ready = poll(&descriptor, 1, UM_SESSION_CLIENT_MS);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return 125;
        }
        if (ready == 0)
            continue;
        got = read(fd, buffer + used, sizeof(buffer) - used);
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return 125;
        }
        if (got == 0) {
            fprintf(stderr,
                    "neoproot-um: the session daemon closed the connection\n");
            return 125;
        }
        used += (size_t)got;
        for (;;) {
            char *newline = memchr(buffer, '\n', used);
            size_t length;

            if (newline == NULL)
                break;
            length = (size_t)(newline - buffer);
            if (length >= sizeof(line))
                return 125;
            memcpy(line, buffer, length);
            line[length] = '\0';
            memmove(buffer, newline + 1, used - length - 1);
            used -= length + 1;

            if (strncmp(line, "OUT ", 4) == 0 || strncmp(line, "ERR ", 4) == 0) {
                char payload[4096];
                long count = strtol(line + 4, NULL, 10);
                int target = line[0] == 'O' ? STDOUT_FILENO : STDERR_FILENO;

                while (count > 0) {
                    size_t chunk = (size_t)count < sizeof(payload)
                                       ? (size_t)count
                                       : sizeof(payload);

                    if (um_client_read_payload(fd, buffer, &used, payload,
                                               chunk) < 0)
                        return 125;
                    if (um_client_write_all(target, payload, chunk) < 0)
                        return 125;
                    count -= (long)chunk;
                }
                continue;
            }
            if (strncmp(line, "EXIT ", 5) == 0) {
                long status = strtol(line + 5, NULL, 10);

                if (status < 0 || status > 255)
                    return 125;
                return (int)status;
            }
            if (strncmp(line, "BAD", 3) == 0 || strncmp(line, "BUSY", 4) == 0) {
                fprintf(stderr, "neoproot-um: %s\n", line);
                return 125;
            }
            /* Unknown frames are ignored rather than fatal: a newer daemon
             * may send more than this client understands. */
        }
    }
}

static void um_client_install_handlers(struct sigaction old[4], bool install)
{
    static const int signals[4] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT };
    struct sigaction action;
    int index;

    memset(&action, 0, sizeof(action));
    action.sa_handler = um_client_signal_handler;
    sigemptyset(&action.sa_mask);
    for (index = 0; index < 4; index++) {
        if (install)
            (void)sigaction(signals[index], &action, &old[index]);
        else
            (void)sigaction(signals[index], &old[index], NULL);
    }
}

static int um_session_command_run(int argc, char *const argv[],
                                  const char *state_path)
{
    struct sigaction old[4];
    const char *cwd = NULL;
    double timeout = 0.0;
    char error[256];
    int fd;
    int index = 0;
    int result;

    while (index < argc) {
        const char *argument = argv[index];

        if (strcmp(argument, "--") == 0) {
            index++;
            break;
        }
        if (strncmp(argument, "--cwd=", 6) == 0) {
            cwd = argument + 6;
            index++;
            continue;
        }
        if (strncmp(argument, "--timeout=", 10) == 0) {
            char *end;
            double parsed;

            errno = 0;
            parsed = strtod(argument + 10, &end);
            if (errno != 0 || end == argument + 10 || *end != '\0' ||
                parsed < 0.0 || parsed > 86400.0 * 365.0) {
                fprintf(stderr,
                        "neoproot-um: --timeout expects seconds (0 disables)\n");
                return 125;
            }
            timeout = parsed;
            index++;
            continue;
        }
        break;
    }
    if (index >= argc) {
        fprintf(stderr, "neoproot-um: session run needs a command\n");
        return 125;
    }
    fd = um_client_connect(state_path, error, sizeof(error));
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: %s\n", error);
        return 125;
    }
    um_client_signal = 0;
    um_client_install_handlers(old, true);
    if (um_client_send_request(fd, cwd, argc - index, &argv[index], timeout) <
        0) {
        fprintf(stderr, "neoproot-um: cannot send the request: %s\n",
                strerror(errno));
        um_client_install_handlers(old, false);
        close(fd);
        return 125;
    }
    result = um_client_receive_result(fd);
    um_client_install_handlers(old, false);
    close(fd);
    return result;
}

static int um_session_command_stop(int argc, char *const argv[],
                                   const char *state_path)
{
    UmLineReader reader;
    struct pollfd descriptor;
    char line[256];
    char error[256];
    pid_t pid;
    int fd;
    double deadline;

    (void)argc;
    (void)argv;
    pid = um_session_pid_read(state_path);
    fd = um_client_connect(state_path, error, sizeof(error));
    if (fd < 0) {
        fprintf(stderr, "neoproot-um: %s\n", error);
        return 1;
    }
    memset(&reader, 0, sizeof(reader));
    if (um_session_send_line(fd, "STOP") < 0) {
        close(fd);
        return 1;
    }
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    if (poll(&descriptor, 1, 2000) > 0)
        (void)um_session_read_line(fd, &reader, line, sizeof(line));
    close(fd);
    deadline = um_now() + UM_SESSION_STOP_SECONDS;
    while (um_now() < deadline) {
        if (!um_session_daemon_alive(pid))
            return 0;
        usleep(20000);
    }
    fprintf(stderr, "neoproot-um: the session daemon did not exit\n");
    return 1;
}

static int um_session_command_status(int argc, char *const argv[],
                                     const char *state_path)
{
    UmLineReader reader;
    struct pollfd descriptor;
    char line[256];
    char error[256];
    pid_t pid;
    int fd;
    int ready = -1;

    (void)argc;
    (void)argv;
    pid = um_session_pid_read(state_path);
    if (pid <= 0 || !um_session_daemon_alive(pid)) {
        printf("session %s: not running\n", state_path);
        return 1;
    }
    fd = um_client_connect(state_path, error, sizeof(error));
    if (fd < 0) {
        printf("session %s: pid %ld alive but not answering\n", state_path,
               (long)pid);
        return 1;
    }
    memset(&reader, 0, sizeof(reader));
    if (um_session_send_line(fd, "STATUS") < 0) {
        close(fd);
        return 1;
    }
    descriptor.fd = fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    if (poll(&descriptor, 1, 5000) > 0)
        ready = um_session_read_line(fd, &reader, line, sizeof(line));
    if (ready == 1)
        printf("session %s: pid %ld %s\n", state_path, (long)pid, line);
    else
        printf("session %s: pid %ld did not answer\n", state_path, (long)pid);
    close(fd);
    return ready == 1 ? 0 : 1;
}

/* --- state directory setup ---------------------------------------------- */

int um_session_prepare_state(const char *state_path, bool fresh)
{
    char parent[PATH_MAX];
    struct stat status;

    if (um_session_state_parent(state_path, parent, sizeof(parent)) < 0)
        return -1;
    if (lstat(state_path, &status) == 0) {
        if (!S_ISDIR(status.st_mode) || !um_session_owned(state_path)) {
            fprintf(stderr,
                    "neoproot-um: %s exists and is not a neoproot session\n",
                    state_path);
            return -1;
        }
        if (fresh) {
            /* A stale directory is a daemon that died; the lock says which.
             * It is taken and released here, so a live one is never touched. */
            int lock = um_session_lock(state_path, false);

            if (lock < 0) {
                fprintf(stderr, "neoproot-um: session %s is in use\n",
                        state_path);
                return -1;
            }
            close(lock);
        }
        return 0;
    }
    if (mkdir(state_path, 0700) < 0) {
        fprintf(stderr, "neoproot-um: cannot create %s: %s\n", state_path,
                strerror(errno));
        return -1;
    }
    if (um_session_write_owner(state_path) < 0) {
        (void)rmdir(state_path);
        return -1;
    }
    return 0;
}

static int um_session_command_start(int argc, char *const argv[],
                                    const char *state_path, const char *name)
{
    char ready_path[PATH_MAX];
    char log_path[PATH_MAX];
    char **child_argv;
    pid_t pid;
    double deadline;
    int log_fd;
    int status;
    int index;

    child_argv = calloc((size_t)argc + 1, sizeof(*child_argv));
    if (child_argv == NULL)
        return 1;
    /* Forward the whole vector, -- included: the daemon uses everything
     * before the delimiter as the supervisor's options and drops the rest. */
    for (index = 0; index < argc; index++)
        child_argv[index] = argv[index];
    child_argv[argc] = NULL;

    if (snprintf(log_path, sizeof(log_path), "%s/log", state_path) >=
            (int)sizeof(log_path) ||
        snprintf(ready_path, sizeof(ready_path), "%s/ready", state_path) >=
            (int)sizeof(ready_path)) {
        free(child_argv);
        return 1;
    }
    (void)unlink(ready_path);

    /*
     * The directory is made here, before the fork, so the pid file has
     * somewhere to go and the child finds a directory that already declares
     * itself as ours.  A session that is already live is refused here rather
     * than by the child, so the message reaches the caller.
     */
    if (um_session_prepare_state(state_path, true) < 0) {
        free(child_argv);
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "neoproot-um: fork: %s\n", strerror(errno));
        free(child_argv);
        return 1;
    }
    if (pid == 0) {
        int devnull;

        if (setsid() < 0)
            _exit(1);
        devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDIN_FILENO);
            if (devnull > STDIN_FILENO)
                close(devnull);
        }
        log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                      0600);
        if (log_fd >= 0) {
            (void)dup2(log_fd, STDOUT_FILENO);
            (void)dup2(log_fd, STDERR_FILENO);
            if (log_fd > STDERR_FILENO)
                close(log_fd);
        }
        _exit(neoproot_um_session_daemon_main(name, argc, child_argv));
    }
    free(child_argv);

    if (um_session_pid_write(state_path, pid) < 0) {
        fprintf(stderr, "neoproot-um: cannot record the session pid\n");
        return 1;
    }
    deadline = um_now() + UM_SESSION_READY_SECONDS;
    for (;;) {
        pid_t reaped = waitpid(pid, &status, WNOHANG);

        if (reaped == pid) {
            int code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

            fprintf(stderr,
                    "neoproot-um: the session daemon exited during startup "
                    "(status %d); see %s\n",
                    code, log_path);
            return code == 0 ? 1 : code;
        }
        if (access(ready_path, F_OK) == 0) {
            printf("session %s: started (pid %ld)\n", name, (long)pid);
            return 0;
        }
        if (um_now() >= deadline) {
            /*
             * Leave the session up long enough to be looked at, and say what
             * is there: the daemon's log is the only record of why the guest
             * never reached its loop, and deleting it as part of giving up
             * makes the failure unexplainable.
             */
            fprintf(stderr,
                    "neoproot-um: the guest did not become ready within %.0f s\n",
                    UM_SESSION_READY_SECONDS);
            fprintf(stderr, "neoproot-um: daemon log: %s\n", log_path);
            fprintf(stderr,
                    "neoproot-um: stop it with 'session --session-name=%s stop'"
                    " (the state directory is kept)\n",
                    name);
            return 1;
        }
        usleep(20000);
    }
}

static void um_session_client_usage(void)
{
    puts("Usage: neoproot-um session <command> [options]");
    puts("Commands:");
    puts("  start  --rootfs=PATH [options]   boot a session and its daemon");
    puts("  run    [--cwd=PATH] [--timeout=S] -- command [args...]");
    puts("  stop                             shut the session down");
    puts("  status                           show whether it is running");
    puts("Option: --session-name=NAME (or NEOPROOT_UM_SESSION), default 'default'");
}

int neoproot_um_session_client_main(int argc, char *const argv[])
{
    const char *name = getenv("NEOPROOT_UM_SESSION");
    char state_path[PATH_MAX];
    int base = 0;

    if (name == NULL || name[0] == '\0')
        name = "default";
    /* --session-name may precede the subcommand; it never consumes one. */
    if (argc > 0 && strncmp(argv[0], "--session-name=", 15) == 0) {
        name = argv[0] + 15;
        base = 1;
    }
    if (!um_session_name_ok(name)) {
        fprintf(stderr, "neoproot-um: invalid session name\n");
        return 125;
    }
    if (um_session_state_path(state_path, sizeof(state_path), name) < 0) {
        fprintf(stderr, "neoproot-um: cannot compute the session path\n");
        return 125;
    }
    if (base >= argc) {
        um_session_client_usage();
        return 1;
    }
    /*
     * The guest loop is plain POSIX sh, so it can be exercised without a
     * kernel at all: printing it lets a test run the real script against a
     * hand-made channel and check the queue/results contract (claim by move,
     * status before done, kill) on any machine.
     */
    if (strcmp(argv[base], "--print-loop") == 0)
        return um_session_write_loop(STDOUT_FILENO) < 0 ? 1 : 0;
    if (strcmp(argv[base], "run") == 0)
        return um_session_command_run(argc - base - 1, argv + base + 1,
                                      state_path);
    if (strcmp(argv[base], "stop") == 0)
        return um_session_command_stop(argc - base - 1, argv + base + 1,
                                       state_path);
    if (strcmp(argv[base], "status") == 0)
        return um_session_command_status(argc - base - 1, argv + base + 1,
                                         state_path);
    if (strcmp(argv[base], "start") == 0)
        return um_session_command_start(argc - base - 1, argv + base + 1,
                                        state_path, name);
    um_session_client_usage();
    return 1;
}

/* --- daemon ------------------------------------------------------------ */

/*
 * The daemon is the session.  It owns the state directory and its lock, it
 * runs the supervisor as a child (the supervisor owns the kernel, unchanged),
 * and it serves the control socket while the guest is up.
 *
 * Requests are serialised.  A client that arrives while a command runs is told
 * BUSY and exits 125 rather than being queued: a queued command whose client
 * died would be a command nobody is waiting for, and the session exists to
 * amortise one boot over many commands, not to be a job server.
 *
 * Nothing here may block on a client read while a job runs: the same loop has
 * to notice STOP, a kill the guest is slow to honour, and the kernel exiting.
 */

typedef enum {
    UM_JOB_IDLE,
    UM_JOB_RUNNING
} UmJobState;

typedef struct {
    const char *name;
    const char *state_path;
    char session_host[PATH_MAX];  /* host path of the session directory */
    char channel_host[PATH_MAX];  /* host path of channel/ */
    char channel_guest[PATH_MAX]; /* channel/ as the guest sees it */
    bool ready;
    pid_t supervisor_pid;

    UmJobState state;
    int id;
    int client;
    int watchdog_ticks;
    bool claimed;
    double queued_at;
    UmLineReader reader;
    double deadline;
    bool timed_out;
    bool kill_sent;
    bool signalled;
    int signal_number;

    int stdout_fd;
    int stderr_fd;
    off_t stdout_offset;
    off_t stderr_offset;

    char directory[PATH_MAX];
    char queue_path[PATH_MAX];
} UmDaemon;

static void um_daemon_publish(const char *directory, const char *name,
                              const char *value)
{
    char temporary[PATH_MAX];
    char final[PATH_MAX];
    int fd;

    if (snprintf(temporary, sizeof(temporary), "%s/.%s", directory, name) >=
            (int)sizeof(temporary) ||
        snprintf(final, sizeof(final), "%s/%s", directory, name) >=
            (int)sizeof(final))
        return;
    fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (um_write_all(fd, value, strlen(value)) < 0 ||
        um_write_all(fd, "\n", 1) < 0 || close(fd) < 0) {
        (void)unlink(temporary);
        return;
    }
    (void)rename(temporary, final);
}

/*
 * Wake the guest loop.
 *
 * The loop blocks on a FIFO in the channel instead of polling it, so anything
 * that changes what the loop should look at has to leave a byte there.  The
 * FIFO is opened non-blocking for writing: with no reader (a guest that has
 * not reached the loop yet, or one whose channel cannot hold a FIFO) the open
 * fails with ENXIO and there is simply nothing to wake -- the loop will see
 * the work when it starts or on its next poll.
 */
static void um_daemon_wake(const char *channel_host)
{
    char path[PATH_MAX];
    int fd;

    if (channel_host == NULL || channel_host[0] == '\0')
        return;
    if (snprintf(path, sizeof(path), "%s/wake", channel_host) >=
        (int)sizeof(path))
        return;
    fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return;
    /* A newline, not a bare byte: the loop reads the FIFO with a plain line
     * read (portable sh has no reliable "-n 1"), and a line read returns when
     * it sees the terminator. */
    (void)write(fd, "w\n", 2);
    close(fd);
}

/* A small file the guest wrote; -1 when it is not there (yet). */
static int um_daemon_read_value(const char *path, char *buffer, size_t size)
{
    ssize_t length;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    length = read(fd, buffer, size - 1);
    close(fd);
    if (length <= 0)
        return -1;
    buffer[length] = '\0';
    buffer[strcspn(buffer, "\r\n")] = '\0';
    return 0;
}

/*
 * Forward what the command wrote since the last call.  The guest appends to
 * these files while it runs, so they are read from a remembered offset: a
 * stream of output is a stream, not a file to be re-read.
 */
static void um_daemon_stream(UmDaemon *daemon, const char *kind, int fd,
                             off_t *offset)
{
    char buffer[8192];

    for (;;) {
        ssize_t length = pread(fd, buffer, sizeof(buffer), *offset);

        if (length <= 0)
            return;
        *offset += length;
        if (um_session_send_frame(daemon->client, kind, buffer,
                                  (size_t)length) < 0)
            return;
    }
}

static void um_daemon_close_streams(UmDaemon *daemon)
{
    if (daemon->stdout_fd >= 0)
        close(daemon->stdout_fd);
    if (daemon->stderr_fd >= 0)
        close(daemon->stderr_fd);
    daemon->stdout_fd = -1;
    daemon->stderr_fd = -1;
}

static void um_daemon_end_job(UmDaemon *daemon, int status)
{
    um_daemon_close_streams(daemon);
    if (daemon->client >= 0) {
        char line[64];

        if (daemon->timed_out)
            snprintf(line, sizeof(line), "EXIT 124");
        else if (daemon->signalled && daemon->signal_number > 0)
            snprintf(line, sizeof(line), "EXIT %d", 128 + daemon->signal_number);
        else if (status < 0 || status > 255)
            snprintf(line, sizeof(line), "EXIT 125");
        else
            snprintf(line, sizeof(line), "EXIT %d", status);
        (void)um_session_send_line(daemon->client, line);
        close(daemon->client);
        daemon->client = -1;
    }
    /*
     * Remove the job's directory completely.  Every file in it has to go --
     * especially done, whose mere presence is what the next job would read as
     * "this command already finished".  The id is not reused either: a stale
     * done in a directory the guest reuses would report the previous command's
     * status, which is exactly the failure this cleanup is here to prevent.
     */
    if (daemon->directory[0] != '\0') {
        static const char *const names[] = {
            "request", "pid", "kill", "status", "done", "stdout", "stderr",
            ".status", ".done", ".pid", NULL
        };
        char path[PATH_MAX];
        size_t index;

        for (index = 0; names[index] != NULL; index++) {
            if (snprintf(path, sizeof(path), "%s/%s", daemon->directory,
                         names[index]) < (int)sizeof(path))
                (void)unlink(path);
        }
        (void)rmdir(daemon->directory);
    }
    daemon->timed_out = false;
    daemon->kill_sent = false;
    daemon->signalled = false;
    daemon->signal_number = 0;
    daemon->deadline = 0.0;
    daemon->directory[0] = '\0';
    daemon->queue_path[0] = '\0';
    daemon->state = UM_JOB_IDLE;
}

/*
 * Write one request into queue/ under a temporary name and rename it: the
 * guest claims a request by moving it out, so a half-written file must never
 * be claimable.
 */
static int um_daemon_queue(UmDaemon *daemon, const char *payload,
                           size_t length)
{
    char temporary[PATH_MAX];
    int fd;

    if (daemon->channel_host[0] == '\0')
        return -1;
    if (snprintf(temporary, sizeof(temporary), "%s/queue/.%d",
                 daemon->channel_host, daemon->id) >=
            (int)sizeof(temporary) ||
        snprintf(daemon->queue_path, sizeof(daemon->queue_path), "%s/queue/%d",
                 daemon->channel_host, daemon->id) >=
            (int)sizeof(daemon->queue_path) ||
        snprintf(daemon->directory, sizeof(daemon->directory),
                 "%s/results/%d", daemon->channel_host, daemon->id) >=
            (int)sizeof(daemon->directory))
        return -1;
    fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (um_write_all(fd, UM_SESSION_REQUEST_MARKER "\n",
                     strlen(UM_SESSION_REQUEST_MARKER) + 1) < 0 ||
        um_write_all(fd, payload, length) < 0 || close(fd) < 0) {
        (void)unlink(temporary);
        return -1;
    }
    if (rename(temporary, daemon->queue_path) < 0) {
        (void)unlink(temporary);
        return -1;
    }
    return 0;
}

/* "EXEC <payload length> <timeout ms>": the header of a command request. */
static int um_daemon_parse_exec(const char *line, size_t *length,
                                long *timeout)
{
    char *end = NULL;
    unsigned long parsed_length;
    long parsed_timeout;

    if (strncmp(line, "EXEC ", 5) != 0)
        return -1;
    errno = 0;
    parsed_length = strtoul(line + 5, &end, 10);
    if (errno != 0 || end == line + 5 || *end != ' ' || parsed_length == 0 ||
        parsed_length > 1024 * 1024)
        return -1;
    errno = 0;
    parsed_timeout = strtol(end + 1, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || parsed_timeout < 0 ||
        parsed_timeout > 86400L * 365L * 1000L)
        return -1;
    *length = (size_t)parsed_length;
    *timeout = parsed_timeout;
    return 0;
}

/* Is the command done?  done is published after status, so it is the gate. */
static bool um_daemon_job_done(UmDaemon *daemon, int *status)
{
    char path[PATH_MAX];
    char value[32];

    if (snprintf(path, sizeof(path), "%s/done", daemon->directory) >=
            (int)sizeof(path) ||
        access(path, F_OK) != 0)
        return false;
    *status = 125;
    if (snprintf(path, sizeof(path), "%s/status", daemon->directory) >=
        (int)sizeof(path))
        return true;
    if (um_daemon_read_value(path, value, sizeof(value)) == 0) {
        char *end = NULL;
        long parsed;

        errno = 0;
        parsed = strtol(value, &end, 10);
        if (errno == 0 && end != value && *end == '\0' && parsed >= 0 &&
            parsed <= 255)
            *status = (int)parsed;
    }
    return true;
}

/* Advance a running job.  Returns -1 when the session must end. */
static int um_daemon_poll_job(UmDaemon *daemon)
{
    int status = 125;

    if (daemon->state != UM_JOB_RUNNING)
        return 0;
    if (daemon->stdout_fd < 0) {
        char path[PATH_MAX];

        if (snprintf(path, sizeof(path), "%s/stdout", daemon->directory) <
            (int)sizeof(path))
            daemon->stdout_fd = open(path, O_RDONLY | O_CLOEXEC);
        if (snprintf(path, sizeof(path), "%s/stderr", daemon->directory) <
            (int)sizeof(path))
            daemon->stderr_fd = open(path, O_RDONLY | O_CLOEXEC);
    }
    if (daemon->stdout_fd >= 0)
        um_daemon_stream(daemon, "OUT", daemon->stdout_fd,
                         &daemon->stdout_offset);
    if (daemon->stderr_fd >= 0)
        um_daemon_stream(daemon, "ERR", daemon->stderr_fd,
                         &daemon->stderr_offset);

    if (!daemon->claimed && access(daemon->directory, F_OK) == 0) {
        daemon->claimed = true;
        if (getenv("NEOPROOT_UM_SESSION_TRACE") != NULL)
            fprintf(stderr, "trace: claimed %d after %.0f ms\n", daemon->id,
                    (um_now() - daemon->queued_at) * 1000.0);
    }
    if (um_daemon_job_done(daemon, &status)) {
        if (getenv("NEOPROOT_UM_SESSION_TRACE") != NULL)
            fprintf(stderr, "trace: done %d after %.0f ms\n", daemon->id,
                    (um_now() - daemon->queued_at) * 1000.0);
        /* Whatever was written after done is still part of the output. */
        if (daemon->stdout_fd >= 0)
            um_daemon_stream(daemon, "OUT", daemon->stdout_fd,
                             &daemon->stdout_offset);
        if (daemon->stderr_fd >= 0)
            um_daemon_stream(daemon, "ERR", daemon->stderr_fd,
                             &daemon->stderr_offset);
        um_daemon_end_job(daemon, status);
        return 0;
    }
    if (!daemon->kill_sent && daemon->deadline > 0.0 &&
        um_now() >= daemon->deadline) {
        daemon->timed_out = true;
        daemon->kill_sent = true;
        um_daemon_publish(daemon->directory, "kill", "timeout");
        um_daemon_wake(daemon->channel_host);
    }
    /*
     * A request the guest never claimed is a guest that is not looping: no
     * amount of waiting turns that into output, and the caller is blocked on
     * a socket that will never see EXIT.
     */
    if (!daemon->claimed &&
        um_now() > daemon->queued_at + UM_SESSION_CLAIM_SECONDS) {
        fprintf(stderr,
                "neoproot-um: the guest did not claim request %d\n",
                daemon->id);
        um_daemon_end_job(daemon, 125);
        return 0;
    }
    if (daemon->kill_sent && daemon->deadline > 0.0 &&
        um_now() > daemon->deadline + 15.0) {
        /* The guest was told to stop and has not.  Nothing good comes of
         * waiting for a guest that ignores its own protocol. */
        um_daemon_end_job(daemon, 125);
        return 0;
    }
    if (kill(daemon->supervisor_pid, 0) < 0) {
        um_daemon_end_job(daemon, 125);
        return -1;
    }
    return 0;
}

/* Parse one line from the client that owns the running job. */
static void um_daemon_job_input(UmDaemon *daemon, const char *line)
{
    if (strncmp(line, "SIGNAL ", 7) == 0) {
        long number = strtol(line + 7, NULL, 10);

        if (number > 0 && number < 128 && !daemon->kill_sent) {
            daemon->signal_number = (int)number;
            daemon->signalled = true;
            daemon->kill_sent = true;
            um_daemon_publish(daemon->directory, "kill", "signal");
        }
        return;
    }
    if (strcmp(line, "PING") == 0) {
        (void)um_session_send_line(daemon->client, "PONG");
        return;
    }
}

/* Start a command for a client that has already sent its request. */
static int um_daemon_start_job(UmDaemon *daemon, int client, char *payload,
                               size_t length, long timeout_ms)
{
    daemon->client = client;
    daemon->id++;
    daemon->timed_out = false;
    daemon->kill_sent = false;
    daemon->signalled = false;
    daemon->signal_number = 0;
    daemon->stdout_fd = -1;
    daemon->stderr_fd = -1;
    daemon->stdout_offset = 0;
    daemon->stderr_offset = 0;
    daemon->deadline = timeout_ms > 0
                           ? um_now() + (double)timeout_ms / 1000.0
                           : 0.0;
    daemon->claimed = false;
    daemon->queued_at = um_now();
    if (um_daemon_queue(daemon, payload, length) < 0) {
        (void)um_session_send_line(client, "BAD cannot queue the request");
        close(client);
        daemon->client = -1;
        daemon->id = 0;
        return 0;
    }
    daemon->state = UM_JOB_RUNNING;
    um_daemon_wake(daemon->channel_host);
    if (getenv("NEOPROOT_UM_SESSION_TRACE") != NULL)
        fprintf(stderr, "trace: queued %d at %.3f\n", daemon->id,
                daemon->queued_at);
    return 0;
}

/*
 * Read one line from a fresh client, waiting at most ms milliseconds for it.
 * The client is our own binary and writes its header at once, so this is a
 * bound, not a protocol.
 */
static int um_daemon_accept_line(int client, UmLineReader *reader, char *line,
                                 size_t size, int ms)
{
    double deadline = um_now() + (double)ms / 1000.0;

    for (;;) {
        struct pollfd descriptor = { .fd = client, .events = POLLIN,
                                     .revents = 0 };
        int result = um_session_read_line(client, reader, line, size);

        if (result != 0)
            return result;
        if (um_now() >= deadline)
            return -1;
        if (poll(&descriptor, 1, 20) < 0 && errno != EINTR)
            return -1;
    }
}

/* Read a payload announced by an EXEC header. */
static char *um_daemon_accept_payload(int client, UmLineReader *reader,
                                      size_t length)
{
    char *payload = malloc(length + 1);
    size_t received;

    if (payload == NULL)
        return NULL;
    received = 0;
    while (received < length) {
        struct pollfd descriptor = { .fd = client, .events = POLLIN,
                                     .revents = 0 };
        ssize_t got;

        /* Whatever arrived with the header is part of the payload. */
        if (reader->used > 0) {
            size_t take = reader->used < length - received
                              ? reader->used
                              : length - received;

            memcpy(payload + received, reader->buffer, take);
            memmove(reader->buffer, reader->buffer + take,
                    reader->used - take);
            reader->used -= take;
            received += take;
            continue;
        }
        if (poll(&descriptor, 1, 5000) <= 0) {
            free(payload);
            return NULL;
        }
        got = recv(client, payload + received, length - received, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            free(payload);
            return NULL;
        }
        if (got == 0) {
            free(payload);
            return NULL;
        }
        received += (size_t)got;
    }
    payload[length] = '\0';
    return payload;
}

/*
 * Answer one connection.  Returns -1 when the session must end, which only
 * STOP does: a bad request is the client's problem, the session's job is to
 * stay up.
 */
static int um_daemon_handle(UmDaemon *daemon, int client)
{
    UmLineReader reader;
    char line[256];
    size_t length;
    long timeout_ms;
    char *payload;
    int result;

    memset(&reader, 0, sizeof(reader));
    if (um_daemon_accept_line(client, &reader, line, sizeof(line), 5000) != 1) {
        close(client);
        return 0;
    }
    if (strcmp(line, "STOP") == 0) {
        (void)um_session_send_line(client, "BYE");
        close(client);
        return -1;
    }
    if (strcmp(line, "STATUS") == 0) {
        (void)um_session_send_line(client, daemon->ready ? "READY" : "BOOTING");
        close(client);
        return 0;
    }
    if (um_daemon_parse_exec(line, &length, &timeout_ms) < 0) {
        (void)um_session_send_line(client, "BAD unknown request");
        close(client);
        return 0;
    }
    payload = um_daemon_accept_payload(client, &reader, length);
    if (payload == NULL) {
        (void)um_session_send_line(client, "BAD truncated request");
        close(client);
        return 0;
    }
    result = um_daemon_start_job(daemon, client, payload, length, timeout_ms);
    free(payload);
    return result;
}

/* Read the channel paths the supervisor recorded once it made them. */
static int um_daemon_read_meta(UmDaemon *daemon)
{
    char path[PATH_MAX];
    char line[PATH_MAX];
    FILE *file;

    if (snprintf(path, sizeof(path), "%s/meta", daemon->state_path) >=
        (int)sizeof(path))
        return -1;
    file = fopen(path, "r");
    if (file == NULL)
        return -1;
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return -1;
    }
    line[strcspn(line, "\r\n")] = '\0';
    snprintf(daemon->session_host, sizeof(daemon->session_host), "%s", line);
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return -1;
    }
    line[strcspn(line, "\r\n")] = '\0';
    snprintf(daemon->channel_guest, sizeof(daemon->channel_guest), "%s", line);
    fclose(file);
    if (snprintf(daemon->channel_host, sizeof(daemon->channel_host),
                 "%s/channel", daemon->session_host) >=
            (int)sizeof(daemon->channel_host))
        return -1;
    return 0;
}

static int um_daemon_listen(UmDaemon *daemon)
{
    char path[PATH_MAX];
    char guest_ready[PATH_MAX];
    char ready_path[PATH_MAX];
    struct sockaddr_un address;
    struct pollfd descriptors[2];
    double boot_deadline;
    int listen_fd;

    if (snprintf(path, sizeof(path), "%s/ctl.sock", daemon->state_path) >=
            (int)sizeof(path) ||
        snprintf(guest_ready, sizeof(guest_ready), "%s/ready",
                 daemon->channel_host) >= (int)sizeof(guest_ready) ||
        snprintf(ready_path, sizeof(ready_path), "%s/ready",
                 daemon->state_path) >= (int)sizeof(ready_path))
        return 1;
    /*
     * The control socket lives at <state>/ctl.sock and connect() uses the same
     * path.  A sun_path is 108 bytes on Linux, and a truncated path silently
     * binds a *different*, shorter name (the symptom is a socket called "ct"),
     * so a state directory that deep is refused here with the length in the
     * message rather than producing a session nothing can connect to.
     */
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fprintf(stderr,
                "neoproot-um: session state path is too long for a unix "
                "socket (%zu bytes, max %zu): %s\n",
                strlen(path),
                sizeof(((struct sockaddr_un *)0)->sun_path) - 1, path);
        return 1;
    }
    (void)unlink(path);
    listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "neoproot-um: control socket: %s\n", strerror(errno));
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    {
        /* The 0700 directory is the access control; 0177 makes the socket
         * 0600 as well, so a mis-set directory is not the only barrier. */
        mode_t previous = umask(0177);

        if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
            listen(listen_fd, 8) < 0) {
            (void)umask(previous);
            fprintf(stderr, "neoproot-um: cannot bind %s: %s\n", path,
                    strerror(errno));
            close(listen_fd);
            return 1;
        }
        (void)umask(previous);
    }

    boot_deadline = um_now() + UM_SESSION_READY_SECONDS;
    for (;;) {
        int job = daemon->state == UM_JOB_RUNNING && daemon->client >= 0;
        struct pollfd *client_slot = &descriptors[1];
        int ready;

        descriptors[0].fd = listen_fd;
        descriptors[0].events = job ? 0 : POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = job ? daemon->client : -1;
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;
        /* A running job is polled by the guest's own loop interval; idling
         * costs one wakeup per 100 ms and only has to notice STOP. */
        ready = poll(descriptors, 2, job ? 5 : 100);
        if (ready < 0 && errno != EINTR)
            break;

        if (job && (client_slot->revents & POLLIN)) {
            char line[256];
            int result = um_session_read_line(daemon->client, &daemon->reader,
                                              line, sizeof(line));

            if (result == 1)
                um_daemon_job_input(daemon, line);
            else if (result < 0) {
                /* The client left.  The command keeps running -- it is not
                 * ours to kill -- and its output stays in the guest's files
                 * until the job ends. */
                close(daemon->client);
                daemon->client = -1;
                memset(&daemon->reader, 0, sizeof(daemon->reader));
            }
        }
        if (job && (client_slot->revents & (POLLHUP | POLLERR))) {
            close(daemon->client);
            daemon->client = -1;
            memset(&daemon->reader, 0, sizeof(daemon->reader));
        }
        if (um_daemon_poll_job(daemon) < 0)
            break;

        if (descriptors[0].revents & POLLIN) {
            int client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);

            if (client >= 0) {
                if (um_daemon_handle(daemon, client) < 0)
                    break;
                if (daemon->state == UM_JOB_RUNNING)
                    memset(&daemon->reader, 0, sizeof(daemon->reader));
            }
        }
        if (!daemon->ready && access(guest_ready, F_OK) == 0) {
            daemon->ready = true;
            um_daemon_publish(daemon->state_path, "ready", "ready");
            fprintf(stderr, "neoproot-um: session ready\n");
        }
        if (!daemon->ready && um_now() >= boot_deadline) {
            fprintf(stderr, "neoproot-um: the guest did not become ready\n");
            break;
        }
        if (daemon->supervisor_pid > 0 &&
            kill(daemon->supervisor_pid, 0) < 0)
            break;
        /*
         * A daemon whose session directory now belongs to somebody else must
         * go away.  This happens when a session is stopped and restarted
         * faster than the old daemon noticed: the new start removes the lock,
         * makes its own, and records its own pid, and the old daemon would
         * otherwise keep polling the same channel and deleting the new run's
         * job directories.  The pid file is the ownership record, so it is
         * what decides.
         */
        if (++daemon->watchdog_ticks >= 50) {
            daemon->watchdog_ticks = 0;
            if (um_session_pid_read(daemon->state_path) != getpid()) {
                fprintf(stderr,
                        "neoproot-um: another daemon owns this session; "
                        "exiting\n");

                break;
            }
        }
    }
    close(listen_fd);
    (void)unlink(path);
    if (daemon->client >= 0)
        close(daemon->client);
    return 0;
}

/* Ask the guest to power off and wait for the supervisor to exit. */
static void um_daemon_shutdown(UmDaemon *daemon)
{
    double deadline;

    if (daemon->channel_host[0] != '\0') {
        um_daemon_publish(daemon->channel_host, "stop", "stop");
        um_daemon_wake(daemon->channel_host);
    }
    deadline = um_now() + UM_SESSION_STOP_SECONDS;
    while (um_now() < deadline) {
        int status;

        if (waitpid(daemon->supervisor_pid, &status, WNOHANG) ==
            daemon->supervisor_pid)
            return;
        usleep(20000);
    }
    fprintf(stderr,
            "neoproot-um: the guest did not shut down; killing the kernel\n");
    (void)kill(daemon->supervisor_pid, SIGTERM);
    usleep(200000);
    (void)kill(daemon->supervisor_pid, SIGKILL);
    (void)waitpid(daemon->supervisor_pid, NULL, 0);
}

int neoproot_um_session_daemon_main(const char *name, int argc,
                                    char *const argv[])
{
    char state_path[PATH_MAX];
    char *session_option = NULL;
    char **child_argv;
    UmDaemon daemon;
    int lock;
    int index;

    if (!um_session_name_ok(name))
        return 125;
    if (um_session_state_path(state_path, sizeof(state_path), name) < 0)
        return 125;
    if (um_session_prepare_state(state_path, true) < 0)
        return 125;
    lock = um_session_lock(state_path, false);
    if (lock < 0) {
        fprintf(stderr, "neoproot-um: session %s is in use\n", state_path);
        return 125;
    }
    if (um_session_pid_write(state_path, getpid()) < 0) {
        fprintf(stderr, "neoproot-um: cannot record the daemon pid\n");
        return 125;
    }
    memset(&daemon, 0, sizeof(daemon));
    daemon.name = name;
    daemon.state_path = state_path;
    daemon.state = UM_JOB_IDLE;
    daemon.client = -1;
    daemon.stdout_fd = -1;
    daemon.stderr_fd = -1;

    /*
     * The supervisor is a child, not a call: it owns the kernel and blocks
     * until the kernel exits, and this process has to serve the socket in the
     * meantime.  Its shutdown path -- umid removal, temporary COW deletion --
     * is exactly the one-shot path, unchanged.
     */
    /*
     * The supervisor's own vector: our arguments, then --session.  Anything
     * the caller put after -- is dropped here: a session has no single
     * command, and passing it on would make the supervisor treat --session as
     * that command.
     */
    child_argv = calloc((size_t)argc + 4, sizeof(*child_argv));
    if (child_argv == NULL)
        return 125;
    /* argv[0] is the supervisor's own name, not an option: the option parser
     * starts at 1, exactly as it does for a direct command line. */
    child_argv[0] = (char *)"neoproot-um";
    index = 1;
    for (int source = 0; source < argc; source++) {
        if (strcmp(argv[source], "--") == 0)
            break;
        child_argv[index++] = argv[source];
    }
    child_argv[index++] = (char *)"--session";
    if (asprintf(&session_option, "--session-state=%s", state_path) > 0)
        child_argv[index++] = session_option;
    child_argv[index] = NULL;

    daemon.supervisor_pid = fork();
    if (daemon.supervisor_pid < 0) {
        fprintf(stderr, "neoproot-um: fork: %s\n", strerror(errno));
        um_session_remove_state(state_path);
        close(lock);
        return 125;
    }
    if (daemon.supervisor_pid == 0) {
        _exit(neoproot_um_supervisor_main(index, child_argv));
    }
    /*
     * The daemon must outlive a client that dies and must not be killed by
     * the terminal that started it: the session belongs to the machine, not
     * to a shell.
     */
    (void)signal(SIGHUP, SIG_IGN);
    (void)signal(SIGPIPE, SIG_IGN);

    /* Wait for the supervisor to record where the channel is. */
    {
        double deadline = um_now() + UM_SESSION_READY_SECONDS;

        while (um_daemon_read_meta(&daemon) < 0) {
            int status;

            if (waitpid(daemon.supervisor_pid, &status, WNOHANG) ==
                daemon.supervisor_pid) {
                /* Keep the directory and its log: the caller reports the
                 * log path, and the next start overwrites it. */
                fprintf(stderr,
                        "neoproot-um: the supervisor exited before the "
                        "session channel existed\n");
                close(lock);
                return 125;
            }
            if (um_now() >= deadline) {
                fprintf(stderr, "neoproot-um: no session channel appeared\n");
                (void)kill(daemon.supervisor_pid, SIGKILL);
                um_session_remove_state(state_path);
                close(lock);
                return 125;
            }
            usleep(20000);
        }
    }

    (void)um_daemon_listen(&daemon);
    um_daemon_shutdown(&daemon);
    um_session_remove_state(state_path);
    close(lock);
    free(session_option);
    return 0;
}
