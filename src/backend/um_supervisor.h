#ifndef NEOPROOT_UM_SUPERVISOR_H
#define NEOPROOT_UM_SUPERVISOR_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define UM_SESSION_NAME_LIMIT 64

/*
 * Files the daemon and the guest loop exchange inside the session directory.
 * They are shared by both halves, so they live here.
 */
#define UM_SESSION_REQUEST_MARKER "neoproot-exec-v1"
#define UM_SESSION_LOOP_MARKER "neoproot-session-loop-v1"
#define UM_SESSION_CHANNEL_NAME "channel"

/* One-shot backend: boot, run one command, shut down. */
int neoproot_um_supervisor_main(int argc, char *const argv[]);

/* The session client: session start / run / stop / status. */
int neoproot_um_session_client_main(int argc, char *const argv[]);

/*
 * The session daemon: the one-shot supervisor in session mode, driving the
 * guest's request loop.  It owns the kernel, so it is started as a child of
 * "session start" and stays alive until the kernel exits.
 */
int neoproot_um_session_daemon_main(const char *name, int argc,
                                    char *const argv[]);

/* Shared by the supervisor, the session code and the daemon. */
int um_write_all(int fd, const void *data, size_t length);
double um_now(void);

/*
 * A newline reader over a non-blocking socket.  One per connection: it keeps
 * whatever arrived after the last newline, so a frame's header and payload
 * can share a read.
 */
#define UM_LINE_READER_SIZE 4096
typedef struct {
    char buffer[UM_LINE_READER_SIZE];
    size_t used;
} UmLineReader;

bool um_session_name_ok(const char *name);
int um_session_state_path(char *buffer, size_t size, const char *name);
int um_session_state_parent(const char *state_path, char *parent, size_t size);
int um_session_prepare_state(const char *state_path, bool fresh);
bool um_session_owned(const char *state_path);
int um_session_write_owner(const char *state_path);
int um_session_lock(const char *state_path, bool wait);
int um_session_pid_write(const char *state_path, pid_t pid);
pid_t um_session_pid_read(const char *state_path);
bool um_session_daemon_alive(pid_t pid);
void um_session_remove_state(const char *state_path);
int um_session_write_loop(int fd);
int um_session_send_bytes(int fd, const void *data, size_t length);
int um_session_send_line(int fd, const char *line);
int um_session_send_frame(int fd, const char *kind, const void *data,
                          size_t length);
int um_session_read_line(int fd, UmLineReader *reader, char *buffer,
                         size_t size);

#endif
