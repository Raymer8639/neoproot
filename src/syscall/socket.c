#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>

#include "syscall/socket.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "path/temp.h"
#include "path/path.h"
#include "arch.h"
#include "compat.h"

static const size_t offsetof_path = offsetof(struct sockaddr_un, sun_path);
static const size_t sizeof_path = sizeof(((struct sockaddr_un *)0)->sun_path);

/**
 * Read sockaddr_un from tracee memory.
 * Returns:
 *  -1  = error
 *   0  = not a AF_UNIX with path
 *   1  = success
 */
static int read_sockaddr_un(
	Tracee *tracee,
	struct sockaddr_un *sockaddr,
	size_t max_size,
	char path[PATH_MAX],
	word_t addr,
	int len)
{
	if (len <= (int)offsetof_path || (size_t)len > max_size)
		return 0;

	memset(sockaddr, 0, sizeof(*sockaddr));
	if (read_data(tracee, sockaddr, addr, len) < 0)
		return -errno;

	if (sockaddr->sun_family != AF_UNIX || sockaddr->sun_path[0] == '\0')
		return 0;

	strncpy(path, sockaddr->sun_path, sizeof_path);
	path[sizeof_path] = '\0';
	return 1;
}

/**
 * Translate socket path on enter (bind/connect/...).
 */
int translate_socketcall_enter(Tracee *tracee, word_t *addr_ptr, int len)
{
	struct sockaddr_un sa;
	char guest_path[PATH_MAX];
	char host_path[PATH_MAX];
	char tmp_path[PATH_MAX];
	int ret;

	if (*addr_ptr == 0)
		return 0;

	ret = read_sockaddr_un(tracee, &sa, sizeof(sa), guest_path, *addr_ptr, len);
	if (ret <= 0)
		return ret;

	ret = translate_path(tracee, host_path, AT_FDCWD, guest_path, true);
	if (ret < 0)
		return ret;

	// Path too long for sun_path: use a shorter temp binding
	if (strlen(host_path) >= sizeof_path) {
		char *short_host;
		Binding *b;

		short_host = create_temp_name(tracee->ctx, "proot");
		if (!short_host || strlen(short_host) >= sizeof_path)
			return -EINVAL;

		strcpy(tmp_path, short_host);
		int fd = mkstemp(tmp_path);
		if (fd >= 0) {
			close(fd);
			unlink(tmp_path);
		}

		strcpy(short_host, tmp_path);
		if (strlen(short_host) >= sizeof_path)
			return -EINVAL;

		// Canonicalize guest path
		strcpy(guest_path, host_path);
		if (detranslate_path(tracee, guest_path, NULL) < 0)
			return -EINVAL;

		b = insort_binding3(tracee, tracee->ctx, short_host, guest_path);
		if (!b)
			return -EINVAL;

		talloc_reparent(tracee->ctx, b, short_host);
		strcpy(host_path, short_host);
	}

	// Overwrite socket path
	strncpy(sa.sun_path, host_path, sizeof_path);

	// Allocate new buffer and write back
	word_t new_addr = alloc_mem(tracee, sizeof(sa));
	if (new_addr == 0)
		return -EFAULT;

	if (write_data(tracee, new_addr, &sa, sizeof(sa)) < 0)
		return -EFAULT;

	*addr_ptr = new_addr;
	return 1;
}

/**
 * Detranslate socket path on exit (accept/getsockname/...).
 */
int translate_socketcall_exit(
	Tracee *tracee,
	word_t sock_addr,
	word_t len_addr,
	size_t max_size)
{
	struct sockaddr_un sa;
	char path[PATH_MAX];
	int len;
	bool truncated = false;
	int ret;

	if (sock_addr == 0)
		return 0;

	len = peek_int32(tracee, len_addr);
	if (errno != 0)
		return -errno;

	if (max_size > sizeof(sa))
		max_size = sizeof(sa);

	ret = read_sockaddr_un(tracee, &sa, max_size, path, sock_addr, len);
	if (ret <= 0)
		return ret;

	if (detranslate_path(tracee, path, NULL) < 0)
		return -ENOENT;

	// Rebuild sockaddr
	size_t new_len = offsetof_path + strlen(path) + 1;
	if (new_len > max_size) {
		new_len = max_size;
		truncated = true;
	}

	strncpy(sa.sun_path, path, sizeof_path);
	if (write_data(tracee, sock_addr, &sa, new_len) < 0)
		return -EFAULT;

	// Update length (truncated flag)
	if (truncated)
		new_len = max_size + 1;

	poke_int32(tracee, len_addr, (int)new_len);
	return 0;
}
