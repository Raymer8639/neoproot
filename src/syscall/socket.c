#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <stdint.h>
#include <talloc.h>
#include "tracee/abi.h"
#include "cli/note.h"

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
	int status = read_data(tracee, sockaddr, addr, len);
	if (status < 0)
		return status;

	if (sockaddr->sun_family != AF_UNIX || sockaddr->sun_path[0] == '\0')
		return 0;

	strncpy(path, sockaddr->sun_path, sizeof_path);
	path[sizeof_path] = '\0';
	return 1;
}

/**
 * Push a copy of @sockaddr whose pathname is replaced with
 * @host_path to a newly allocated space in the @tracee memory, and put
 * its address in the @address parameter.  This function returns
 * -errno if an error occurred, otherwise 1.
 */
static int push_sockaddr_un(Tracee *tracee, struct sockaddr_un *sockaddr,
			const char *host_path, word_t *address)
{
	int status;

	strncpy(sockaddr->sun_path, host_path, sizeof_path);

	/* Push the updated sockaddr to a newly allocated space.  */
	*address = alloc_mem(tracee, sizeof(*sockaddr));
	if (*address == 0)
		return -EFAULT;

	status = write_data(tracee, *address, sockaddr, sizeof(*sockaddr));
	if (status < 0)
		return status;

	return 1;
}

static int remove_shorter_host_path(char *path)
{
	struct stat st;
	if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) && unlink(path) < 0)
		note(NULL, WARNING, SYSTEM, "cannot remove socket %s", path);
	return 0;
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
		TALLOC_CTX *binding_context = tracee->fs->bindings.guest != NULL
			? (TALLOC_CTX *)tracee->fs->bindings.guest : tracee->fs;

		/* Keep cleanup until tracer exit: cloned binding trees still use it. */
		short_host = create_temp_name(NULL, "proot");
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

		b = insort_binding4(tracee, binding_context, short_host, guest_path,
				   BINDING_MOUNT_INTERNAL);
		if (!b)
			return -EINVAL;

		talloc_set_destructor(short_host, remove_shorter_host_path);
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
 * Translate the pathname of the struct sockaddr_un currently stored
 * in the @tracee memory at the given @address (@size bytes long), the
 * destination of a message sent by sendto(2), sendmsg(2) or
 * sendmmsg(2).  It is translated like the address connect(2) is
 * given, except:
 *
 *   - when nothing exists at this absolute path in the guest
 *     namespace, the address is left as is.  Addresses the kernel
 *     reports, like the source of a datagram given by recvfrom(2),
 *     name host paths: a reply sent to one of them has to reach it.
 *
 *   - a translated path too long to fit the sun_path array is
 *     refused with -ENAMETOOLONG, or with -ENOENT when nothing exists
 *     there: unlike bind(2), the socket has to exist already, so it
 *     can't be bound to a shorter path.  A socket bound by the
 *     tracees to such a path is found through the binding created by
 *     bind(2) instead.
 *
 * The new address of the translated sockaddr_un is put in the
 * @address parameter.  This function returns -errno if an error
 * occurred, 0 if the address was left as is, otherwise 1.
 */
int translate_send_address(Tracee *tracee, word_t *address, int size)
{
	struct sockaddr_un sockaddr;
	char user_path[PATH_MAX];
	char host_path[PATH_MAX];
	struct stat statl;
	int saved_errno;
	int status;

	if (*address == 0)
		return 0;

	status = read_sockaddr_un(tracee, &sockaddr, sizeof(sockaddr), user_path, *address, size);
	if (status <= 0)
		return status;

	status = translate_path(tracee, host_path, AT_FDCWD, user_path, true);

	/* Only an absolute path can be a host path the kernel reported:
	 * bind(2) gives it the absolute host path of the sockets the
	 * tracees bind.  A relative path is always resolved against the
	 * guest working directory, the kernel tells whether something
	 * exists there unless the translated path is too long for it.  */
	if (status == 0 && (user_path[0] == '/' || strlen(host_path) > sizeof_path)) {
		saved_errno = errno;
		if (lstat(host_path, &statl) < 0 && (errno == ENOENT || errno == ENOTDIR))
			status = -errno;
		errno = saved_errno;
	}

	if ((status == -ENOENT || status == -ENOTDIR) && user_path[0] == '/')
		return 0;

	if (status < 0)
		return status;

	/* Be careful: sun_path doesn't have to be null-terminated.  */
	if (strlen(host_path) > sizeof_path)
		return -ENAMETOOLONG;

	return push_sockaddr_un(tracee, &sockaddr, host_path, address);
}

/* A struct msghdr is seven words long, msg_name being the first one
 * and msg_namelen the second one, and a struct mmsghdr is a struct
 * msghdr followed by msg_len, eight words long, on all ABIs.  */
#define SIZEOF_MSGHDR(tracee)	(7 * sizeof_word(tracee))
#define SIZEOF_MMSGHDR(tracee)	(8 * sizeof_word(tracee))

/**
 * Return the word stored in the copy of @tracee memory at @data.
 */
static word_t get_word(const Tracee *tracee, const uint8_t *data)
{
	uint32_t value32;
	word_t value;

	if (sizeof_word(tracee) == sizeof(value32)) {
		memcpy(&value32, data, sizeof(value32));
		return value32;
	}

	memcpy(&value, data, sizeof(value));
	return value;
}

/**
 * Store @value as a word in the copy of @tracee memory at @data.
 */
static void set_word(const Tracee *tracee, uint8_t *data, word_t value)
{
	uint32_t value32 = value;

	if (sizeof_word(tracee) == sizeof(value32))
		memcpy(data, &value32, sizeof(value32));
	else
		memcpy(data, &value, sizeof(value));
}

/**
 * Translate the destination of the struct msghdr whose copy is at
 * @msghdr, see translate_send_address().  This function returns
 * -errno if an error occurred, 0 if the copy was left as is,
 * otherwise 1.
 */
static int translate_msg_name(Tracee *tracee, uint8_t *msghdr)
{
	const size_t offsetof_namelen = sizeof_word(tracee);
	int32_t namelen;
	word_t name;
	int status;

	name = get_word(tracee, msghdr);
	memcpy(&namelen, msghdr + offsetof_namelen, sizeof(namelen));

	status = translate_send_address(tracee, &name, namelen);
	if (status <= 0)
		return status;

	namelen = sizeof(struct sockaddr_un);
	set_word(tracee, msghdr, name);
	memcpy(msghdr + offsetof_namelen, &namelen, sizeof(namelen));

	return 1;
}

/**
 * Push a copy of the @size bytes at @data to a newly allocated space
 * in the @tracee memory, and put its address in the @address
 * parameter.  This function returns -errno if an error occurred,
 * otherwise 0.
 */
static int push_data(Tracee *tracee, const void *data, size_t size, word_t *address)
{
	*address = alloc_mem(tracee, size);
	if (*address == 0)
		return -EFAULT;

	return write_data(tracee, *address, data, size);
}

/**
 * Translate the destination of the struct msghdr currently stored in
 * the @tracee memory at the given @address, see
 * translate_send_address().  The tracee might use its structure
 * again, so it is left untouched: the address of an updated copy is
 * put in the @address parameter instead.  This function returns
 * -errno if an error occurred, 0 if nothing was changed, otherwise 1.
 */
int translate_sendmsg_enter(Tracee *tracee, word_t *address)
{
	uint8_t msghdr[7 * sizeof(word_t)];
	const size_t size = SIZEOF_MSGHDR(tracee);
	int status;

	if (*address == 0)
		return 0;

	/* Let the kernel report a bad address.  */
	status = read_data(tracee, msghdr, *address, size);
	if (status < 0)
		return 0;

	status = translate_msg_name(tracee, msghdr);
	if (status <= 0)
		return status;

	status = push_data(tracee, msghdr, size, address);
	if (status < 0)
		return status;

	return 1;
}

/**
 * Translate the destination of each of the *@vlen struct mmsghdr
 * currently stored in the @tracee memory at the given @address, see
 * translate_send_address().  As with translate_sendmsg_enter(), the
 * address of an updated copy of this vector is put in the @address
 * parameter when a destination is translated: the kernel reports the
 * number of bytes sent for each message in this copy, see
 * translate_sendmmsg_exit().  Like the kernel, only the messages that
 * precede the first one that can't be sent are sent: *@vlen is
 * lowered to their number, or the error is returned if there's none.
 * This function returns -errno if an error occurred, 0 if nothing
 * was changed, otherwise 1.
 */
int translate_sendmmsg_enter(Tracee *tracee, word_t *address, word_t *vlen)
{
	const size_t size = SIZEOF_MMSGHDR(tracee);
	bool translated = false;
	uint8_t *vector;
	word_t count;
	word_t i;
	int status = 0;

	if (*address == 0 || *vlen == 0)
		return 0;

	/* The kernel doesn't send more messages at once.  */
	count = MIN(*vlen, UIO_MAXIOV);

	vector = talloc_size(tracee->ctx, count * size);
	if (vector == NULL)
		return -ENOMEM;

	/* Let the kernel report a bad address.  */
	status = read_data(tracee, vector, *address, count * size);
	if (status < 0)
		return 0;

	for (i = 0; i < count; i++) {
		status = translate_msg_name(tracee, vector + i * size);
		if (status < 0)
			break;
		if (status > 0)
			translated = true;
	}

	if (status < 0) {
		if (i == 0)
			return status;
		count = i;
	}
	else if (!translated)
		return 0;

	*vlen = count;

	if (translated) {
		status = push_data(tracee, vector, count * size, address);
		if (status < 0)
			return status;
	}

	return 1;
}

/**
 * Report to the vector of struct mmsghdr stored in the @tracee memory
 * at the given @address the number of bytes the kernel sent for each
 * of its first @count messages, written in the copy of this vector at
 * @copy, see translate_sendmmsg_enter().  This function returns
 * -errno if an error occurred, otherwise 0.
 */
int translate_sendmmsg_exit(Tracee *tracee, word_t address, word_t copy, word_t count)
{
	const size_t offsetof_len = SIZEOF_MSGHDR(tracee);
	const size_t size = SIZEOF_MMSGHDR(tracee);
	uint32_t length;
	word_t i;

	for (i = 0; i < count; i++) {
		length = peek_uint32(tracee, copy + i * size + offsetof_len);
		if (errno != 0)
			return -errno;

		poke_uint32(tracee, address + i * size + offsetof_len, length);
		if (errno != 0)
			return -errno;
	}

	return 0;
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
