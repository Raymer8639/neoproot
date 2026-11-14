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
#include <sys/syscall.h>
#include <stdint.h>
#include <talloc.h>
#include "tracee/abi.h"
#include "cli/note.h"

#include "syscall/socket.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"
#include "path/binding.h"
#include "path/temp.h"
#include "path/path.h"
#include "arch.h"
#include "compat.h"

static const size_t offsetof_path = offsetof(struct sockaddr_un, sun_path);
static const size_t sizeof_path = sizeof(((struct sockaddr_un *)0)->sun_path);

/* Unlike ptrace (and write_data's fallback), process_vm_* honors the
 * tracee's page protections.  Never fall back when accessing a sendmmsg
 * input header or reporting msg_len: a fault must stop the batch. */
static int sendmmsg_read(const Tracee *tracee, void *data, word_t address, size_t size)
{
#ifdef __NR_process_vm_readv
	struct iovec local = { .iov_base = data, .iov_len = size };
	struct iovec remote = { .iov_base = (void *)address, .iov_len = size };
	ssize_t result = syscall(__NR_process_vm_readv, tracee->pid,
				&local, 1, &remote, 1, 0);
	if (result < 0)
		return -errno;
	return result == (ssize_t)size ? 0 : -EFAULT;
#else
	(void)tracee; (void)data; (void)address; (void)size;
	return -ENOSYS;
#endif
}

static int sendmmsg_write_length(Tracee *tracee, word_t address, uint32_t length)
{
#ifdef __NR_process_vm_writev
	struct iovec local = { .iov_base = &length, .iov_len = sizeof(length) };
	struct iovec remote = { .iov_base = (void *)address, .iov_len = sizeof(length) };
	ssize_t result = syscall(__NR_process_vm_writev, tracee->pid,
				&local, 1, &remote, 1, 0);
	if (result < 0)
		return -errno;
	return result == sizeof(length) ? 0 : -EFAULT;
#else
	(void)tracee; (void)address; (void)length;
	return -ENOSYS;
#endif
}

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

	if (host_path != sockaddr->sun_path)
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
 * The translated address is copied to @sockaddr.  With @checked, input
 * reads honor page protections instead of using the ptrace fallback.
 * Returns -errno on error, 0 if unchanged, otherwise 1.
 */
static int translate_send_sockaddr(Tracee *tracee, word_t address, int size,
				   struct sockaddr_un *sockaddr, bool checked)
{
	char user_path[PATH_MAX];
	char host_path[PATH_MAX];
	struct stat statl;
	int saved_errno;
	int status;

	if (address == 0)
		return 0;

	if (checked) {
		if (size <= (int)offsetof_path || (size_t)size > sizeof(*sockaddr))
			return 0;
		memset(sockaddr, 0, sizeof(*sockaddr));
		status = sendmmsg_read(tracee, sockaddr, address, size);
		if (status < 0)
			return status;
		if (sockaddr->sun_family != AF_UNIX || sockaddr->sun_path[0] == '\0')
			return 0;
		memcpy(user_path, sockaddr->sun_path, sizeof_path);
		user_path[sizeof_path] = '\0';
	}
	else {
		status = read_sockaddr_un(tracee, sockaddr, sizeof(*sockaddr), user_path, address, size);
		if (status <= 0)
			return status;
	}

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

	strncpy(sockaddr->sun_path, host_path, sizeof_path);
	return 1;
}

int translate_send_address(Tracee *tracee, word_t *address, int size)
{
	struct sockaddr_un sockaddr;
	int status = translate_send_sockaddr(tracee, *address, size, &sockaddr, false);

	if (status <= 0)
		return status;
	return push_sockaddr_un(tracee, &sockaddr, sockaddr.sun_path, address);
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

	for (i = 0; i < count; i++) {
		/* Keep the translated prefix if a later header is unreadable.  */
		status = read_data(tracee, vector + i * size, *address + i * size, size);
		if (status < 0) {
			/* With no valid prefix, let the kernel report the bad address.  */
			if (i == 0)
				return 0;
			break;
		}

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

		int status = sendmmsg_write_length(tracee, address + i * size + offsetof_len, length);
		if (status < 0)
			return status;
	}

	return 0;
}

/* Only an index is kept across stops.  Each next input header is read after
 * the previous send AND msg_len store have completed, just as in the kernel.
 * This object is a child of Tracee, never of the per-event tracee->ctx. */
struct sendmmsg_pending {
	Tracee *tracee;
	struct sendmmsg_pending *next;
	struct sendmmsg_pending **previous;
	word_t vector;
	word_t count;
	word_t completed;
	word_t scratch;
	word_t fd;
	word_t flags;
	bool chained;
};

static struct sendmmsg_pending *sendmmsg_pending_head;

static int unlink_sendmmsg_pending(struct sendmmsg_pending *pending)
{
	*pending->previous = pending->next;
	if (pending->next != NULL)
		pending->next->previous = pending->previous;
	return 0;
}

static struct sendmmsg_pending *find_sendmmsg_pending(const Tracee *tracee)
{
	struct sendmmsg_pending *pending;
	for (pending = sendmmsg_pending_head; pending != NULL; pending = pending->next)
		if (pending->tracee == tracee)
			return pending;
	return NULL;
}

/* Read only msghdr, not the output msg_len or trailing mmsghdr padding.
 * A readable input header followed by an inaccessible msg_len still sends. */
static int read_sendmmsg_header(Tracee *tracee, word_t vector, word_t index, uint8_t *header)
{
	word_t offset = index * SIZEOF_MMSGHDR(tracee);
	if (vector > (word_t)-1 - offset ||
	    vector + offset > (word_t)-1 - SIZEOF_MSGHDR(tracee))
		return -EFAULT;
	return sendmmsg_read(tracee, header, vector + offset, SIZEOF_MSGHDR(tracee));
}

static int translate_sendmmsg_name(Tracee *tracee, uint8_t *header, struct sockaddr_un *sockaddr)
{
	int32_t namelen;
	memcpy(&namelen, header + sizeof_word(tracee), sizeof(namelen));
	return translate_send_sockaddr(tracee, get_word(tracee, header), namelen, sockaddr, true);
}

static int prepare_sendmmsg_message(struct sendmmsg_pending *pending)
{
	Tracee *tracee = pending->tracee;
	uint8_t header[7 * sizeof(word_t)];
	struct sockaddr_un sockaddr;
	int32_t namelen = sizeof(sockaddr);
	int status;

	status = read_sendmmsg_header(tracee, pending->vector, pending->completed, header);
	if (status < 0)
		return status;
	status = translate_sendmmsg_name(tracee, header, &sockaddr);
	if (status < 0)
		return status;
	if (status > 0) {
		word_t name = pending->scratch + SIZEOF_MSGHDR(tracee);
		status = write_data(tracee, name, &sockaddr, sizeof(sockaddr));
		if (status < 0)
			return status;
		set_word(tracee, header, name);
		memcpy(header + sizeof_word(tracee), &namelen, sizeof(namelen));
	}
	return write_data(tracee, pending->scratch, header, SIZEOF_MSGHDR(tracee));
}

/* Install the first sendmsg directly.  No chain is registered until that
 * send's result and the permission-respecting msg_len store are known. */
int translate_sendmmsg_start(Tracee *tracee, word_t address, word_t vlen)
{
	uint8_t header[7 * sizeof(word_t)];
	struct sockaddr_un sockaddr;
	struct sendmmsg_pending *pending;
	word_t count = MIN((unsigned int)vlen, UIO_MAXIOV);
	word_t i;
	int status;

	if (address == 0 || count == 0)
		return 0;
	if (find_sendmmsg_pending(tracee) != NULL)
		return -EBUSY;

	/* Leave the complete native syscall intact if the readable prefix
	 * needs no destination translation.  In particular a later bad
	 * header must not discard the kernel's already-sent prefix. */
	for (i = 0; i < count; i++) {
		status = read_sendmmsg_header(tracee, address, i, header);
		if (status < 0)
			return status == -EFAULT ? 0 : status;
		status = translate_sendmmsg_name(tracee, header, &sockaddr);
		if (status != 0)
			break;
	}
	if (i == count)
		return 0;

	pending = talloc_zero(tracee, struct sendmmsg_pending);
	if (pending == NULL)
		return -ENOMEM;
	pending->tracee = tracee;
	pending->vector = address;
	pending->count = count;
	pending->fd = peek_reg(tracee, CURRENT, SYSARG_1);
	pending->flags = (unsigned int)peek_reg(tracee, CURRENT, SYSARG_4);
	/* This is the only alloc_mem in the lowered batch (including 1024
	 * messages).  Subsequent exits only overwrite this fixed area. */
	pending->scratch = alloc_mem(tracee, SIZEOF_MSGHDR(tracee) + sizeof(sockaddr));
	if (pending->scratch == 0) {
		talloc_free(pending);
		return -EFAULT;
	}
	status = prepare_sendmmsg_message(pending);
	if (status < 0) {
		talloc_free(pending);
		return status;
	}

	pending->next = sendmmsg_pending_head;
	pending->previous = &sendmmsg_pending_head;
	if (pending->next != NULL)
		pending->next->previous = &pending->next;
	sendmmsg_pending_head = pending;
	talloc_set_destructor(pending, unlink_sendmmsg_pending);

	set_sysnum(tracee, PR_sendmsg);
	poke_reg(tracee, SYSARG_2, pending->scratch);
	poke_reg(tracee, SYSARG_3, pending->flags);
	tracee->restart_how = PTRACE_SYSCALL;
	return 1;
}

static void finish_sendmmsg_batch(struct sendmmsg_pending *pending, long error)
{
	Tracee *tracee = pending->tracee;
	word_t result = pending->completed != 0 ? pending->completed : (word_t)error;
	poke_reg(tracee, SYSARG_RESULT, result);
	if (pending->chained)
		force_chain_final_result(tracee, result);
	talloc_free(pending);
}

static void complete_sendmmsg_message(struct sendmmsg_pending *pending)
{
	Tracee *tracee = pending->tracee;
	long result = (long)peek_reg(tracee, CURRENT, SYSARG_RESULT);
	int status;

	if (result < 0) {
		finish_sendmmsg_batch(pending, result);
		return;
	}
	status = sendmmsg_write_length(tracee,
		pending->vector + pending->completed * SIZEOF_MMSGHDR(tracee) + SIZEOF_MSGHDR(tracee),
		(uint32_t)result);
	if (status < 0) {
		finish_sendmmsg_batch(pending, status);
		return;
	}
	pending->completed++;
	if (pending->completed == pending->count) {
		finish_sendmmsg_batch(pending, 0);
		return;
	}
	status = prepare_sendmmsg_message(pending);
	if (status >= 0)
		status = register_chained_syscall(tracee, PR_sendmsg, pending->fd,
			pending->scratch, pending->flags, 0, 0, 0);
	if (status < 0) {
		finish_sendmmsg_batch(pending, status);
		return;
	}
	pending->chained = true;
	force_chain_final_result(tracee, pending->completed);
}

bool translate_sendmmsg_finish(Tracee *tracee)
{
	struct sendmmsg_pending *pending = find_sendmmsg_pending(tracee);
	if (pending == NULL || pending->chained)
		return false;
	complete_sendmmsg_message(pending);
	return true;
}

void translate_sendmmsg_chained_exit(Tracee *tracee)
{
	struct sendmmsg_pending *pending = find_sendmmsg_pending(tracee);
	if (pending != NULL && pending->chained)
		complete_sendmmsg_message(pending);
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
