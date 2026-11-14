#include <linux/limits.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/helper_functions.h"

#define OWNER_PERMS  0
#define GROUP_PERMS  1
#define OTHER_PERMS  2

typedef struct MetaRecord {
	char key[48];
	mode_t mode;
	uid_t owner;
	gid_t group;
	bool recorded;
	struct MetaRecord *next;
	/* Translated host path, with trailing slashes removed except for root. */
	char host_path[];
} MetaRecord;

static MetaRecord *meta_records;

static MetaRecord *find_meta_record(const char *key)
{
	for (MetaRecord *record = meta_records; record != NULL; record = record->next)
		if (strcmp(record->key, key) == 0)
			return record;
	return NULL;
}

static bool is_meta_key(const char *path)
{
	return strncmp(path, "@neoproot-meta:", 15) == 0;
}

int initialize_meta_store(void)
{
	return 0;
}

int dtoo(int n)
{
	int rem, i=1, octal=0;
	while (n!=0)
	{
		rem=n%8;
		n/=8;
		octal+=rem*i;
		i*=10;
	}
	return octal;
}

int otod(int n)
{
	int decimal=0, i=0, rem;
	while (n!=0)
	{
		int j;
		int pow = 1;
		for(j = 0; j < i; j++)
			pow = pow * 8;
		rem = n%10;
		n/=10;
		decimal += rem*pow;
		++i;
	}
	return decimal;
}

int path_exists(char path[PATH_MAX])
{
	struct stat st;
	if (is_meta_key(path)) {
		MetaRecord *record = find_meta_record(path);
		if (record != NULL && record->recorded)
			return 0;
		errno = ENOENT;
		return -1;
	}
	return lstat(path, &st);
}

int get_fd_path(Tracee *tracee, char path[PATH_MAX], Reg fd_sysarg, RegVersion version)
{
	int status;

	if(fd_sysarg != IGNORE_SYSARG) {
		if((signed int) peek_reg(tracee, version, fd_sysarg) == -100)
			status = getcwd2(tracee, path);
		else {
			status = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, version, fd_sysarg), path);
		}
		if(status < 0)
			return status;
	} else {
		translate_path(tracee, path, AT_FDCWD, "/", true);
	}

	if(path[0] != '/' || !belongs_to_guestfs(tracee, path))
		return 1;

	return 0;
}

/* Only canonical proc descriptor names are accepted by the kernel. */
int resolve_proc_fd_path(Tracee *tracee, char path[PATH_MAX])
{
	char target[PATH_MAX];
	const char *cursor = path;
	char *end;
	unsigned long pid, fd;

	if (strncmp(cursor, "/proc/", 6) != 0)
		return -1;
	cursor += 6;
	if (strncmp(cursor, "self/", 5) == 0) {
		pid = tracee->pid;
		cursor += 5;
	} else {
		if (*cursor < '1' || *cursor > '9')
			return -1;
		errno = 0;
		pid = strtoul(cursor, &end, 10);
		if (errno != 0 || pid > INT_MAX || *end != '/')
			return -1;
		cursor = end + 1;
	}
	if (strncmp(cursor, "fd/", 3) != 0)
		return -1;
	cursor += 3;
	if (*cursor < '0' || *cursor > '9' || (*cursor == '0' && cursor[1] != '\0'))
		return -1;
	errno = 0;
	fd = strtoul(cursor, &end, 10);
	if (errno != 0 || fd > INT_MAX || *end != '\0')
		return -1;
	if (readlink_proc_pid_fd(pid, fd, target) < 0 || target[0] != '/')
		return -1;
	strcpy(path, target);
	return belongs_to_guestfs(tracee, path) ? 0 : 1;
}

int read_sysarg_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg, RegVersion version)
{
	int size;
	char original[PATH_MAX];
	path[0] = '\0';

	switch(version) {
		case MODIFIED:
			size = read_string(tracee, path, peek_reg(tracee, MODIFIED, path_sysarg), PATH_MAX);
			break;
		case CURRENT:
			size = read_string(tracee, path, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
			break;
		case ORIGINAL:
			size = read_string(tracee, original, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
			if (size > 0 && size < PATH_MAX) {
				int status = translate_path(tracee, path, AT_FDCWD, original, true);
				if (status < 0)
					return status;
			}
			break;
		default:
			size = 0;
			break;
	}

	if(size < 0)
		return size;
	if(size >= PATH_MAX)
		return -ENAMETOOLONG;

	if(strlen(path) > 0)
		if(!belongs_to_guestfs(tracee, path))
			return 1;

	return 0;
}

char * get_name(char path[PATH_MAX])
{
	char *name;

	name = strrchr(path,'/');
	if (name == NULL)
		name = path;
	else
		name++;

	return name;
}

int get_permissions(char meta_path[PATH_MAX], Config *config, bool uses_real)
{
	int perms;
	int omode;
	mode_t mode;
	uid_t owner, emulated_uid;
	gid_t group, emulated_gid;

	int status = read_meta_file(meta_path, &mode, &owner, &group, config);
	if(status < 0)
		return status;

	if(uses_real) {
		emulated_uid = config->ruid;
		emulated_gid = config->rgid;
	} else {
		emulated_uid = config->euid;
		emulated_gid = config->egid;
	}

	if (emulated_uid == owner || emulated_uid == 0)
		perms = OWNER_PERMS;
	else if(emulated_gid == group)
		perms = GROUP_PERMS;
	else
		perms = OTHER_PERMS;

	omode = dtoo(mode);
	switch(perms) {
	case OWNER_PERMS:
		omode /= 10;
	case GROUP_PERMS:
		omode /= 10;
	case OTHER_PERMS:
		omode = omode % 10;
	}

	if(emulated_uid == 0)
		omode |= 6;
	return omode;
}

int check_dir_perms(Tracee *tracee, char type, char path[PATH_MAX], char rel_path[PATH_MAX], Config *config)
{
	int status, perms;
	char meta_path[PATH_MAX];
	char shorten_path[PATH_MAX];
	int x = 1;
	int w = 2;

	get_dir_path(path, shorten_path);
	status = get_meta_path(shorten_path, meta_path);
	if(status < 0)
		return status;

	perms = get_permissions(meta_path, config, 0);

	if(type == 'w' && (perms & w) != w)
		return -EACCES;

	if(type == 'r' && (perms & x) != x)
		return -EACCES;

	while(strcmp(shorten_path, rel_path) != 0 && strlen(rel_path) < strlen(shorten_path)) {
		get_dir_path(shorten_path, shorten_path);
		if(!belongs_to_guestfs(tracee, shorten_path))
			break;

		status = get_meta_path(shorten_path, meta_path);
		if(status < 0)
			return status;

		perms = get_permissions(meta_path, config, 0);
		if((perms & x) != x)
			return -EACCES;
	}

	return 0;
}

int get_dir_path(char path[PATH_MAX], char dir_path[PATH_MAX])
{
	int offset;

	(void)strcpy(dir_path, path);
	offset = strlen(dir_path) - 1;
	if (offset > 0) {
		while (offset > 1 && dir_path[offset] == '/')
			offset--;

		while (offset > 1 && dir_path[offset] != '/')
			offset--;

		dir_path[offset] = '\0';
	}
	return 0;
}

/* Hashing is allocation-free so staged tree updates cannot register partial keys. */
static void make_meta_key(const char *path, size_t length, char key[48])
{
	uint64_t hash = UINT64_C(1469598103934665603);
	uint64_t hash2 = UINT64_C(0x9e3779b97f4a7c15);
	const unsigned char *cursor;
	for (cursor = (const unsigned char *)path; (size_t)(cursor - (const unsigned char *)path) < length; ++cursor) {
		hash ^= *cursor;
		hash *= UINT64_C(1099511628211);
		hash2 ^= *cursor;
		hash2 *= UINT64_C(0x100000001b3);
		hash2 ^= hash2 >> 29;
	}

	snprintf(key, 48, "@neoproot-meta:%016llx%016llx",
		 (unsigned long long)hash, (unsigned long long)hash2);
}

int get_meta_path(char orig_path[PATH_MAX], char meta_path[PATH_MAX])
{
	char key[48];
	MetaRecord *record;
	size_t length = strnlen(orig_path, PATH_MAX);
	if (length >= PATH_MAX)
		return -ENAMETOOLONG;
	while (length > 1 && orig_path[length - 1] == '/')
		length--;
	make_meta_key(orig_path, length, key);
	record = find_meta_record(key);
	if (record == NULL) {
		/* Register the path without making default metadata appear recorded. */
		record = calloc(1, sizeof(*record) + length + 1);
		if (record == NULL)
			return -ENOMEM;
		memcpy(record->host_path, orig_path, length);
		record->host_path[length] = '\0';
		strcpy(record->key, key);
		record->next = meta_records;
		meta_records = record;
	}
	strcpy(meta_path, key);
	return 0;
}

int read_meta_file(char path[PATH_MAX], mode_t *mode, uid_t *owner, gid_t *group, Config *config)
{
	MetaRecord *record = find_meta_record(path);
	if(record == NULL || !record->recorded) {
		*owner = config->euid;
		*group = config->egid;
		*mode = otod(755);
		return 0;
	}
	*mode = record->mode;
	*owner = record->owner;
	*group = record->group;
	return 0;
}

int write_meta_file(char path[PATH_MAX], mode_t mode, uid_t owner, gid_t group,
	bool is_creat, Config *config)
{
	MetaRecord *record = find_meta_record(path);
	/* All callers obtain opaque keys through get_meta_path(). */
	if (record == NULL)
		return -ENOENT;

	if(is_creat)
		mode = (mode & ~(config->umask) & 0777);

	record->recorded = true;
	record->mode = mode & 07777;
	record->owner = owner;
	record->group = group;
	return 0;
}

int remove_meta_file(char path[PATH_MAX])
{
	MetaRecord *record = find_meta_record(path);
	/* Keep the registration valid for callers holding this opaque key. */
	if (record != NULL)
		record->recorded = false;
	return 0;
}

static bool in_meta_tree(const char *path, const char *root, size_t length)
{
	return strncmp(path, root, length) == 0
		&& (path[length] == '\0' || path[length] == '/'
			|| (length == 1 && root[0] == '/'));
}

int rename_meta_tree(const char *old_path, const char *new_path, bool exchange)
{
	char old_root[PATH_MAX], new_root[PATH_MAX];
	size_t old_length = strnlen(old_path, PATH_MAX);
	size_t new_length = strnlen(new_path, PATH_MAX);
	MetaRecord *staged = NULL;
	int status = -ENOMEM;
	if (old_length >= PATH_MAX || new_length >= PATH_MAX)
		return -ENAMETOOLONG;
	while (old_length > 1 && old_path[old_length - 1] == '/')
		old_length--;
	while (new_length > 1 && new_path[new_length - 1] == '/')
		new_length--;
	/* Normalize locally without modifying the caller's host paths. */
	memcpy(old_root, old_path, old_length);
	old_root[old_length] = '\0';
	memcpy(new_root, new_path, new_length);
	new_root[new_length] = '\0';
	if (strcmp(old_root, new_root) == 0)
		return 0;
	/* Successful kernel renames cannot have overlapping directory roots. */
	if (old_length == 0 || new_length == 0
		|| in_meta_tree(old_root, new_root, new_length)
		|| in_meta_tree(new_root, old_root, old_length))
		return -EINVAL;

	/* Stage every replacement before changing the live table. This also makes
	 * exchange simultaneous, even when both subtrees contain identical suffixes. */
	for (MetaRecord *record = meta_records; record != NULL; record = record->next) {
		const char *target;
		size_t prefix, target_length, suffix_length, length;
		MetaRecord *replacement;
		if (in_meta_tree(record->host_path, old_root, old_length)) {
			prefix = old_length;
			target = new_root;
			target_length = new_length;
		} else if (exchange && in_meta_tree(record->host_path, new_root, new_length)) {
			prefix = new_length;
			target = old_root;
			target_length = old_length;
		} else
			continue;
		if (!record->recorded)
			continue;
		suffix_length = strlen(record->host_path) - prefix;
		length = target_length + suffix_length;
		if (length >= PATH_MAX) {
			status = -ENAMETOOLONG;
			goto rollback;
		}
		replacement = calloc(1, sizeof(*replacement) + length + 1);
		if (replacement == NULL)
			goto rollback;
		memcpy(replacement, record, sizeof(*replacement));
		memcpy(replacement->host_path, target, target_length);
		memcpy(replacement->host_path + target_length,
			record->host_path + prefix, suffix_length + 1);
		make_meta_key(replacement->host_path, length, replacement->key);
		replacement->next = staged;
		staged = replacement;
	}

	/* No allocations or fallible work remain. Clear the whole overwritten
	 * destination even without source records. Keep path registrations valid
	 * for existing callers holding opaque keys, as remove_meta_file() does. */
	for (MetaRecord *record = meta_records; record != NULL; record = record->next)
		if (in_meta_tree(record->host_path, old_root, old_length)
			|| in_meta_tree(record->host_path, new_root, new_length))
			record->recorded = false;
	while (staged != NULL) {
		MetaRecord *record = staged;
		MetaRecord *destination = find_meta_record(record->key);
		staged = record->next;
		if (destination != NULL) {
			destination->mode = record->mode;
			destination->owner = record->owner;
			destination->group = record->group;
			destination->recorded = true;
			free(record);
		} else {
			record->next = meta_records;
			meta_records = record;
		}
	}
	return 0;

rollback:
	while (staged != NULL) {
		MetaRecord *record = staged;
		staged = record->next;
		free(record);
	}
	return status;
}

int rename_meta_file(char old_path[PATH_MAX], char new_path[PATH_MAX])
{
	MetaRecord *record = find_meta_record(old_path);
	MetaRecord *destination = find_meta_record(new_path);
	if (record == NULL || strcmp(old_path, new_path) == 0)
		return 0;
	if (destination == NULL)
		return -ENOENT;
	return rename_meta_tree(record->host_path, destination->host_path, false);
}
