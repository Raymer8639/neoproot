#include <linux/limits.h>
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
	struct MetaRecord *next;
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
		if (find_meta_record(path) != NULL)
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

	if(!belongs_to_guestfs(tracee, path))
		return 1;

	return 0;
}

int read_sysarg_path(Tracee *tracee, char path[PATH_MAX], Reg path_sysarg, RegVersion version)
{
	int size;
	char original[PATH_MAX];

	switch(version) {
		case MODIFIED:
			size = read_string(tracee, path, peek_reg(tracee, MODIFIED, path_sysarg), PATH_MAX);
			break;
		case CURRENT:
			size = read_string(tracee, path, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
			break;
		case ORIGINAL:
			size = read_string(tracee, original, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
			translate_path(tracee, path, AT_FDCWD, original, true);
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

int get_meta_path(char orig_path[PATH_MAX], char meta_path[PATH_MAX])
{
	uint64_t hash = UINT64_C(1469598103934665603);
	uint64_t hash2 = UINT64_C(0x9e3779b97f4a7c15);
	const unsigned char *cursor;
	int written;

	if (strnlen(orig_path, PATH_MAX) >= PATH_MAX)
		return -EINVAL;

	for (cursor = (const unsigned char *)orig_path; *cursor != '\0'; ++cursor) {
		hash ^= *cursor;
		hash *= UINT64_C(1099511628211);
		hash2 ^= *cursor;
		hash2 *= UINT64_C(0x100000001b3);
		hash2 ^= hash2 >> 29;
	}

	written = snprintf(meta_path, PATH_MAX, "@neoproot-meta:%016llx%016llx",
			   (unsigned long long)hash, (unsigned long long)hash2);
	return written < 0 || written >= PATH_MAX ? -ENAMETOOLONG : 0;
}

int read_meta_file(char path[PATH_MAX], mode_t *mode, uid_t *owner, gid_t *group, Config *config)
{
	MetaRecord *record = find_meta_record(path);
	if(record == NULL) {
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
	if (record == NULL) {
		record = calloc(1, sizeof(*record));
		if (record == NULL)
			return -ENOMEM;
		if (snprintf(record->key, sizeof(record->key), "%s", path) >= (int)sizeof(record->key)) {
			free(record);
			return -ENAMETOOLONG;
		}
		record->next = meta_records;
		meta_records = record;
	}

	if(is_creat)
		mode = (mode & ~(config->umask) & 0777);

	record->mode = mode;
	record->owner = owner;
	record->group = group;
	return 0;
}

int remove_meta_file(char path[PATH_MAX])
{
	MetaRecord **cursor = &meta_records;
	while (*cursor != NULL) {
		if (strcmp((*cursor)->key, path) == 0) {
			MetaRecord *record = *cursor;
			*cursor = record->next;
			free(record);
			return 0;
		}
		cursor = &(*cursor)->next;
	}
	return 0;
}

int rename_meta_file(char old_path[PATH_MAX], char new_path[PATH_MAX])
{
	MetaRecord *record = find_meta_record(old_path);
	MetaRecord *replaced;
	if (record == NULL)
		return 0;
	if (strcmp(old_path, new_path) == 0)
		return 0;
	replaced = find_meta_record(new_path);
	if (replaced != NULL)
		remove_meta_file(new_path);
	if (snprintf(record->key, sizeof(record->key), "%s", new_path) >= (int)sizeof(record->key))
		return -ENAMETOOLONG;
	return 0;
}
