#include <linux/limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/helper_functions.h"

#define META_TAG ".proot-meta-file."

#define OWNER_PERMS  0
#define GROUP_PERMS  1
#define OTHER_PERMS  2

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
	return access(path, F_OK);
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
	char *filename;

	get_dir_path(orig_path, meta_path);
	filename = get_name(orig_path);

	if(strcmp(meta_path, "/") != 0)
		(void)strcat(meta_path, "/");

	if(strlen(meta_path) + strlen(filename) + strlen(META_TAG) >= PATH_MAX)
		return -ENAMETOOLONG;

	(void)strcat(meta_path, META_TAG);
	(void)strcat(meta_path, filename);
	return 0;
}

int read_meta_file(char path[PATH_MAX], mode_t *mode, uid_t *owner, gid_t *group, Config *config)
{
	FILE *fp;
	int lcl_mode;
	fp = fopen(path, "r");
	if(!fp) {
		*owner = config->euid;
		*group = config->egid;
		*mode = otod(755);
		return 0;
	}
	fscanf(fp, "%d %d %d ", &lcl_mode, owner, group);
	lcl_mode = otod(lcl_mode);
	*mode = (mode_t)lcl_mode;
	fclose(fp);
	return 0;
}

int write_meta_file(char path[PATH_MAX], mode_t mode, uid_t owner, gid_t group,
	bool is_creat, Config *config)
{
	FILE *fp;
	fp = fopen(path, "w");
	if(!fp)
		return -1;

	if(is_creat)
		mode = (mode & ~(config->umask) & 0777);

	fprintf(fp, "%d\n%d\n%d\n", dtoo(mode), owner, group);
	fclose(fp);
	return 0;
}
