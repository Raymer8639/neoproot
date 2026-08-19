#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int create_file(const char *path)
{
	int fd = open(path, O_CREAT | O_WRONLY, 0600);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

int main(void)
{
	DIR *dir;
	struct dirent *entry;
	unsigned int fake_type = 255;
	unsigned int real_type = 255;

	if (mkdir("work", 0700) < 0 || chdir("work") < 0)
		return 1;
	if (create_file("source") < 0 || link("source", "fake") < 0 ||
	    symlink("source", "real-link") < 0)
		return 1;

	dir = opendir(".");

	if (dir == NULL)
		return 1;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, "fake") == 0)
			fake_type = entry->d_type;
		else if (strcmp(entry->d_name, "real-link") == 0)
			real_type = entry->d_type;
	}
	closedir(dir);

	printf("fake=%u real=%u\n", fake_type, real_type);
	return fake_type == 255 || real_type == 255;
}
