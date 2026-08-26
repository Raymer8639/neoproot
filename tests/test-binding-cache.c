#include <sys/stat.h>

int main(void)
{
	struct stat st;

	for (int i = 0; i < 128; i++) {
		if (stat("/probe", &st) < 0)
			return 1;
	}
	return 0;
}
