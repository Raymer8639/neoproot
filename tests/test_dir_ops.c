#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

/*
 * SciCat PRoot 测试程序 - 测试目录操作
 * 该程序测试目录创建、读取等操作
 */

int main()
{
    const char *test_dir = "test_directory";
    const char *test_file = "test_directory/test_file.txt";
    DIR *dir;
    struct dirent *entry;
    
    printf("开始目录操作测试...\n");

    // 创建目录
    if (mkdir(test_dir, 0755) < 0) {
        perror("创建目录失败");
        return 1;
    }
    printf("成功创建目录: %s\n", test_dir);

    // 在目录中创建文件
    int fd = open(test_file, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        perror("在测试目录中创建文件失败");
        rmdir(test_dir);
        return 1;
    }
    
    const char *content = "目录测试文件内容\n";
    write(fd, content, strlen(content));
    close(fd);
    printf("在目录中创建文件: %s\n", test_file);

    // 读取目录内容
    dir = opendir(test_dir);
    if (dir == NULL) {
        perror("打开目录失败");
        rmdir(test_dir);
        return 1;
    }

    printf("目录 %s 的内容:\n", test_dir);
    while ((entry = readdir(dir)) != NULL) {
        printf("  %s\n", entry->d_name);
    }
closedir(dir);

    // 清理
    unlink(test_file);
    if (rmdir(test_dir) < 0) {
        perror("删除目录失败");
        return 1;
    }
    printf("成功清理测试目录\n");

    printf("目录操作测试完成\n");
    return 0;
}