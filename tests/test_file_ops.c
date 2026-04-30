#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

/*
 * SciCat PRoot 测试程序 - 测试文件操作
 * 该程序测试基本的文件读写操作
 */

int main()
{
    const char *test_file = "test_output.txt";
    const char *content = "SciCat PRoot 文件操作测试内容\n";
    char buffer[256];
    int fd;
    ssize_t bytes_read;

    printf("开始文件操作测试...\n");

    // 创建并写入文件
    fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("打开文件失败");
        return 1;
    }

    if (write(fd, content, strlen(content)) < 0) {
        perror("写入文件失败");
        close(fd);
        return 1;
    }

    close(fd);
    printf("成功写入文件: %s\n", test_file);

    // 读取文件
    fd = open(test_file, O_RDONLY);
    if (fd < 0) {
        perror("重新打开文件失败");
        return 1;
    }

    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("读取文件失败");
        close(fd);
        return 1;
    }

    buffer[bytes_read] = '\0';
    printf("从文件读取的内容:\n%s", buffer);

    close(fd);

    printf("文件操作测试完成\n");
    return 0;
}