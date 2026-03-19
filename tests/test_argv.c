#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * SciCat PRoot 测试程序 - 测试命令行参数处理
 * 该程序显示接收到的所有命令行参数
 */

int main(int argc, char *argv[])
{
    int i;

    printf("SciCat PRoot 测试 - 参数计数: %d\n", argc);
    
    for (i = 0; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }

    // 额外测试一些基本功能
    printf("当前工作目录: ");
    fflush(stdout);
    if (system("pwd") != 0) {
        printf("(无法获取)\n");
    }

    return 0;
}