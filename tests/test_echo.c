#include <stdio.h>
#include <unistd.h>
#include <string.h>

/*
 * SciCat PRoot 测试程序 - 测试基本输出功能
 * 该程序输出一些信息并测试标准输出
 */

int main()
{
    const char *message = "SciCat PRoot 基本输出测试\n";
    
    // 使用 write 系统调用
    write(STDOUT_FILENO, message, strlen(message));
    
    // 使用 printf
    printf("使用 printf 输出测试\n");
    
    // 测试返回值
    return 42;  // 使用非零返回值进行测试
}