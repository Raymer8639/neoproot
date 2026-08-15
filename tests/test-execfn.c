/* AT_EXECFN 修复回归测试
 *
 * 双通道验证：
 *   1) getauxval(AT_EXECFN) —— 读栈上 auxv（loader 修补的通道）
 *   2) read(/proc/self/auxv) —— 读绑定文件（bind_proc_pid_auxv 填充，
 *      其内容取自 guest 栈上 auxv，loader 修好后自动正确）
 * 期望：两通道的 AT_EXECFN 都等于 argv[0]（真实程序名），
 * 而不是 loader 临时路径。 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/auxv.h>

#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif

int main(int argc, char **argv)
{
    int fail = 0;

    /* 通道 1：getauxval（栈上 auxv） */
    const char *ef = (const char *)getauxval(AT_EXECFN);
    printf("getauxval AT_EXECFN: %s\n", ef ? ef : "(null)");
    if (!ef || strcmp(ef, argv[0]) != 0)
        fail++;

    /* 通道 2：/proc/self/auxv 读
     * 修复方式：enter 侧把 open(/proc/self/auxv) 路径改写为生成的
     * 正确内容临时文件（绕过 -b /proc 绑定优先级）。 */
    FILE *f = fopen("/proc/self/auxv", "rb");
    if (f) {
        unsigned long type, value;
        int found = 0;
        while (fread(&type, sizeof(type), 1, f) == 1 &&
               fread(&value, sizeof(value), 1, f) == 1) {
            if (type == AT_NULL)
                break;
            if (type == AT_EXECFN) {
                const char *p = (const char *)value;
                printf("proc/self/auxv AT_EXECFN: %s\n", p);
                if (strcmp(p, argv[0]) != 0)
                    fail++;
                found = 1;
                break;
            }
        }
        fclose(f);
        if (!found)
            fail++;
    } else {
        fail++;
    }

    printf(fail ? "RESULT: FAIL (%d)\n" : "RESULT: ALL PASS\n", fail);
    return fail ? 1 : 0;
}
