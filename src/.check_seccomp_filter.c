#include <sys/prctl.h>     /* prctl(2), PR_* */
#include <linux/seccomp.h> /* SECCOMP_MODE_FILTER, */
#include <linux/filter.h>  /* struct sock_*, */
#include <linux/audit.h>   /* AUDIT_ARCH_AARCH64, */
#include <stddef.h>        /* offsetof(3), */
#include <stdio.h>         /* perror(3), */
#include <stdlib.h>        /* exit(3), */

int main(void)
{
    const size_t arch_offset    = offsetof(struct seccomp_data, arch);
    const size_t syscall_offset = offsetof(struct seccomp_data, nr);
    struct sock_fprog program;

    // 强制定义为ARM64架构，彻底删除x86相关定义
    #define ARCH_NR AUDIT_ARCH_AARCH64

    // ARM64专属Seccomp过滤规则（严格遵循ARM64 BPF指令集）
    struct sock_filter filter[] = {
        // 1. 加载Seccomp数据中的架构信息并校验
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_offset),
        // 2. 校验是否为ARM64架构，不匹配则直接终止进程
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
        
        // 3. 加载系统调用号
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_offset),
        
        // 4. 自定义系统调用过滤规则（示例：过滤系统调用号0）
        //    格式：BPF_JUMP(操作类型+比较类型+数据大小, 目标值, 匹配时跳转, 不匹配时跳转)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),
        
        // 5. 过滤策略：匹配则跟踪(TRACE)，不匹配则允许(ALLOW)
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
    };

    program.filter = filter;
    program.len = sizeof(filter) / sizeof(struct sock_filter);

    // 启用NO_NEW_PRIVS：禁止子进程获得比父进程更高的权限（安全最佳实践）
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
        exit(EXIT_FAILURE);
    }

    // 应用Seccomp过滤规则
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == -1) {
        perror("prctl(PR_SET_SECCOMP) failed");
        exit(EXIT_FAILURE);
    }

    printf("✅ ARM64 Seccomp filter loaded successfully\n");
    return EXIT_SUCCESS;
}
