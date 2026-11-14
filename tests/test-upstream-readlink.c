#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "syscall/readlink_result.h"
static word_t regs[NB_REG_VERSION][USERARG_1+1];
static bool fail_alloc;
word_t peek_reg(const Tracee *t, RegVersion v, Reg r) { (void)t; return regs[v][r]; }
void poke_reg(Tracee *t, Reg r, word_t value) { (void)t; regs[CURRENT][r]=value; }
word_t alloc_mem(Tracee *t, ssize_t n) { return fail_alloc ? 0 : (word_t)talloc_size(t->ctx,n); }
int read_data(const Tracee *t,void *out,word_t source,word_t n)
{ (void)t; if(source<4096)return -EFAULT; memcpy(out,(void*)source,n); return 0; }
int write_data(Tracee *t,word_t target,const void *in,word_t n)
{ (void)t; if(target<4096)return -EFAULT; memcpy((void*)target,in,n); return 0; }
int main(void)
{
    Tracee tr={0}; tr.pid=getpid(); tr.ctx=talloc_new(NULL);
    const char host[]="/very/long/host/root/guest/file";
    const char guest[]="/g/file";
    for(int is_at=0;is_at<2;is_at++) {
        Reg output=is_at?SYSARG_3:SYSARG_2, size=is_at?SYSARG_4:SYSARG_3;
        for(size_t cap=1;cap<=sizeof(host)+1;cap++) {
            unsigned char user[PATH_MAX+1]; memset(user,0xa5,sizeof(user));
            memset(regs,0,sizeof(regs)); regs[CURRENT][output]=(word_t)user; regs[CURRENT][size]=cap;
            memcpy(regs[ORIGINAL],regs[CURRENT],sizeof(regs[CURRENT]));
            assert(prepare_readlink_output(&tr,output,size)==0);
            assert(regs[CURRENT][output]!=(word_t)user && tr.sysexit_pending && tr.restart_how==PTRACE_SYSCALL);
            memcpy(regs[MODIFIED],regs[CURRENT],sizeof(regs[CURRENT]));
            size_t kernel_count=strlen(host)<cap?strlen(host):cap;
            memcpy((void*)regs[MODIFIED][output],host,kernel_count);
            for(size_t i=0;i<sizeof(user);i++) assert(user[i]==0xa5);
            size_t result=strlen(guest)<cap?strlen(guest):cap;
            assert(write_readlink_output(&tr,(word_t)user,guest,result)==0);
            assert(memcmp(user,guest,result)==0 && user[result]==0xa5);
            memset(user,0xa5,sizeof(user));
            assert(copy_raw_readlink_output(&tr,output,kernel_count)==0);
            assert(memcmp(user,host,kernel_count)==0 && user[kernel_count]==0xa5);
        }
        regs[CURRENT][output]=0; regs[CURRENT][size]=1;
        assert(prepare_readlink_output(&tr,output,size)==0 && regs[CURRENT][output]==0);
        regs[CURRENT][output]=1; regs[CURRENT][size]=0;
        assert(prepare_readlink_output(&tr,output,size)==0 && regs[CURRENT][output]==1);
        regs[CURRENT][output]=1; regs[CURRENT][size]=PATH_MAX+100;
        fail_alloc=true; assert(prepare_readlink_output(&tr,output,size)==-EFAULT); fail_alloc=false;
        assert(prepare_readlink_output(&tr,output,size)==0 && regs[CURRENT][size]==PATH_MAX);
        regs[ORIGINAL][output]=1; memcpy(regs[MODIFIED],regs[CURRENT],sizeof(regs[CURRENT]));
        assert(copy_raw_readlink_output(&tr,output,1)==-EFAULT);
    }
    size_t page_size = sysconf(_SC_PAGESIZE);
    unsigned char *readonly = mmap(NULL,page_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(readonly != MAP_FAILED); memset(readonly,0xa5,page_size);
    assert(mprotect(readonly,page_size,PROT_READ)==0);
    assert(write_readlink_output(&tr,(word_t)readonly,guest,strlen(guest))==-EFAULT);
    for(size_t i=0;i<page_size;i++) assert(readonly[i]==0xa5);
    regs[ORIGINAL][SYSARG_2]=(word_t)readonly;
    regs[MODIFIED][SYSARG_2]=(word_t)host;
    assert(copy_raw_readlink_output(&tr,SYSARG_2,strlen(host))==-EFAULT);
    for(size_t i=0;i<page_size;i++) assert(readonly[i]==0xa5);
    munmap(readonly,page_size);
    talloc_free(tr.ctx); puts("PASS actual readlink staging: original canaries, raw byte counts, zero/null/fault limits");
}
