#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include "syscall/socket.h"
#include "syscall/compat_policy.h"
#include "tracee/mem.h"
#include "path/path.h"

static char host_target[PATH_MAX];
static word_t inaccessible_start, inaccessible_end;
int read_data(const Tracee *t, void *out, word_t src, word_t size)
{
    (void)t;
    if (src < 4096) return -EFAULT;
    /* Model tracee read failures without memcpy touching the protected page. */
    if (size && src < inaccessible_end &&
        (src >= inaccessible_start || size > inaccessible_start - src))
        return -EFAULT;
    memcpy(out, (void*)src, size); return 0;
}
int write_data(Tracee *t, word_t dst, const void *in, word_t size)
{ (void)t; if (dst < 4096) return -EFAULT; memcpy((void*)dst, in, size); return 0; }
word_t alloc_mem(Tracee *t, ssize_t size) { return (word_t)talloc_size(t->ctx, size); }
int translate_path(Tracee *t, char out[PATH_MAX], int fd, const char *path, bool follow)
{
    (void)t; (void)fd; (void)follow;
    if (strcmp(path,"missing") == 0 || strcmp(path,"/missing") == 0) return -ENOENT;
    if (strcmp(path,"denied") == 0) return -EACCES;
    strcpy(out,host_target); return 0;
}
static struct sockaddr_un address(const char *name)
{
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    snprintf(sa.sun_path,sizeof(sa.sun_path),"%s",name); return sa;
}
int main(void)
{
    Tracee tr = {0}; tr.pid=getpid(); tr.ctx=talloc_new(NULL);
    char tmp[]="/tmp/neoproot-send-unit.XXXXXX";
    int fd=mkstemp(tmp); assert(fd>=0); close(fd); strcpy(host_target,tmp);
    struct sockaddr_un sa=address("/guest"); word_t ptr=(word_t)&sa;
    assert(translate_send_address(&tr,&ptr,sizeof(sa))==1 && ptr!=(word_t)&sa);
    assert(strcmp(((struct sockaddr_un*)ptr)->sun_path,tmp)==0 && strcmp(sa.sun_path,"/guest")==0);
    sa=address("/missing"); ptr=(word_t)&sa;
    assert(translate_send_address(&tr,&ptr,sizeof(sa))==0 && ptr==(word_t)&sa);
    sa=address("missing"); ptr=(word_t)&sa;
    assert(translate_send_address(&tr,&ptr,sizeof(sa))==-ENOENT);
    sa=address("denied"); ptr=(word_t)&sa;
    assert(translate_send_address(&tr,&ptr,sizeof(sa))==-EACCES);
    sa=address(""); ptr=(word_t)&sa;
    assert(translate_send_address(&tr,&ptr,sizeof(sa))==0);
    sa=address("/guest"); sa.sun_family=AF_INET; ptr=(word_t)&sa;
    assert(translate_send_address(&tr,&ptr,sizeof(sa))==0);
    ptr=1; assert(translate_send_address(&tr,&ptr,sizeof(sa))==-EFAULT);
    sa=address("/guest");
    struct iovec iov={.iov_base=(void*)"x",.iov_len=1};
    struct msghdr msg={.msg_name=&sa,.msg_namelen=sizeof(sa),.msg_iov=&iov,.msg_iovlen=1,.msg_flags=91};
    struct msghdr before=msg; ptr=(word_t)&msg;
    assert(translate_sendmsg_enter(&tr,&ptr)==1);
    struct msghdr *copy=(void*)ptr;
    assert(ptr!=(word_t)&msg && memcmp(&before,&msg,sizeof(msg))==0);
    assert(copy->msg_iov==&iov && copy->msg_iovlen==1 && copy->msg_flags==91);
    assert(strcmp(((struct sockaddr_un*)copy->msg_name)->sun_path,tmp)==0);
    struct sockaddr_un absent=address("missing");
    struct mmsghdr batch[2]={{.msg_hdr=msg},{.msg_hdr=msg}};
    batch[1].msg_hdr.msg_name=&absent; word_t count=2; ptr=(word_t)batch;
    assert(translate_sendmmsg_enter(&tr,&ptr,&count)==1 && count==1 && ptr!=(word_t)batch);
    ((struct mmsghdr*)ptr)[0].msg_len=7;
    assert(translate_sendmmsg_exit(&tr,(word_t)batch,ptr,count)==0 && batch[0].msg_len==7 && batch[1].msg_len==0);
    ptr=1; count=2;
    assert(translate_sendmmsg_enter(&tr,&ptr,&count)==0 && ptr==1 && count==2);

    long page_size=sysconf(_SC_PAGESIZE);
    assert(page_size>0 && (size_t)page_size>=sizeof(struct mmsghdr));
    char *pages=mmap(NULL,2*page_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(pages!=MAP_FAILED);
    struct mmsghdr *edge=(void*)(pages+page_size-sizeof(*edge));
    *edge=(struct mmsghdr){.msg_hdr=msg};
    struct mmsghdr edge_before=*edge;
    assert(mprotect(pages+page_size,page_size,PROT_NONE)==0);
    inaccessible_start=(word_t)(pages+page_size);
    inaccessible_end=(word_t)(pages+2*page_size);
    ptr=(word_t)edge; count=2;
    assert(translate_sendmmsg_enter(&tr,&ptr,&count)==1 && count==1 && ptr!=(word_t)edge);
    struct mmsghdr *prefix=(void*)ptr;
    assert(prefix[0].msg_hdr.msg_name!=&sa);
    assert(strcmp(((struct sockaddr_un*)prefix[0].msg_hdr.msg_name)->sun_path,tmp)==0);
    assert(memcmp(edge,&edge_before,sizeof(*edge))==0);
    prefix[0].msg_len=13;
    assert(translate_sendmmsg_exit(&tr,(word_t)edge,ptr,count)==0 && edge->msg_len==13);
    ptr=inaccessible_start; count=2;
    assert(translate_sendmmsg_enter(&tr,&ptr,&count)==0 && ptr==inaccessible_start && count==2);
    inaccessible_start=inaccessible_end=0;
    assert(munmap(pages,2*page_size)==0);
    assert(valid_no_new_privs_request(PR_GET_NO_NEW_PRIVS,0,0,0,0));
    assert(valid_no_new_privs_request(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    for(unsigned i=0;i<5;i++) assert(!valid_no_new_privs_request(PR_SET_NO_NEW_PRIVS,i,1,0,0));
    assert(!valid_no_new_privs_request(PR_SET_NO_NEW_PRIVS,0,0,0,0));
    assert(!valid_no_new_privs_request(PR_GET_NO_NEW_PRIVS,1,0,0,0));
    assert(!valid_no_new_privs_request(PR_GET_NO_NEW_PRIVS,0,0,0,1));
    assert(empty_path_uses_guest_cwd(AT_FDCWD,"",1,AT_EMPTY_PATH));
    assert(!empty_path_uses_guest_cwd(AT_FDCWD,"",0,AT_EMPTY_PATH));
    assert(!empty_path_uses_guest_cwd(4,"",1,AT_EMPTY_PATH));
    assert(!empty_path_uses_guest_cwd(AT_FDCWD,"x",1,AT_EMPTY_PATH));
    assert(!empty_path_uses_guest_cwd(AT_FDCWD,"",1,0));
    assert(LOADER_ADDRESS >= (128ULL<<30) && LOADER_ADDRESS >= (336ULL<<30));
    assert(LOADER_ADDRESS < EXEC_PIC_ADDRESS && EXEC_PIC_ADDRESS < INTERP_PIC_ADDRESS && INTERP_PIC_ADDRESS < (512ULL<<30));
    unlink(tmp); talloc_free(tr.ctx); puts("PASS upstream socket destination, partial batch, privilege argument, empty-path and ARM64 layout units");
}
