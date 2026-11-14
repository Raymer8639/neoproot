#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/stat.h>
static void require(int ok,const char *message) { if(!ok) { perror(message); exit(1); } }
static void privilege(int expected)
{
    require(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==expected,"inherited no_new_privs");
    for(int i=0;i<4;i++) {
        unsigned long args[4]={0}; args[i]=1; errno=0;
        require(prctl(PR_GET_NO_NEW_PRIVS,args[0],args[1],args[2],args[3])==-1 && errno==EINVAL,"invalid privilege GET");
        unsigned long set[4]={1,0,0,0}; set[i]=i==0?2:1; errno=0;
        require(prctl(PR_SET_NO_NEW_PRIVS,set[0],set[1],set[2],set[3])==-1 && errno==EINVAL,"invalid privilege SET");
        require(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==expected,"invalid SET changed virtual state");
    }
    errno=0; require(prctl(0xdeadbeef,0,0,0,0)==-1 && errno==EINVAL,"ordinary prctl error");
    require(prctl(PR_GET_DUMPABLE,0,0,0,0)>0,"ordinary prctl positive result");
    require(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0,"valid SET");
    require(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1,"GET after SET");
}
static void link_result(const char *path,const char *expected)
{
    size_t length=strlen(expected);
    for(size_t cap=1;cap<=length+8;cap++) {
        unsigned char buf[PATH_MAX+1]; memset(buf,0xa5,sizeof(buf));
        ssize_t n=readlink(path,(char*)buf,cap); size_t want=length<cap?length:cap;
        require(n==(ssize_t)want && memcmp(buf,expected,want)==0,"readlink length/content");
        require(buf[want]==0xa5,"readlink wrote beyond returned bytes");
    }
}
static void readonly_link(const char *path)
{
    size_t page_size = sysconf(_SC_PAGESIZE);
    unsigned char *buffer = mmap(NULL,page_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    require(buffer != MAP_FAILED,"readonly output mmap"); memset(buffer,0xa5,page_size);
    require(mprotect(buffer,page_size,PROT_READ)==0,"readonly output mprotect");
    errno=0; require(readlink(path,(char *)buffer,32)==-1 && errno==EFAULT,"readlink readonly output must fail");
    for(size_t i=0;i<page_size;i++) require(buffer[i]==0xa5,"readlink modified readonly output");
    munmap(buffer,page_size);
}
static void paths(void)
{
    int fd=open("file",O_CREAT|O_RDWR|O_TRUNC,0600); require(fd>=0,"fixture open");
    char proc[128]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
    link_result(proc,"/case/file");
    readonly_link(proc);
    link_result("relative-link","file");
    readonly_link("relative-link");
    snprintf(proc,sizeof(proc),"/proc/%d/task/%ld/fd/%d",getpid(),syscall(SYS_gettid),fd);
    link_result(proc,"/case/file");
    struct stat cwd,empty; require(stat(".",&cwd)==0,"cwd stat");
    require(fstatat(AT_FDCWD,"",&empty,AT_EMPTY_PATH)==0 && empty.st_ino==cwd.st_ino && empty.st_dev==cwd.st_dev,"empty path guest cwd");
#ifdef SYS_statx
    struct statx sx; require(syscall(SYS_statx,AT_FDCWD,"",AT_EMPTY_PATH,STATX_INO,&sx)==0 && sx.stx_ino==cwd.st_ino,"statx empty cwd");
#endif
    close(fd);
}
static struct sockaddr_un named(const char *path) { struct sockaddr_un sa={.sun_family=AF_UNIX}; snprintf(sa.sun_path,sizeof(sa.sun_path),"%s",path); return sa; }
static void expect_datagrams(int receiver, int count)
{
    char data[8];
    for(int i=0;i<count;i++) require(recv(receiver,data,sizeof(data),MSG_DONTWAIT)==1,"expected batch datagram");
    errno=0; require(recv(receiver,data,sizeof(data),MSG_DONTWAIT)==-1 &&
            (errno==EAGAIN || errno==EWOULDBLOCK),"batch sent beyond first output fault");
}
static void batch_permissions(int sender,int receiver,const struct msghdr *message)
{
    size_t page = sysconf(_SC_PAGESIZE);
    unsigned char *memory = mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    require(memory!=MAP_FAILED,"batch permission mmap");
    struct mmsghdr *batch=(void*)memory;
    for(int i=0;i<2;i++) batch[i]=(struct mmsghdr){.msg_hdr=*message};
    require(mprotect(memory,2*page,PROT_READ)==0,"batch readonly");
    errno=0; require(sendmmsg(sender,batch,2,0)==-1 && errno==EFAULT,"readonly batch output errno");
    expect_datagrams(receiver,1);
    require(mprotect(memory,2*page,PROT_READ|PROT_WRITE)==0,"restore batch pages");
    batch=(void*)(memory+page-sizeof(*batch));
    for(int i=0;i<3;i++) batch[i]=(struct mmsghdr){.msg_hdr=*message};
    require(mprotect(memory+page,page,PROT_READ)==0,"later batch readonly");
    require(sendmmsg(sender,batch,3,0)==1 && batch[0].msg_len==1 && batch[1].msg_len==0,"later readonly batch prefix");
    expect_datagrams(receiver,2);
    require(mprotect(memory+page,page,PROT_READ|PROT_WRITE)==0,"restore batch pages");
    batch=(void*)(memory+page-sizeof(*batch)); batch[0]=(struct mmsghdr){.msg_hdr=*message};
    require(mprotect(memory+page,page,PROT_NONE)==0,"later batch inaccessible");
    require(sendmmsg(sender,batch,2,0)==1 && batch[0].msg_len==1,"inaccessible later header prefix");
    expect_datagrams(receiver,1);
    require(mprotect(memory+page,page,PROT_READ|PROT_WRITE)==0,"restore batch pages");
    batch=(void*)(memory+page-__builtin_offsetof(struct mmsghdr,msg_len));
    *batch=(struct mmsghdr){.msg_hdr=*message};
    require(mprotect(memory+page,page,PROT_NONE)==0,"first output inaccessible");
    errno=0; require(sendmmsg(sender,batch,1,0)==-1 && errno==EFAULT,"inaccessible first msg_len errno");
    expect_datagrams(receiver,1);
    munmap(memory,2*page);
}
static void native_socket_permissions(void)
{
    int pair[2]; require(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)==0,"native socketpair");
    struct iovec iov={.iov_base=(void*)"n",.iov_len=1};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    batch_permissions(pair[0],pair[1],&message); close(pair[0]); close(pair[1]);
}
static void sockets(void)
{
    int receiver=socket(AF_UNIX,SOCK_DGRAM,0),sender=socket(AF_UNIX,SOCK_DGRAM,0);
    require(receiver>=0&&sender>=0,"sockets"); struct sockaddr_un addr=named("/case/receiver"); unlink(addr.sun_path);
    require(bind(receiver,(void*)&addr,sizeof(addr))==0,"bind guest socket");
    char buf[8];
    require(sendto(sender,"a",1,0,(void*)&addr,sizeof(addr))==1,"sendto guest destination"); require(recv(receiver,buf,sizeof(buf),0)==1&&buf[0]=='a',"recv sendto");
    struct iovec iov={.iov_base=(void*)"b",.iov_len=1};
    struct msghdr msg={.msg_name=&addr,.msg_namelen=sizeof(addr),.msg_iov=&iov,.msg_iovlen=1};
    struct msghdr before=msg; require(sendmsg(sender,&msg,0)==1,"sendmsg guest destination");
    require(memcmp(&before,&msg,sizeof(msg))==0,"sendmsg altered input header"); require(recv(receiver,buf,sizeof(buf),0)==1&&buf[0]=='b',"recv sendmsg");
    struct mmsghdr batch[2]={{.msg_hdr=msg},{.msg_hdr=msg}};
    require(sendmmsg(sender,batch,2,0)==2 && batch[0].msg_len==1 && batch[1].msg_len==1,"sendmmsg lengths");
    for(int i=0;i<2;i++) require(recv(receiver,buf,sizeof(buf),0)==1,"recv sendmmsg");
    batch_permissions(sender,receiver,&msg);
    close(sender); close(receiver); unlink(addr.sun_path);
}
static int large_mapping(void)
{
    size_t size=256ULL<<30; void *p=mmap(NULL,size,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);
    if(p==MAP_FAILED) return 0; munmap(p,size); return 1;
}
int main(int argc,char **argv)
{
    require(argc>=2,"mode");
    if(strcmp(argv[1],"native-privilege")==0) { printf("%d\n",prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)); return 0; }
    if(strcmp(argv[1],"native-mapping")==0) { printf("%d\n",large_mapping()); return 0; }
    if(strcmp(argv[1],"socket-permissions")==0) native_socket_permissions();
    else if(strcmp(argv[1],"permissions")==0) readonly_link(argv[2]);
    else if(strcmp(argv[1],"privilege")==0) privilege(atoi(argv[2]));
    else if(strcmp(argv[1],"paths")==0) paths();
    else if(strcmp(argv[1],"sockets")==0) sockets();
    else if(strcmp(argv[1],"mapping")==0) require(large_mapping() || atoi(argv[2])==0,"large ARM64 VM reservation");
    else abort();
    printf("PASS upstream compatibility %s\n",argv[1]); return 0;
}
