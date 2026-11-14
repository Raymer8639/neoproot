#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s (errno=%d)\n",__LINE__,#x,errno); return 1; } } while(0)
static int create(const char *name) {
    int fd=open(name,O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0) return -1;
    int result=write(fd,"payload",7)==7?0:-1;
    if(close(fd)<0) result=-1;
    return result;
}
static int links(const char *name,int expected) {
    struct stat st;
    if(stat(name,&st)<0 || !S_ISREG(st.st_mode) || st.st_nlink!=(nlink_t)expected) {
        fprintf(stderr,"%s: expected %d links\n",name,expected); return 0;
    }
    return 1;
}
static int fd_name(int fd,const char *expected) {
    char proc[80],name[PATH_MAX];
    snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(proc,name,sizeof(name)-1);
    if(n<0) return 0;
    name[n]=0;
    if(strcmp(name,expected)) { fprintf(stderr,"fd: [%s] expected [%s]\n",name,expected); return 0; }
    return 1;
}
int main(int argc,char **argv) {
    if(argc==4 && !strcmp(argv[1],"link-error")) {
        if(link(argv[2],argv[3])==0) return 0;
        return errno;
    }
    CHECK(argc==2 && chdir(argv[1])==0);
    CHECK(create("a")==0 && link("a","b")==0 && links("a",2));
    CHECK(unlinkat(AT_FDCWD,"b",AT_REMOVEDIR)<0 && errno==ENOTDIR && links("a",2));
    CHECK(rename("missing","b")<0 && errno==ENOENT && links("a",2));
#ifdef SYS_renameat2
    errno=0;
    long result=syscall(SYS_renameat2,AT_FDCWD,"a",AT_FDCWD,"b",1);
    CHECK(result<0 && (errno==EEXIST || errno==ENOSYS));
    CHECK(links("a",2) && links("b",2));
    result=syscall(SYS_renameat2,AT_FDCWD,"a",AT_FDCWD,"b",2);
    CHECK(result==0 || (result<0 && errno==ENOSYS));
    CHECK(links("a",2) && links("b",2));
#endif
    CHECK(rename("a","b")==0 && access("a",F_OK)==0 && access("b",F_OK)==0);
    CHECK(links("a",2) && linkat(AT_FDCWD,"b",AT_FDCWD,"c",AT_SYMLINK_FOLLOW)==0);
    CHECK(links("a",3) && links("c",3));
    CHECK(linkat(AT_FDCWD,"b",AT_FDCWD,"c",AT_SYMLINK_FOLLOW)<0 && errno==EEXIST);
    CHECK(links("a",3));
    CHECK(create("replacement")==0 && rename("replacement","a")==0);
    CHECK(links("b",2) && unlink("b")==0 && links("c",1));
    CHECK(symlink("/guest-only/target","symbolic")==0 && link("symbolic","symbolic-copy")==0);
    char content[PATH_MAX];
    ssize_t n=readlink("symbolic-copy",content,sizeof(content)-1);
    CHECK(n>0); content[n]=0; CHECK(!strcmp(content,"/guest-only/target"));
    struct stat st; CHECK(lstat("symbolic-copy",&st)==0 && S_ISLNK(st.st_mode));
    CHECK(symlink("../relative","relative")==0 && link("relative","relative-copy")==0);
    n=readlink("relative-copy",content,sizeof(content)-1);
    CHECK(n>0); content[n]=0; CHECK(!strcmp(content,"../relative"));
    /* Relative opens preserve the custom materialization policy's shared chain. */
    char expected[PATH_MAX]; CHECK(getcwd(expected,sizeof(expected))!=NULL);
    CHECK(strlen(expected)+3<sizeof(expected)); strcat(expected,"/c");
    int fd=open("c",O_RDONLY|O_NOFOLLOW); CHECK(fd>=0 && fd_name(fd,expected));
    CHECK(dup2(fd,31)==31 && close(fd)==0 && fd_name(31,expected));
    pid_t child=fork(); CHECK(child>=0);
    if(child==0) _exit(fd_name(31,expected)?0:1);
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(close(31)==0);
    CHECK(symlink("c","alias")==0);
    fd=open("alias",O_RDONLY); CHECK(fd>=0 && fd_name(fd,expected)); CHECK(close(fd)==0);
    /* An O_PATH request may materialize c; its reported name remains c. */
    fd=open("c",O_PATH|O_NOFOLLOW); CHECK(fd>=0 && fd_name(fd,expected)); CHECK(close(fd)==0);
    puts("upstream link2symlink host integration regressions passed");
    return 0;
}
