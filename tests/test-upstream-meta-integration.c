#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE 2
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
static void require(int ok,const char *message) { if(!ok) { fprintf(stderr,"FAIL %s errno=%d (%s)\n",message,errno,strerror(errno)); exit(1); } }
static void create_file(const char *path)
{ int fd=open(path,O_CREAT|O_EXCL|O_RDWR,0600); require(fd>=0,"create isolated file"); require(write(fd,"x",1)==1,"write isolated file"); close(fd); }
static void metadata(const char *path,mode_t mode,uid_t uid,gid_t gid)
{
    struct stat st; require(stat(path,&st)==0,"stat metadata");
    require(S_ISREG(st.st_mode) && (st.st_mode&07777)==mode && st.st_uid==uid && st.st_gid==gid,"stat mode/type/IDs");
    int fd=open(path,O_RDONLY); require(fd>=0,"open metadata file");
    require(fstat(fd,&st)==0 && S_ISREG(st.st_mode) && (st.st_mode&07777)==mode && st.st_uid==uid && st.st_gid==gid,"fstat chained metadata");
    require(fstatat(fd,"",&st,AT_EMPTY_PATH)==0 && S_ISREG(st.st_mode) && (st.st_mode&07777)==mode && st.st_uid==uid && st.st_gid==gid,"fstatat empty-fd metadata");
    struct statx sx={0};
    require(syscall(SYS_statx,AT_FDCWD,path,0,STATX_TYPE|STATX_MODE|STATX_UID|STATX_GID,&sx)==0,"statx metadata");
    require(S_ISREG(sx.stx_mode) && (sx.stx_mode&07777)==mode && sx.stx_uid==uid && sx.stx_gid==gid,"statx mode/type/IDs");
    memset(&sx,0,sizeof(sx));
    require(syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_TYPE|STATX_MODE|STATX_UID|STATX_GID,&sx)==0,"statx empty-fd metadata");
    require(S_ISREG(sx.stx_mode) && (sx.stx_mode&07777)==mode && sx.stx_uid==uid && sx.stx_gid==gid,"statx empty-fd mode/type/IDs"); close(fd);
}
static void set_record(const char *path,mode_t mode,uid_t uid,gid_t gid)
{ require(chown(path,uid,gid)==0,"virtual chown"); require(chmod(path,mode)==0,"virtual chmod"); metadata(path,mode,uid,gid); }
static int native_capability(const char *path)
{
    pid_t child=fork(); require(child>=0,"fork native 452 capability probe");
    if(child==0) {
        struct rlimit no_core={0}; (void)setrlimit(RLIMIT_CORE,&no_core);
        create_file(path); errno=0;
        int result=syscall(SYS_fchmodat2,AT_FDCWD,path,0600,0),error=errno;
        _exit(result==0 ? 0 : error==ENOSYS ? 77 : 78);
    }
    int status; while(waitpid(child,&status,0)<0) require(errno==EINTR,"wait native 452 probe");
    unlink(path);
    if(WIFSIGNALED(status) && WTERMSIG(status)==SIGSYS) return 0;
    if(WIFEXITED(status) && WEXITSTATUS(status)==77) return 0;
    require(WIFEXITED(status) && WEXITSTATUS(status)==0,"native fchmodat2 capability");
    return 1;
}
static void tracee(int native_fchmodat2)
{
    require(geteuid()==0 && getegid()==0,"real -0 tracee identity");
    create_file("a"); create_file("b"); set_record("a",04751,13001,24001); set_record("b",0640,13002,24002);
    int fd=open("a",O_PATH); require(fd>=0,"O_PATH for failed chmod"); errno=0;
    require(fchmod(fd,0700)==-1 && errno==EBADF,"failed fchmod O_PATH"); close(fd); metadata("a",04751,13001,24001);
    errno=0; int rc=syscall(SYS_fchmodat2,AT_FDCWD,"a",0641,0),error=errno;
    if(!native_fchmodat2) { require(rc==-1 && error==ENOSYS,"unsupported fchmodat2 unchanged"); metadata("a",04751,13001,24001); puts("SKIP native kernel/Android policy fchmodat2 unavailable"); }
    else { require(rc==0,"supported fchmodat2"); metadata("a",0641,13001,24001); require(chmod("a",04751)==0,"restore virtual mode"); }
    errno=0; rc=syscall(SYS_fchmodat2,AT_FDCWD,"a",0777,0x80000000U); error=errno;
    require(rc==-1 && (error==EINVAL || (!native_fchmodat2 && error==ENOSYS)),"invalid fchmodat2 flags"); metadata("a",04751,13001,24001);
    require(symlink("a","soft")==0,"symlink mode guard"); errno=0;
    rc=syscall(SYS_fchmodat2,AT_FDCWD,"soft",0777,AT_SYMLINK_NOFOLLOW); error=errno;
    require(rc==-1 && (error==EOPNOTSUPP || error==EINVAL || (!native_fchmodat2 && error==ENOSYS)),"nofollow chmod failure"); metadata("a",04751,13001,24001);
    errno=0; require(syscall(SYS_renameat2,AT_FDCWD,"a",AT_FDCWD,"b",RENAME_NOREPLACE)==-1 && errno==EEXIST,"failed rename no-replace");
    metadata("a",04751,13001,24001); metadata("b",0640,13002,24002);
    require(rename("a","a")==0,"rename same path no-op"); metadata("a",04751,13001,24001);
    require(syscall(SYS_renameat2,AT_FDCWD,"a",AT_FDCWD,"b",RENAME_EXCHANGE)==0,"exchange files");
    metadata("a",0640,13002,24002); metadata("b",04751,13001,24001);
    require(mkdir("d1",0700)==0 && mkdir("d1/sub",0700)==0 && mkdir("d2",0700)==0 && mkdir("d2/sub",0700)==0,"directory fixtures");
    create_file("d1/sub/item"); create_file("d2/sub/item"); set_record("d1/sub/item",0400,13003,24003); set_record("d2/sub/item",0600,13004,24004);
    require(rename("d1","moved")==0,"rename directory subtree"); metadata("moved/sub/item",0400,13003,24003);
    require(syscall(SYS_renameat2,AT_FDCWD,"moved",AT_FDCWD,"d2",RENAME_EXCHANGE)==0,"exchange directory subtrees");
    metadata("moved/sub/item",0600,13004,24004); metadata("d2/sub/item",0400,13003,24003);
    errno=0; require(rename("moved","d2")==-1 && (errno==ENOTEMPTY || errno==EEXIST),"failed populated directory replacement");
    metadata("moved/sub/item",0600,13004,24004); metadata("d2/sub/item",0400,13003,24003);
    create_file("owner-access"); require(chmod("owner-access",0000)==0,"virtual zero mode"); struct stat st;
    require(stat("owner-access",&st)==0 && S_ISREG(st.st_mode) && (st.st_mode&07777)==0,"virtual owner access mode");
    puts("PASS real USERLAND -0 metadata: chmod failures, typed stat APIs, rename/exchange and descendants");
}
static void native_check(const char *directory)
{
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/owner-access",directory); struct stat st;
    require(stat(path,&st)==0 && S_ISREG(st.st_mode) && (st.st_mode&0600)==0600,"native owner access retained");
    DIR *dir=opendir(directory); require(dir!=NULL,"native fixture scan"); struct dirent *entry;
    while((entry=readdir(dir))!=NULL) require(strncmp(entry->d_name,".proot-meta",11)!=0,"no metadata sidecars"); closedir(dir);
    puts("PASS native owner access and no metadata sidecars");
}
int main(int argc,char **argv)
{
    require(argc==3,"integration arguments");
    if(strcmp(argv[1],"native")==0) printf("%d\n",native_capability(argv[2]));
    else if(strcmp(argv[1],"tracee")==0) tracee(atoi(argv[2]));
    else if(strcmp(argv[1],"check")==0) native_check(argv[2]);
    else abort(); return 0;
}
