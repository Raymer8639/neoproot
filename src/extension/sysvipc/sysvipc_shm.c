#include "sysvipc.h"
#include "sysvipc_internal.h"

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/tracee.h"
#include "extension/extension.h"
#include "path/temp.h"
#include "syscall/chain.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <syscall.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/param.h>

#ifdef __ANDROID__
#include <linux/ashmem.h>
#endif

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))
#define NORETURN __attribute__((noreturn))

#define SYSVIPC_MAX_SHM_SIZE        (100U * 4096U)
#define SYSVIPC_SHMHELPER_SOCKET_LEN 108U

struct SysVIpcRecvMsgPointers {
    word_t msghdr_ptr;
    word_t cmsg_controllen_ptr;
    word_t cmsg_control_ptr;
};

enum SysVIpcShmHelperRequestOp {
    SHMHELPER_DISTRIBUTE,
    SHMHELPER_ALLOC,
    SHMHELPER_FREE
};

struct SysVIpcShmHelperRequest {
    enum SysVIpcShmHelperRequestOp op;
    int fd;
    size_t size;
};

static struct sockaddr_un sysvipc_shm_helper_addr;
static bool sysvipc_shm_helper_initialized = false;
static int proot2helper_fd = -1;
static int helper2proot_fd = -1;
static size_t page_size_cache = 0;

static ALWAYS_INLINE size_t get_page_size(void) {
    if (UNLIKELY(page_size_cache == 0))
        page_size_cache = (size_t)sysconf(_SC_PAGESIZE);
    return page_size_cache;
}

// 简化版：仅64位，无32位兼容
int sysvipc_shm_recvmsg_pointers(Tracee *restrict tracee,
                                 struct SysVIpcRecvMsgPointers *restrict out_pointers,
                                 word_t guest_buf, bool do_write) {
    if (UNLIKELY(!tracee || !out_pointers)) return -EINVAL;
    const word_t ptr_len = 8;  // 64-bit
    const word_t buf_end = guest_buf + sizeof(struct sockaddr_un);
    const word_t data_addr = buf_end - 4;
    const word_t data_iov_length = data_addr - ptr_len;
    const word_t data_iov_addr = data_iov_length - ptr_len;
    const word_t msghdr_flags = data_iov_addr - ptr_len;
    const word_t msghdr_controllen = msghdr_flags - ptr_len;
    const word_t msghdr_control = msghdr_controllen - ptr_len;
    const word_t msghdr_iovlen = msghdr_control - ptr_len;
    const word_t msghdr_iov = msghdr_iovlen - ptr_len;
    const word_t msghdr = msghdr_iov - ptr_len * 2;

    if (do_write) {
        char data[sizeof(struct sockaddr_un)] = {0};
        *(uint64_t *)(data + (data_iov_addr - guest_buf)) = data_addr;
        *(uint64_t *)(data + (data_iov_length - guest_buf)) = 1ULL;
        *(uint64_t *)(data + (msghdr_iov - guest_buf)) = data_iov_addr;
        *(uint64_t *)(data + (msghdr_iovlen - guest_buf)) = 1ULL;
        *(uint64_t *)(data + (msghdr_control - guest_buf)) = guest_buf;
        *(uint64_t *)(data + (msghdr_controllen - guest_buf)) = 20ULL;
        int st = write_data(tracee, guest_buf, data, sizeof(data));
        if (UNLIKELY(st < 0)) return st;
    }
    out_pointers->msghdr_ptr = msghdr;
    out_pointers->cmsg_controllen_ptr = msghdr_controllen;
    out_pointers->cmsg_control_ptr = guest_buf;
    return 0;
}

static int sysvipc_shm_launch_helper(void) {
    if (LIKELY(sysvipc_shm_helper_initialized)) return 0;
    int pipe_proot2helper[2] = {-1, -1};
    int pipe_helper2proot[2] = {-1, -1};
    if (UNLIKELY(pipe2(pipe_proot2helper, O_CLOEXEC) < 0 || pipe2(pipe_helper2proot, O_CLOEXEC) < 0))
        goto cleanup;
    pid_t pid = fork();
    if (UNLIKELY(pid < 0)) goto cleanup;
    if (pid == 0) {
        close(pipe_proot2helper[1]);
        close(pipe_helper2proot[0]);
        if (dup2(pipe_proot2helper[0], STDIN_FILENO) < 0 ||
            dup2(pipe_helper2proot[1], STDOUT_FILENO) < 0)
            _exit(1);
        close(pipe_proot2helper[0]);
        close(pipe_helper2proot[1]);
        fcntl(STDIN_FILENO, F_SETFL, 0);
        fcntl(STDOUT_FILENO, F_SETFL, 0);
        pid_t child = fork();
        if (child < 0) _exit(1);
        if (child == 0) {
            execl("/proc/self/exe", "neoproot", "--shm-helper", NULL);
            _exit(1);
        }
        _exit(0);
    }
    close(pipe_proot2helper[0]);
    close(pipe_helper2proot[1]);
    ssize_t nread = read(pipe_helper2proot[0], sysvipc_shm_helper_addr.sun_path,
                         SYSVIPC_SHMHELPER_SOCKET_LEN);
    if (UNLIKELY(nread != SYSVIPC_SHMHELPER_SOCKET_LEN)) goto cleanup;
    sysvipc_shm_helper_addr.sun_family = AF_UNIX;
    proot2helper_fd = pipe_proot2helper[1];
    helper2proot_fd = pipe_helper2proot[0];
    sysvipc_shm_helper_initialized = true;
    return 0;
cleanup:
    if (pipe_proot2helper[0] >= 0) close(pipe_proot2helper[0]);
    if (pipe_proot2helper[1] >= 0) close(pipe_proot2helper[1]);
    if (pipe_helper2proot[0] >= 0) close(pipe_helper2proot[0]);
    if (pipe_helper2proot[1] >= 0) close(pipe_helper2proot[1]);
    return -1;
}

static ALWAYS_INLINE int sysvipc_shm_send_helper_request(struct SysVIpcShmHelperRequest *req) {
    if (UNLIKELY(!req)) return -1;
    if (UNLIKELY(sysvipc_shm_launch_helper() < 0)) return -1;
    if (UNLIKELY(write(proot2helper_fd, req, sizeof(*req)) != sizeof(*req))) return -1;
    if (req->op == SHMHELPER_ALLOC) {
        int fd;
        if (UNLIKELY(read(helper2proot_fd, &fd, sizeof(fd)) != sizeof(fd) || fd < 0))
            return -1;
        return fd;
    }
    return 0;
}

HOT int sysvipc_shmget(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    word_t key = peek_reg(tracee, CURRENT, SYSARG_1);
    size_t size = (size_t)peek_reg(tracee, CURRENT, SYSARG_2);
    word_t flg = peek_reg(tracee, CURRENT, SYSARG_3);
    struct SysVIpcSharedMem *shms = config->ipc_namespace->shms;
    size_t num = talloc_array_length(shms);
    size_t unused = 0, idx = 0;
    bool found_unused = false, found_existing = false;
    for (; idx < num; ++idx) {
        if (shms[idx].valid) {
            if (key != IPC_PRIVATE && shms[idx].key == (int32_t)key) {
                found_existing = true; break;
            }
        } else if (!found_unused) {
            unused = idx; found_unused = true;
        }
    }
    struct SysVIpcSharedMem *shm = NULL;
    if (!found_existing) {
        if (!(flg & IPC_CREAT)) return -ENOENT;
        if (size > SYSVIPC_MAX_SHM_SIZE) return -EINVAL;
        if (found_unused) {
            idx = unused;
            shm = &shms[idx];
            memset(shm, 0, sizeof(*shm));
        } else {
            shms = talloc_realloc(config->ipc_namespace, shms, struct SysVIpcSharedMem, num + 1);
            if (!shms) return -ENOMEM;
            config->ipc_namespace->shms = shms;
            idx = num;
            shm = &shms[idx];
            memset(shm, 0, sizeof(*shm));
        }
        struct SysVIpcShmHelperRequest req = { .op = SHMHELPER_ALLOC, .fd = (int)((idx + 1) | ((unsigned int)shm->generation << 12)), .size = size };
        shm->fd = sysvipc_shm_send_helper_request(&req);
        if (UNLIKELY(shm->fd < 0)) return -ENOSPC;
        memset(&shm->stats, 0, sizeof(shm->stats));
        shm->stats.shm_perm.mode = flg & 0777;
        shm->stats.shm_segsz = size;
        shm->stats.shm_cpid = config->process->pgid;
        shm->key = key;
        shm->valid = true;
        shm->mappings = talloc_zero(config->ipc_namespace, struct SysVIpcSharedMemMaps);
        if (!shm->mappings) {
            struct SysVIpcShmHelperRequest freereq = { .op = SHMHELPER_FREE, .fd = shm->fd };
            sysvipc_shm_send_helper_request(&freereq);
            return -ENOMEM;
        }
        LIST_INIT(shm->mappings);
    } else {
        if ((flg & IPC_CREAT) && (flg & IPC_EXCL)) return -EEXIST;
        shm = &shms[idx];
        if (size != 0 && size != shm->stats.shm_segsz) return -EINVAL;
    }
    return (int)((idx + 1) | ((unsigned int)shm->generation << 12));
}

static ALWAYS_INLINE void sysvipc_do_rmid(struct SysVIpcSharedMem *shm) {
    assert(shm && LIST_EMPTY(shm->mappings));
    struct SysVIpcShmHelperRequest req = { .op = SHMHELPER_FREE, .fd = shm->fd };
    sysvipc_shm_send_helper_request(&req);
    TALLOC_FREE(shm->mappings);
    shm->valid = false;
    shm->rmid_pending = false;
    shm->generation++;
    shm->fd = -1;
}

static int sysvipc_shm_memmap_destructor(struct SysVIpcSharedMemMap *mapping) {
    if (UNLIKELY(!mapping)) return 0;
    LIST_REMOVE(mapping, link_shmid);
    LIST_REMOVE(mapping, link_process);
    struct SysVIpcSharedMem *shm = &mapping->ipc_namespace->shms[mapping->shm_index];
    if (shm->rmid_pending && LIST_EMPTY(shm->mappings))
        sysvipc_do_rmid(shm);
    return 0;
}

static ALWAYS_INLINE void sysvipc_shm_wake_pending_shmat(void) {
    Tracee *ot;
    struct SysVIpcConfig *ocfg;
    SYSVIPC_FOREACH_TRACEE_ANY_NAMESPACE(ot, ocfg) {
        if (ocfg->wait_reason == WR_WAIT_SHMAT_HELPER_BUSY) {
            sysvipc_wake_tracee(ot, ocfg, 0);
            register_chained_syscall(ot, PR_socket, AF_UNIX, SOCK_SEQPACKET, 0, 0, 0, 0);
            ocfg->chain_state = CSTATE_SHMAT_SOCKET;
            return;
        }
    }
}

HOT int sysvipc_shmat(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx;
    struct SysVIpcSharedMem *shm;
    LOOKUP_IPC_OBJECT(idx, shm, config->ipc_namespace->shms);
    config->waiting_object_index = idx;
    struct SysVIpcSharedMemMap *mapping = talloc_zero(config->process, struct SysVIpcSharedMemMap);
    if (!mapping) return -ENOMEM;
    talloc_set_destructor(mapping, sysvipc_shm_memmap_destructor);
    mapping->ipc_namespace = config->ipc_namespace;
    mapping->shm_index = idx;
    LIST_INSERT_HEAD(&config->process->mapped_shms, mapping, link_process);
    LIST_INSERT_HEAD(shm->mappings, mapping, link_shmid);
    Tracee *ot;
    struct SysVIpcConfig *ocfg;
    SYSVIPC_FOREACH_TRACEE_ANY_NAMESPACE(ot, ocfg) {
        if (ocfg->chain_state > CSTATE_SHMAT_SOCKET && ocfg->chain_state <= CSTATE_SHMAT_MMAP) {
            config->wait_reason = WR_WAIT_SHMAT_HELPER_BUSY;
            return 0;
        }
    }
    set_sysnum(tracee, PR_socket);
    poke_reg(tracee, SYSARG_1, AF_UNIX);
    poke_reg(tracee, SYSARG_2, SOCK_SEQPACKET);
    poke_reg(tracee, SYSARG_3, 0);
    config->chain_state = CSTATE_SHMAT_SOCKET;
    return 0;
}

static ALWAYS_INLINE struct SysVIpcSharedMemMap *sysvipc_shm_find_pending_mapping(
    struct SysVIpcProcess *process, struct SysVIpcNamespace *ns, size_t idx) {
    struct SysVIpcSharedMemMap *map;
    LIST_FOREACH(map, &process->mapped_shms, link_process) {
        if (map->size == 0 && map->shm_index == idx && map->ipc_namespace == ns)
            return map;
    }
    __builtin_unreachable();
    return NULL;
}

HOT int sysvipc_shmat_chain(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    struct SysVIpcSharedMem *shm = &config->ipc_namespace->shms[config->waiting_object_index];
    assert(shm->valid);
    switch (config->chain_state) {
    case CSTATE_SHMAT_SOCKET: {
        config->shmat_socket_fd = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if (UNLIKELY(config->shmat_socket_fd < 0)) goto fail_dont_close;
        word_t guest_addr = peek_reg(tracee, CURRENT, STACK_POINTER) - sizeof(struct sockaddr_un);
        if (UNLIKELY(guest_addr == 0)) goto fail_dont_close;
        if (UNLIKELY(write_data(tracee, guest_addr, &sysvipc_shm_helper_addr, sizeof(struct sockaddr_un)) < 0))
            goto fail_dont_close;
        register_chained_syscall(tracee, PR_connect, config->shmat_socket_fd,
                                 guest_addr, sizeof(struct sockaddr_un), 0, 0, 0);
        config->shmat_guest_buf = guest_addr;
        config->chain_state = CSTATE_SHMAT_CONNECT;
        return 1;
    }
    case CSTATE_SHMAT_CONNECT: {
        if (UNLIKELY((int)peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)) goto fail_close_socket;
        struct SysVIpcRecvMsgPointers ptrs;
        if (UNLIKELY(sysvipc_shm_recvmsg_pointers(tracee, &ptrs, config->shmat_guest_buf, true) < 0))
            goto fail_close_socket;
        struct SysVIpcShmHelperRequest req = { .op = SHMHELPER_DISTRIBUTE, .fd = shm->fd };
        if (UNLIKELY(sysvipc_shm_send_helper_request(&req) < 0)) goto fail_close_socket;
        register_chained_syscall(tracee, PR_recvmsg, config->shmat_socket_fd,
                                 ptrs.msghdr_ptr, 0, 0, 0, 0);
        config->chain_state = CSTATE_SHMAT_RECVMSG;
        return 1;
    }
    case CSTATE_SHMAT_RECVMSG: {
        struct SysVIpcRecvMsgPointers ptrs;
        if (UNLIKELY(sysvipc_shm_recvmsg_pointers(tracee, &ptrs, config->shmat_guest_buf, false) < 0))
            goto fail_close_socket;
        struct cmsghdr cmsg;
        if (UNLIKELY(read_data(tracee, &cmsg, ptrs.cmsg_control_ptr, sizeof(cmsg)) < 0))
            goto fail_close_socket;
        if (UNLIKELY(cmsg.cmsg_level != SOL_SOCKET || cmsg.cmsg_type != SCM_RIGHTS))
            goto fail_close_socket;
        word_t fd;
        if (UNLIKELY(read_data(tracee, &fd, ptrs.cmsg_control_ptr + sizeof(cmsg), 4) < 0 || fd > 0xFFFF))
            goto fail_close_socket;
        config->shmat_mem_fd = (int)fd;
        size_t page_sz = get_page_size();
        size_t map_size = shm->stats.shm_segsz;
        map_size = (map_size + (page_sz - 1)) & ~(page_sz - 1);
        word_t mmap_sys = (detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER) ? PR_mmap2 : PR_mmap;
        register_chained_syscall(tracee, mmap_sys, 0, map_size,
                                 PROT_READ | PROT_WRITE, MAP_SHARED,
                                 config->shmat_mem_fd, 0);
        config->chain_state = CSTATE_SHMAT_MMAP;
        return 1;
    }
    case CSTATE_SHMAT_MMAP: {
        word_t addr = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if (UNLIKELY(addr == (word_t)-1)) goto fail_close_socket;
        struct SysVIpcSharedMemMap *map = sysvipc_shm_find_pending_mapping(
            config->process, config->ipc_namespace, config->waiting_object_index);
        map->addr = addr;
        map->size = (size_t)peek_reg(tracee, CURRENT, SYSARG_2);
        register_chained_syscall(tracee, PR_close, config->shmat_mem_fd, 0, 0, 0, 0, 0);
        register_chained_syscall(tracee, PR_close, config->shmat_socket_fd, 0, 0, 0, 0, 0);
        force_chain_final_result(tracee, addr);
        config->chain_state = CSTATE_NOT_CHAINED;
        sysvipc_shm_wake_pending_shmat();
        return 1;
    }
    default:
        __builtin_unreachable();
    }
fail_close_socket:
    register_chained_syscall(tracee, PR_close, config->shmat_socket_fd, 0, 0, 0, 0, 0);
    force_chain_final_result(tracee, -ENOMEM);
    config->chain_state = CSTATE_NOT_CHAINED;
    talloc_free(sysvipc_shm_find_pending_mapping(config->process, config->ipc_namespace,
                                                config->waiting_object_index));
    sysvipc_shm_wake_pending_shmat();
    return 1;
fail_dont_close:
    config->chain_state = CSTATE_NOT_CHAINED;
    talloc_free(sysvipc_shm_find_pending_mapping(config->process, config->ipc_namespace,
                                                config->waiting_object_index));
    sysvipc_shm_wake_pending_shmat();
    return -ENOMEM;
}

HOT int sysvipc_shmdt(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->process)) return -EINVAL;
    word_t addr = peek_reg(tracee, CURRENT, SYSARG_1);
    struct SysVIpcSharedMemMap *map;
    LIST_FOREACH(map, &config->process->mapped_shms, link_process) {
        if (map->addr == addr) {
            set_sysnum(tracee, PR_munmap);
            poke_reg(tracee, SYSARG_2, (word_t)map->size);
            config->chain_state = CSTATE_SINGLE;
            talloc_free(map);
            return 0;
        }
    }
    return -EINVAL;
}

static ALWAYS_INLINE void sysvipc_shm_update_stats(struct SysVIpcSharedMem *shm) {
    if (UNLIKELY(!shm || !shm->mappings)) return;
    shm->stats.shm_nattch = 0;
    struct SysVIpcSharedMemMap *map;
    LIST_FOREACH(map, shm->mappings, link_shmid) shm->stats.shm_nattch++;
}

HOT int sysvipc_shmctl(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx __attribute__((unused));
    struct SysVIpcSharedMem *shm;
    LOOKUP_IPC_OBJECT(idx, shm, config->ipc_namespace->shms);
    int cmd = (int)peek_reg(tracee, CURRENT, SYSARG_2);
    word_t buf = peek_reg(tracee, CURRENT, SYSARG_3);
    switch (cmd) {
    case IPC_RMID:
    case IPC_RMID | SYSVIPC_IPC_64:
        if (LIST_EMPTY(shm->mappings))
            sysvipc_do_rmid(shm);
        else
            shm->rmid_pending = true;
        return 0;
    case IPC_STAT:
        sysvipc_shm_update_stats(shm);
        return write_data(tracee, buf, &shm->stats, sizeof(struct SysVIpcShmidDs));
    default:
        return -EINVAL;
    }
}

void sysvipc_shm_inherit_process(struct SysVIpcProcess *parent, struct SysVIpcProcess *child) {
    if (UNLIKELY(!parent || !child)) return;
    struct SysVIpcSharedMemMap *pmap, *cmap, *prev = NULL;
    LIST_FOREACH(pmap, &parent->mapped_shms, link_process) {
        cmap = talloc_zero(child, struct SysVIpcSharedMemMap);
        if (!cmap) continue;
        talloc_set_destructor(cmap, sysvipc_shm_memmap_destructor);
        cmap->addr = pmap->addr;
        cmap->size = pmap->size;
        cmap->ipc_namespace = pmap->ipc_namespace;
        cmap->shm_index = pmap->shm_index;
        LIST_INSERT_AFTER(pmap, cmap, link_shmid);
        if (prev)
            LIST_INSERT_AFTER(prev, cmap, link_process);
        else
            LIST_INSERT_HEAD(&child->mapped_shms, cmap, link_process);
        prev = cmap;
    }
}

void sysvipc_shm_remove_mappings_from_process(struct SysVIpcProcess *process) {
    if (UNLIKELY(!process)) return;
    struct SysVIpcSharedMemMap *map = process->mapped_shms.lh_first;
    while (map) {
        struct SysVIpcSharedMemMap *next = map->link_process.le_next;
        talloc_free(map);
        map = next;
    }
}

void sysvipc_shm_fill_proc(FILE *proc_file, struct SysVIpcNamespace *ns) {
    if (UNLIKELY(!proc_file || !ns)) return;
    fprintf(proc_file,
        "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n");
    size_t page_sz = get_page_size();
    struct SysVIpcSharedMem *shms = ns->shms;
    size_t num = talloc_array_length(shms);
    for (size_t i = 0; i < num; ++i) {
        struct SysVIpcSharedMem *shm = &shms[i];
        if (!shm->valid) continue;
        sysvipc_shm_update_stats(shm);
        size_t map_size = (shm->stats.shm_segsz + (page_sz - 1)) & ~(page_sz - 1);
        fprintf(proc_file,
            "%10d %10d  %4o %21lu %5u %5u  %5lu %5u %5u %5u %5u %10llu %10llu %10llu %21lu %21lu\n",
            shm->key, (int)((i + 1) | ((unsigned int)shm->generation << 12)),
            shm->stats.shm_perm.mode, (unsigned long)shm->stats.shm_segsz,
            shm->stats.shm_cpid, shm->stats.shm_lpid, (unsigned long)shm->stats.shm_nattch,
            shm->stats.shm_perm.uid, shm->stats.shm_perm.gid,
            shm->stats.shm_perm.cuid, shm->stats.shm_perm.cgid,
            (unsigned long long)shm->stats.shm_atime,
            (unsigned long long)shm->stats.shm_dtime,
            (unsigned long long)shm->stats.shm_ctime,
            (unsigned long)map_size, 0UL);
    }
}

int sysvipc_shm_namespace_destructor(struct SysVIpcNamespace *ns) {
    if (UNLIKELY(!ns)) return 0;
    struct SysVIpcSharedMem *shms = ns->shms;
    size_t num = talloc_array_length(shms);
    for (size_t i = 0; i < num; ++i) {
        struct SysVIpcSharedMem *shm = &shms[i];
        if (shm->valid) {
            struct SysVIpcSharedMemMap *map;
            LIST_FOREACH(map, shm->mappings, link_shmid)
                talloc_set_destructor(map, NULL);
        }
    }
    return 0;
}

static ALWAYS_INLINE int sysvipc_shm_do_allocate(size_t size, int shmid) {
#ifdef __ANDROID__
    int fd = open("/dev/ashmem", O_RDWR, 0);
    if (UNLIKELY(fd < 0)) return -ENOSPC;
    char name[ASHMEM_NAME_LEN];
    snprintf(name, sizeof(name)-1, "sysvshm_0x%X", shmid);
    if (ioctl(fd, ASHMEM_SET_NAME, name) < 0 || ioctl(fd, ASHMEM_SET_SIZE, size) < 0) {
        close(fd);
        return -ENOSPC;
    }
    return fd;
#else
    FILE *tmp = tmpfile();
    if (!tmp) return -ENOSPC;
    int fd = dup(fileno(tmp));
    fclose(tmp);
    if (fd < 0 || ftruncate(fd, size) < 0) {
        if (fd >= 0) close(fd);
        return -ENOSPC;
    }
    return fd;
#endif
}

NORETURN void sysvipc_shm_helper_main(void) {
    char *temp_path = NULL;
    int server_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (UNLIKELY(server_fd < 0)) _exit(1);
    struct sockaddr_un server_addr = { .sun_family = AF_UNIX };
    for (int i = 0; i < 64; ++i) {
        temp_path = create_temp_name(NULL, "prootshm");
        if (!temp_path) continue;
        char template[PATH_MAX];
        strncpy(template, temp_path, sizeof(template)-1);
        template[sizeof(template)-1] = '\0';
        size_t len = strlen(template);
        if (len > 6) strcpy(template + len - 6, "XXXXXX");
        int fd = mkstemp(template);
        if (fd >= 0) { close(fd); unlink(template); }
        if (strlen(template) > SYSVIPC_SHMHELPER_SOCKET_LEN) {
            TALLOC_FREE(temp_path);
            continue;
        }
        memset(server_addr.sun_path, 0, sizeof(server_addr.sun_path));
        strncpy(server_addr.sun_path, template, sizeof(server_addr.sun_path)-1);
        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
            break;
        TALLOC_FREE(temp_path);
    }
    if (!temp_path) { close(server_fd); _exit(1); }
    if (listen(server_fd, 1) < 0) {
        unlink(server_addr.sun_path);
        close(server_fd);
        _exit(1);
    }
    write(STDOUT_FILENO, server_addr.sun_path, SYSVIPC_SHMHELPER_SOCKET_LEN);
    for (;;) {
        struct SysVIpcShmHelperRequest req;
        ssize_t ret = TEMP_FAILURE_RETRY(read(STDIN_FILENO, &req, sizeof(req)));
        if (ret == 0) break;
        if (ret != sizeof(req)) break;
        switch (req.op) {
        case SHMHELPER_ALLOC: {
            int fd = sysvipc_shm_do_allocate(req.size, req.fd);
            write(STDOUT_FILENO, &fd, sizeof(fd));
            break;
        }
        case SHMHELPER_FREE:
            close(req.fd);
            break;
        case SHMHELPER_DISTRIBUTE: {
            int client = accept(server_fd, NULL, NULL);
            if (client < 0) break;
            char dummy = '!';
            struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
            struct { struct cmsghdr hdr; int fd[1]; } anc;
            struct msghdr msg = {
                .msg_name = NULL, .msg_namelen = 0,
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = &anc, .msg_controllen = sizeof(anc),
                .msg_flags = 0
            };
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_len = msg.msg_controllen;
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            ((int *)CMSG_DATA(cmsg))[0] = req.fd;
            sendmsg(client, &msg, 0);
            close(client);
            break;
        }
        default: break;
        }
    }
    unlink(server_addr.sun_path);
    close(server_fd);
    TALLOC_FREE(temp_path);
    _exit(0);
}