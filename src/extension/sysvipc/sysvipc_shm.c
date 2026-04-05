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
#else
#include <sys/stat.h>
#endif

/* 共享内存最大尺寸限制（100页，默认4096字节/页） */
#define SYSVIPC_MAX_SHM_SIZE (100 * 4096)
/* SHM helper UNIX socket路径长度限制 */
#define SYSVIPC_SHMHELPER_SOCKET_LEN 108
/* 临时文件模板长度 */
#define TEMP_NAME_TEMPLATE_LEN 16

/**
 * recvmsg 参数指针结构体（存储msghdr相关字段在进程内存中的地址）
 */
struct SysVIpcRecvMsgPointers {
	word_t msghdr_ptr;        // msghdr结构体指针
	word_t cmsg_controllen_ptr; // cmsg_controllen字段指针
	word_t cmsg_control_ptr;  // cmsg_control字段指针
};

/**
 * 计算并设置recvmsg所需的参数指针（32/64位兼容）
 * @param tracee 进程追踪句柄
 * @param out_pointers 输出参数指针结构体
 * @param guest_buf 进程内存中的缓冲区地址
 * @param do_write 是否将参数结构写入进程内存
 * @return 0-成功，非0-错误码
 */
int sysvipc_shm_recvmsg_pointers(Tracee *tracee, struct SysVIpcRecvMsgPointers *out_pointers,
                                 word_t guest_buf, bool do_write)
{
	if (tracee == NULL || out_pointers == NULL)
		return -EINVAL;

	bool is32 = is_32on64_mode(tracee);
	word_t ptr_len = is32 ? 4 : 8;
	word_t buf_end = guest_buf + sizeof(struct sockaddr_un);

	// 计算各字段在进程内存中的偏移地址
	word_t data_addr = buf_end - 4;
	word_t data_iov_length = data_addr - ptr_len;
	word_t data_iov_addr = data_iov_length - ptr_len;
	word_t msghdr_flags = data_iov_addr - ptr_len;
	word_t msghdr_controllen = msghdr_flags - ptr_len;
	word_t msghdr_control = msghdr_controllen - ptr_len;
	word_t msghdr_iovlen = msghdr_control - ptr_len;
	word_t msghdr_iov = msghdr_iovlen - ptr_len;
	word_t msghdr = msghdr_iov - ptr_len * 2; // name/namelen 未使用

	// 写入参数结构到进程内存
	if (do_write) {
		char data[sizeof(struct sockaddr_un)] = {0};
		if (is32) {
			*(uint32_t *)&data[data_iov_addr - guest_buf] = (uint32_t)data_addr;
			*(uint32_t *)&data[data_iov_length - guest_buf] = 1;
			*(uint32_t *)&data[msghdr_iov - guest_buf] = (uint32_t)data_iov_addr;
			*(uint32_t *)&data[msghdr_iovlen - guest_buf] = 1;
			*(uint32_t *)&data[msghdr_control - guest_buf] = (uint32_t)guest_buf;
			*(uint32_t *)&data[msghdr_controllen - guest_buf] = 20; // sizeof(cmsghdr) + sizeof(uint64_t)
		} else {
			*(uint64_t *)&data[data_iov_addr - guest_buf] = data_addr;
			*(uint64_t *)&data[data_iov_length - guest_buf] = 1;
			*(uint64_t *)&data[msghdr_iov - guest_buf] = data_iov_addr;
			*(uint64_t *)&data[msghdr_iovlen - guest_buf] = 1;
			*(uint64_t *)&data[msghdr_control - guest_buf] = guest_buf;
			*(uint64_t *)&data[msghdr_controllen - guest_buf] = 20;
		}

		int status = write_data(tracee, guest_buf, data, sizeof(data));
		if (status < 0)
			return status;
	}

	// 输出参数指针
	out_pointers->msghdr_ptr = msghdr;
	out_pointers->cmsg_controllen_ptr = msghdr_controllen;
	out_pointers->cmsg_control_ptr = guest_buf;
	return 0;
}

/**
 * SHM helper 请求操作类型
 */
enum SysVIpcShmHelperRequestOp {
	SHMHELPER_DISTRIBUTE, // 分发共享内存FD
	SHMHELPER_ALLOC,      // 分配共享内存
	SHMHELPER_FREE        // 释放共享内存
};

/**
 * SHM helper 请求结构体
 */
struct SysVIpcShmHelperRequest {
	enum SysVIpcShmHelperRequestOp op;
	int fd;
	size_t size;
};

static struct sockaddr_un sysvipc_shm_helper_addr; // SHM helper UNIX socket地址
static bool sysvipc_shm_helper_initialized = false; // helper初始化标志
static int proot2helper_fd = -1; // proot→helper 通信FD
static int helper2proot_fd = -1; // helper→proot 通信FD

/**
 * 启动SHM helper进程（仅执行一次）
 * @return 0-成功，-1-失败
 */
static int sysvipc_shm_launch_helper(void)
{
	if (sysvipc_shm_helper_initialized)
		return 0;

	int pipe_proot2helper[2] = {-1, -1};
	int pipe_helper2proot[2] = {-1, -1};

	// 创建双向通信管道
	if (pipe2(pipe_proot2helper, O_CLOEXEC) < 0 || pipe2(pipe_helper2proot, O_CLOEXEC) < 0) {
		perror("sysvipc: pipe2 failed");
		goto cleanup;
	}

	// 第一次fork：创建helper父进程
	pid_t pid = fork();
	if (pid < 0) {
		perror("sysvipc: first fork failed");
		goto cleanup;
	}

	if (pid == 0) {
		// 子进程：关闭不需要的管道端
		close(pipe_proot2helper[1]);
		close(pipe_helper2proot[0]);

		// 重定向标准输入输出到管道
		if (dup2(pipe_proot2helper[0], STDIN_FILENO) < 0 ||
		    dup2(pipe_helper2proot[1], STDOUT_FILENO) < 0) {
			perror("sysvipc: dup2 failed");
			_exit(1);
		}

		// 关闭原始管道描述符
		close(pipe_proot2helper[0]);
		close(pipe_helper2proot[1]);

		// 清除文件状态标志
		fcntl(STDIN_FILENO, F_SETFL, 0);
		fcntl(STDOUT_FILENO, F_SETFL, 0);

		// 第二次fork：脱离proot的waitpid监控
		pid_t child_pid = fork();
		if (child_pid < 0) {
			perror("sysvipc: second fork failed");
			_exit(1);
		}

		if (child_pid == 0) {
			// 孙进程：执行helper主逻辑
			execl("/proc/self/exe", "proot-scicat", "--shm-helper", NULL);
			perror("sysvipc: execl failed");
			_exit(1);
		} else {
			_exit(0);
		}
	}

	// 父进程：关闭不需要的管道端
	close(pipe_proot2helper[0]);
	close(pipe_helper2proot[1]);

	// 读取helper的UNIX socket路径
	ssize_t nread = read(pipe_helper2proot[0], sysvipc_shm_helper_addr.sun_path,
	                     SYSVIPC_SHMHELPER_SOCKET_LEN);
	if (nread != SYSVIPC_SHMHELPER_SOCKET_LEN) {
		perror("sysvipc: read helper socket path failed");
		goto cleanup;
	}

	// 初始化helper地址结构
	sysvipc_shm_helper_addr.sun_family = AF_UNIX;
	proot2helper_fd = pipe_proot2helper[1];
	helper2proot_fd = pipe_helper2proot[0];
	sysvipc_shm_helper_initialized = true;
	return 0;

cleanup:
	// 清理资源
	if (pipe_proot2helper[0] >= 0) close(pipe_proot2helper[0]);
	if (pipe_proot2helper[1] >= 0) close(pipe_proot2helper[1]);
	if (pipe_helper2proot[0] >= 0) close(pipe_helper2proot[0]);
	if (pipe_helper2proot[1] >= 0) close(pipe_helper2proot[1]);
	return -1;
}

/**
 * 发送请求到SHM helper进程
 * @param request 请求结构体
 * @return 成功返回FD（ALLOC操作）或0，失败返回-1
 */
static int sysvipc_shm_send_helper_request(struct SysVIpcShmHelperRequest *request)
{
	if (request == NULL)
		return -1;

	// 确保helper已启动
	if (sysvipc_shm_launch_helper() < 0)
		return -1;

	// 发送请求
	ssize_t ret = write(proot2helper_fd, request, sizeof(*request));
	if (ret != sizeof(*request)) {
		perror("sysvipc: write helper request failed");
		return -1;
	}

	// ALLOC操作需要读取返回的FD
	if (request->op == SHMHELPER_ALLOC) {
		int fd = -1;
		ret = read(helper2proot_fd, &fd, sizeof(fd));
		if (ret != sizeof(fd) || fd < 0) {
			perror("sysvipc: read helper alloc fd failed");
			return -1;
		}
		return fd;
	}

	return 0;
}

/**
 * 实现shmget系统调用：创建/获取共享内存段
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 成功返回shmid，失败返回-errno
 */
int sysvipc_shmget(Tracee *tracee, struct SysVIpcConfig *config)
{
	if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
		return -EINVAL;

	word_t shm_key = peek_reg(tracee, CURRENT, SYSARG_1);
	size_t shm_size = (size_t)peek_reg(tracee, CURRENT, SYSARG_2);
	word_t shmflg = peek_reg(tracee, CURRENT, SYSARG_3);

	struct SysVIpcSharedMem *shms = config->ipc_namespace->shms;
	size_t num_shms = talloc_array_length(shms);
	size_t unused_slot = 0;
	size_t shm_index = 0;
	bool found_unused_slot = false;
	bool found_existing = false;

	// 查找已存在的共享内存段或未使用的槽位
	for (; shm_index < num_shms; shm_index++) {
		if (shms[shm_index].valid) {
			// 找到匹配key的已存在段
			if (shm_key != IPC_PRIVATE && shms[shm_index].key == (int32_t)shm_key) {
				found_existing = true;
				break;
			}
		} else if (!found_unused_slot) {
			unused_slot = shm_index;
			found_unused_slot = true;
		}
	}

	struct SysVIpcSharedMem *shm = NULL;
	// 未找到已存在的段，需要创建新段
	if (!found_existing) {
		// 未指定IPC_CREAT，返回不存在错误
		if (!(shmflg & IPC_CREAT))
			return -ENOENT;

		// 检查尺寸限制
		if (shm_size > SYSVIPC_MAX_SHM_SIZE)
			return -EINVAL;

		// 分配新槽位
		if (found_unused_slot) {
			shm_index = unused_slot;
			shm = &shms[shm_index];
			memset(shm, 0, sizeof(*shm));
		} else {
			// 扩展共享内存数组
			shms = talloc_realloc(config->ipc_namespace, shms,
			                      struct SysVIpcSharedMem, num_shms + 1);
			if (shms == NULL)
				return -ENOMEM;
			config->ipc_namespace->shms = shms;
			shm_index = num_shms;
			shm = &shms[shm_index];
			memset(shm, 0, sizeof(*shm));
		}

		// 向helper发送分配请求
		struct SysVIpcShmHelperRequest request = {
			.op = SHMHELPER_ALLOC,
			.fd = IPC_OBJECT_ID(shm_index, shm),
			.size = shm_size
		};
		shm->fd = sysvipc_shm_send_helper_request(&request);
		if (shm->fd < 0)
			return -ENOSPC;

		// 初始化共享内存属性
		memset(&shm->stats, 0, sizeof(shm->stats));
		shm->stats.shm_perm.mode = shmflg & 0777;
		shm->stats.shm_segsz = shm_size;
		shm->stats.shm_cpid = config->process->pgid;
		shm->key = shm_key;
		shm->valid = true;
		shm->mappings = talloc_zero(config->ipc_namespace, struct SysVIpcSharedMemMaps);
		if (shm->mappings == NULL) {
			sysvipc_shm_send_helper_request(&((struct SysVIpcShmHelperRequest){
				.op = SHMHELPER_FREE, .fd = shm->fd
			}));
			return -ENOMEM;
		}
		LIST_INIT(shm->mappings);
	} else {
		// 找到已存在的段，检查IPC_EXCL标志
		if ((shmflg & IPC_CREAT) && (shmflg & IPC_EXCL))
			return -EEXIST;

		shm = &shms[shm_index];
		// 检查尺寸匹配（非零尺寸时）
		if (shm_size != 0 && shm_size != shm->stats.shm_segsz)
			return -EINVAL;
	}

	return IPC_OBJECT_ID(shm_index, shm);
}

/**
 * 实际执行共享内存段删除（所有映射解除后）
 * @param shm 共享内存段结构体
 */
static void sysvipc_do_rmid(struct SysVIpcSharedMem *shm)
{
	assert(shm != NULL && LIST_EMPTY(shm->mappings));

	// 通知helper释放FD
	struct SysVIpcShmHelperRequest request = {
		.op = SHMHELPER_FREE,
		.fd = shm->fd
	};
	sysvipc_shm_send_helper_request(&request);

	// 标记为已释放
	TALLOC_FREE(shm->mappings);
	shm->valid = false;
	shm->rmid_pending = false;
	shm->generation = (shm->generation + 1) & 0xFFFF;
	shm->fd = -1;
}

/**
 * 共享内存映射析构函数：解除映射时调用
 * @param mapping 共享内存映射结构体
 * @return 0-成功
 */
static int sysvipc_shm_memmap_destructor(struct SysVIpcSharedMemMap *mapping)
{
	if (mapping == NULL)
		return 0;

	// 从进程和共享内存的映射列表中移除
	LIST_REMOVE(mapping, link_shmid);
	LIST_REMOVE(mapping, link_process);

	// 所有映射解除且有删除 pending 时，执行实际删除
	struct SysVIpcSharedMem *shm = &mapping->ipc_namespace->shms[mapping->shm_index];
	if (shm->rmid_pending && LIST_EMPTY(shm->mappings)) {
		sysvipc_do_rmid(shm);
	}

	return 0;
}

/**
 * 唤醒等待中的shmat操作
 */
static void sysvipc_shm_wake_pending_shmat(void)
{
	Tracee *other_tracee;
	struct SysVIpcConfig *other_config;

	SYSVIPC_FOREACH_TRACEE_ANY_NAMESPACE(other_tracee, other_config) {
		if (other_config->wait_reason == WR_WAIT_SHMAT_HELPER_BUSY) {
			// 重启shmat操作，创建UNIX socket
			sysvipc_wake_tracee(other_tracee, other_config, 0);
			register_chained_syscall(other_tracee, PR_socket, AF_UNIX, SOCK_SEQPACKET, 0, 0, 0, 0);
			other_config->chain_state = CSTATE_SHMAT_SOCKET;
			return;
		}
	}
}

/**
 * 实现shmat系统调用：附加共享内存段到进程地址空间
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 0-成功，失败返回-errno
 */
int sysvipc_shmat(Tracee *tracee, struct SysVIpcConfig *config)
{
	if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
		return -EINVAL;

	size_t shm_index;
	struct SysVIpcSharedMem *shm;
	LOOKUP_IPC_OBJECT(shm_index, shm, config->ipc_namespace->shms);

	// 记录等待的共享内存索引
	config->waiting_object_index = shm_index;

	// 创建映射结构体并注册到进程和共享内存
	struct SysVIpcSharedMemMap *mapping = talloc_zero(config->process, struct SysVIpcSharedMemMap);
	if (mapping == NULL)
		return -ENOMEM;

	talloc_set_destructor(mapping, sysvipc_shm_memmap_destructor);
	mapping->ipc_namespace = config->ipc_namespace;
	mapping->shm_index = shm_index;
	LIST_INSERT_HEAD(&config->process->mapped_shms, mapping, link_process);
	LIST_INSERT_HEAD(shm->mappings, mapping, link_shmid);

	// 检查是否有其他进程正在执行shmat，需要等待
	Tracee *other_tracee;
	struct SysVIpcConfig *other_config;
	SYSVIPC_FOREACH_TRACEE_ANY_NAMESPACE(other_tracee, other_config) {
		if (other_config->chain_state > CSTATE_SHMAT_SOCKET &&
		    other_config->chain_state <= CSTATE_SHMAT_MMAP) {
			config->wait_reason = WR_WAIT_SHMAT_HELPER_BUSY;
			return 0;
		}
	}

	// 启动shmat链式调用：创建UNIX socket
	set_sysnum(tracee, PR_socket);
	poke_reg(tracee, SYSARG_1, AF_UNIX);
	poke_reg(tracee, SYSARG_2, SOCK_SEQPACKET);
	poke_reg(tracee, SYSARG_3, 0);
	config->chain_state = CSTATE_SHMAT_SOCKET;
	return 0;
}

/**
 * 查找进程中未完成的共享内存映射
 * @param process 进程结构体
 * @param ipc_namespace IPC命名空间
 * @param shm_index 共享内存索引
 * @return 找到的映射结构体，未找到则触发assert
 */
static struct SysVIpcSharedMemMap *sysvipc_shm_find_pending_mapping(struct SysVIpcProcess *process,
                                                                   struct SysVIpcNamespace *ipc_namespace,
                                                                   size_t shm_index)
{
	assert(process != NULL && ipc_namespace != NULL);

	struct SysVIpcSharedMemMap *mapping;
	LIST_FOREACH(mapping, &process->mapped_shms, link_process) {
		if (mapping->size == 0 && mapping->shm_index == shm_index &&
		    mapping->ipc_namespace == ipc_namespace) {
			return mapping;
		}
	}
	assert(!"sysvipc: no pending shmat mapping found");
	return NULL;
}

/**
 * shmat链式调用处理：处理socket/connect/recvmsg/mmap等步骤
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 1-继续链式调用，0-结束，失败返回-errno
 */
int sysvipc_shmat_chain(Tracee *tracee, struct SysVIpcConfig *config)
{
	if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
		return -EINVAL;

	assert(config->waiting_object_index < talloc_array_length(config->ipc_namespace->shms));
	struct SysVIpcSharedMem *shm = &config->ipc_namespace->shms[config->waiting_object_index];
	assert(shm->valid);

	switch (config->chain_state) {
	case CSTATE_SHMAT_SOCKET: {
		// 步骤1：创建UNIX socket
		config->shmat_socket_fd = (int)peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if (config->shmat_socket_fd < 0)
			goto fail_dont_close;

		// 在进程栈上分配socket地址缓冲区
		word_t guest_addr = peek_reg(tracee, CURRENT, STACK_POINTER) - sizeof(struct sockaddr_un);
		if (guest_addr == 0)
			goto fail_dont_close;

		// 写入helper的socket地址到进程内存
		if (write_data(tracee, guest_addr, &sysvipc_shm_helper_addr, sizeof(struct sockaddr_un)) < 0)
			goto fail_dont_close;

		// 下一步：连接到helper socket
		register_chained_syscall(tracee, PR_connect, config->shmat_socket_fd,
		                         guest_addr, sizeof(struct sockaddr_un), 0, 0, 0);
		config->shmat_guest_buf = guest_addr;
		config->chain_state = CSTATE_SHMAT_CONNECT;
		return 1;
	}

	case CSTATE_SHMAT_CONNECT: {
		// 步骤2：连接到helper socket
		if ((int)peek_reg(tracee, CURRENT, SYSARG_RESULT) != 0)
			goto fail_close_socket;

		// 准备recvmsg参数
		struct SysVIpcRecvMsgPointers pointers;
		if (sysvipc_shm_recvmsg_pointers(tracee, &pointers, config->shmat_guest_buf, true) < 0)
			goto fail_close_socket;

		// 通知helper分发共享内存FD
		struct SysVIpcShmHelperRequest request = {
			.op = SHMHELPER_DISTRIBUTE,
			.fd = shm->fd
		};
		if (sysvipc_shm_send_helper_request(&request) < 0)
			goto fail_close_socket;

		// 下一步：接收helper发送的FD
		register_chained_syscall(tracee, PR_recvmsg, config->shmat_socket_fd,
		                         pointers.msghdr_ptr, 0, 0, 0, 0);
		config->chain_state = CSTATE_SHMAT_RECVMSG;
		return 1;
	}

	case CSTATE_SHMAT_RECVMSG: {
		// 步骤3：接收helper发送的共享内存FD
		struct SysVIpcRecvMsgPointers pointers;
		if (sysvipc_shm_recvmsg_pointers(tracee, &pointers, config->shmat_guest_buf, false) < 0)
			goto fail_close_socket;

		// 读取控制消息（包含FD）
		struct cmsghdr cmsg = {0};
		if (read_data(tracee, &cmsg, pointers.cmsg_control_ptr, sizeof(cmsg)) < 0)
			goto fail_close_socket;

		// 验证控制消息类型
		if (cmsg.cmsg_level != SOL_SOCKET || cmsg.cmsg_type != SCM_RIGHTS)
			goto fail_close_socket;

		// 读取共享内存FD
		word_t fd = 0;
		if (read_data(tracee, &fd, pointers.cmsg_control_ptr + sizeof(cmsg), 4) < 0 || fd > 0xFFFF)
			goto fail_close_socket;
		config->shmat_mem_fd = (int)fd;

		// 计算内存映射尺寸（按页对齐）
		size_t page_size = sysconf(_SC_PAGESIZE);
		size_t map_size = shm->stats.shm_segsz;
		map_size = (map_size + (page_size - 1)) & ~(page_size - 1);

		// 选择mmap或mmap2系统调用
		word_t mmap_sysnum = (detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER)
		                     ? PR_mmap2 : PR_mmap;

		// 下一步：映射共享内存到进程地址空间
		register_chained_syscall(tracee, mmap_sysnum, 0, map_size,
		                         PROT_READ | PROT_WRITE, MAP_SHARED,
		                         config->shmat_mem_fd, 0);
		config->chain_state = CSTATE_SHMAT_MMAP;
		return 1;
	}

	case CSTATE_SHMAT_MMAP: {
		// 步骤4：完成内存映射
		word_t map_addr = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if (map_addr == (word_t)-1)
			goto fail_close_socket;

		// 更新映射信息
		struct SysVIpcSharedMemMap *mapping = sysvipc_shm_find_pending_mapping(
			config->process, config->ipc_namespace, config->waiting_object_index);
		mapping->addr = map_addr;
		mapping->size = (size_t)peek_reg(tracee, CURRENT, SYSARG_2);

		// 关闭临时FD，结束链式调用
		register_chained_syscall(tracee, PR_close, config->shmat_mem_fd, 0, 0, 0, 0, 0);
		register_chained_syscall(tracee, PR_close, config->shmat_socket_fd, 0, 0, 0, 0, 0);
		force_chain_final_result(tracee, map_addr);
		config->chain_state = CSTATE_NOT_CHAINED;

		// 唤醒等待中的shmat操作
		sysvipc_shm_wake_pending_shmat();
		return 1;
	}

	default:
		assert(!"sysvipc: invalid shmat chain state");
	}

fail_close_socket:
	// 失败：关闭socket和内存FD，返回错误
	register_chained_syscall(tracee, PR_close, config->shmat_socket_fd, 0, 0, 0, 0, 0);
	force_chain_final_result(tracee, -ENOMEM);
	config->chain_state = CSTATE_NOT_CHAINED;
	talloc_free(sysvipc_shm_find_pending_mapping(config->process, config->ipc_namespace,
	                                            config->waiting_object_index));
	sysvipc_shm_wake_pending_shmat();
	return 1;

fail_dont_close:
	// 失败：未创建socket，直接返回错误
	config->chain_state = CSTATE_NOT_CHAINED;
	talloc_free(sysvipc_shm_find_pending_mapping(config->process, config->ipc_namespace,
	                                            config->waiting_object_index));
	sysvipc_shm_wake_pending_shmat();
	return -ENOMEM;
}

/**
 * 实现shmdt系统调用：解除共享内存段映射
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 0-成功，失败返回-errno
 */
int sysvipc_shmdt(Tracee *tracee, struct SysVIpcConfig *config)
{
	if (tracee == NULL || config == NULL || config->process == NULL)
		return -EINVAL;

	word_t addr = peek_reg(tracee, CURRENT, SYSARG_1);
	struct SysVIpcSharedMemMap *mapping;

	// 查找地址对应的映射
	LIST_FOREACH(mapping, &config->process->mapped_shms, link_process) {
		if (mapping->addr == addr) {
			// 替换为munmap系统调用
			set_sysnum(tracee, PR_munmap);
			poke_reg(tracee, SYSARG_2, (word_t)mapping->size);
			config->chain_state = CSTATE_SINGLE;

			// 释放映射结构体（触发析构函数）
			talloc_free(mapping);
			return 0;
		}
	}

	return -EINVAL;
}

/**
 * 更新共享内存段状态（当前附加进程数）
 * @param shm 共享内存段结构体
 */
static void sysvipc_shm_update_stats(struct SysVIpcSharedMem *shm)
{
	if (shm == NULL || shm->mappings == NULL)
		return;

	shm->stats.shm_nattch = 0;
	struct SysVIpcSharedMemMap *mapping;
	LIST_FOREACH(mapping, shm->mappings, link_shmid) {
		shm->stats.shm_nattch++;
	}
}

/**
 * 实现shmctl系统调用：控制共享内存段
 * @param tracee 进程追踪句柄
 * @param config SysV IPC配置
 * @return 0-成功，失败返回-errno
 */
int sysvipc_shmctl(Tracee *tracee, struct SysVIpcConfig *config)
{
	if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
		return -EINVAL;

	// 用临时变量占位（仅为满足宏参数格式，不实际使用）
	size_t unused_shm_index;
	struct SysVIpcSharedMem *shm;
	LOOKUP_IPC_OBJECT(unused_shm_index, shm, config->ipc_namespace->shms);

	// 显式标记变量未使用，消除编译警告
	(void)unused_shm_index;

	int cmd = (int)peek_reg(tracee, CURRENT, SYSARG_2);
	word_t buf = peek_reg(tracee, CURRENT, SYSARG_3);

	switch (cmd) {
	case IPC_RMID:
	case IPC_RMID | SYSVIPC_IPC_64: {
		// 删除共享内存段：无映射直接删除，有映射标记pending
		if (LIST_EMPTY(shm->mappings)) {
			sysvipc_do_rmid(shm);
		} else {
			shm->rmid_pending = true;
		}
		return 0;
	}

	case IPC_STAT: {
		// 获取共享内存段状态
		sysvipc_shm_update_stats(shm);

		// 写入状态到进程内存
		int status = write_data(tracee, buf, &shm->stats, sizeof(struct SysVIpcShmidDs));
		if (status < 0)
			return status;
		return 0;
	}

	default:
		// 不支持的命令
		return -EINVAL;
	}
}

/**
 * 进程继承时复制共享内存映射
 * @param parent 父进程结构体
 * @param child 子进程结构体
 */
void sysvipc_shm_inherit_process(struct SysVIpcProcess *parent, struct SysVIpcProcess *child)
{
	if (parent == NULL || child == NULL)
		return;

	struct SysVIpcSharedMemMap *parent_mapping = NULL;
	struct SysVIpcSharedMemMap *prev_child_mapping = NULL;

	// 遍历父进程的所有映射，复制到子进程
	LIST_FOREACH(parent_mapping, &parent->mapped_shms, link_process) {
		struct SysVIpcSharedMemMap *child_mapping = talloc_zero(child, struct SysVIpcSharedMemMap);
		if (child_mapping == NULL)
			continue;

		// 设置析构函数
		talloc_set_destructor(child_mapping, sysvipc_shm_memmap_destructor);

		// 复制映射信息
		child_mapping->addr = parent_mapping->addr;
		child_mapping->size = parent_mapping->size;
		child_mapping->ipc_namespace = parent_mapping->ipc_namespace;
		child_mapping->shm_index = parent_mapping->shm_index;

		// 添加到共享内存的映射列表
		LIST_INSERT_AFTER(parent_mapping, child_mapping, link_shmid);

		// 添加到子进程的映射列表
		if (prev_child_mapping != NULL) {
			LIST_INSERT_AFTER(prev_child_mapping, child_mapping, link_process);
		} else {
			LIST_INSERT_HEAD(&child->mapped_shms, child_mapping, link_process);
		}

		prev_child_mapping = child_mapping;
	}
}

/**
 * 从进程中移除所有共享内存映射
 * @param process 进程结构体
 */
void sysvipc_shm_remove_mappings_from_process(struct SysVIpcProcess *process)
{
	if (process == NULL)
		return;

	// 遍历并释放所有映射（手动处理链表，避免迭代器失效）
	struct SysVIpcSharedMemMap *mapping = process->mapped_shms.lh_first;
	while (mapping != NULL) {
		struct SysVIpcSharedMemMap *next_mapping = mapping->link_process.le_next;
		talloc_free(mapping);
		mapping = next_mapping;
	}
}

/**
 * 填充/proc文件系统中的共享内存信息
 * @param proc_file 输出文件指针
 * @param ipc_namespace IPC命名空间
 */
void sysvipc_shm_fill_proc(FILE *proc_file, struct SysVIpcNamespace *ipc_namespace)
{
	if (proc_file == NULL || ipc_namespace == NULL)
		return;

	// 输出表头
	fprintf(proc_file,
	        "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n");

	size_t page_size = sysconf(_SC_PAGESIZE);
	struct SysVIpcSharedMem *shms = ipc_namespace->shms;
	size_t num_shms = talloc_array_length(shms);

	// 输出每个共享内存段的信息
	for (size_t shm_index = 0; shm_index < num_shms; shm_index++) {
		struct SysVIpcSharedMem *shm = &shms[shm_index];
		if (!shm->valid)
			continue;

		// 更新附加进程数
		sysvipc_shm_update_stats(shm);

		// 计算按页对齐的映射尺寸
		size_t map_size = shm->stats.shm_segsz;
		map_size = (map_size + (page_size - 1)) & ~page_size;

		// 输出详细信息
		fprintf(proc_file,
		        "%10d %10d  %4o %21lu %5u %5u  "
		        "%5lu %5u %5u %5u %5u %10llu %10llu %10llu "
		        "%21lu %21lu\n",
		        shm->key,
		        (int)IPC_OBJECT_ID(shm_index, shm),
		        shm->stats.shm_perm.mode,
		        (unsigned long)shm->stats.shm_segsz,
		        shm->stats.shm_cpid,
		        shm->stats.shm_lpid,
		        (unsigned long)shm->stats.shm_nattch,
		        shm->stats.shm_perm.uid,
		        shm->stats.shm_perm.gid,
		        shm->stats.shm_perm.cuid,
		        shm->stats.shm_perm.cgid,
		        (unsigned long long)shm->stats.shm_atime,
		        (unsigned long long)shm->stats.shm_dtime,
		        (unsigned long long)shm->stats.shm_ctime,
		        (unsigned long)map_size,
		        0L);
	}
}

/**
 * IPC命名空间析构函数：清理共享内存资源
 * @param ipc_namespace IPC命名空间
 * @return 0-成功
 */
int sysvipc_shm_namespace_destructor(struct SysVIpcNamespace *ipc_namespace)
{
	if (ipc_namespace == NULL)
		return 0;

	struct SysVIpcSharedMem *shms = ipc_namespace->shms;
	size_t num_shms = talloc_array_length(shms);

	// 遍历所有共享内存段，清理映射
	for (size_t shm_index = 0; shm_index < num_shms; shm_index++) {
		struct SysVIpcSharedMem *shm = &shms[shm_index];
		if (shm->valid) {
			struct SysVIpcSharedMemMap *mapping;
			LIST_FOREACH(mapping, shm->mappings, link_shmid) {
				talloc_set_destructor(mapping, NULL);
			}
		}
	}

	return 0;
}

/**
 * 分配共享内存（Android/ Linux 兼容）
 * @param size 共享内存尺寸
 * @param shmid 共享内存ID
 * @return 成功返回文件描述符，失败返回-errno
 */
static int sysvipc_shm_do_allocate(size_t size, int shmid)
{
#ifdef __ANDROID__
	// Android：使用ashmem分配共享内存
	int fd = open("/dev/ashmem", O_RDWR, 0);
	if (fd < 0)
		return -ENOSPC;

	// 设置ashmem名称
	char name[ASHMEM_NAME_LEN] = {0};
	snprintf(name, sizeof(name) - 1, "sysvshm_0x%X", shmid);
	if (ioctl(fd, ASHMEM_SET_NAME, name) < 0) {
		close(fd);
		return -ENOSPC;
	}

	// 设置ashmem尺寸
	if (ioctl(fd, ASHMEM_SET_SIZE, size) < 0) {
		close(fd);
		return -ENOSPC;
	}

	return fd;
#else
	// Linux：使用临时文件分配共享内存
	FILE *tmp_file = tmpfile();
	if (tmp_file == NULL)
		return -ENOSPC;

	// 复制文件描述符
	int fd = dup(fileno(tmp_file));
	fclose(tmp_file);
	if (fd < 0)
		return -ENOSPC;

	// 设置文件尺寸
	if (ftruncate(fd, size) < 0) {
		close(fd);
		return -ENOSPC;
	}

	return fd;
#endif
}

/**
 * SHM helper 主函数：处理共享内存分配/释放/分发请求
 */
void sysvipc_shm_helper_main()
{
	char *temp_path = NULL;
	int server_fd = -1;
	struct sockaddr_un server_addr = {.sun_family = AF_UNIX};

	// 创建UNIX socket
	server_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (server_fd < 0) {
		perror("shm-helper: socket creation failed");
		_exit(1);
	}

	// 生成唯一的临时socket路径
	for (int i = 0; i < 64; i++) {
		// 创建临时文件名模板
		temp_path = create_temp_name(NULL, "prootshm");
		if (temp_path == NULL)
			continue;

		char template[PATH_MAX];
		strncpy(template, temp_path, sizeof(template) - 1);
		template[sizeof(template) - 1] = '\0';
		strcpy(template + strlen(template) - 6, "XXXXXX");

		// 使用mkstemp创建唯一文件，然后删除（仅用路径）
		int fd = mkstemp(template);
		if (fd >= 0) {
			close(fd);
			unlink(template);
		}

		// 检查路径长度
		if (strlen(template) > SYSVIPC_SHMHELPER_SOCKET_LEN) {
			TALLOC_FREE(temp_path);
			continue;
		}

		// 设置socket路径
		memset(server_addr.sun_path, 0, sizeof(server_addr.sun_path));
		strncpy(server_addr.sun_path, template, sizeof(server_addr.sun_path) - 1);

		// 绑定socket
		if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
			break;

		TALLOC_FREE(temp_path);
	}

	if (temp_path == NULL) {
		fprintf(stderr, "shm-helper: failed to create temp path\n");
		close(server_fd);
		_exit(1);
	}

	// 开始监听socket
	if (listen(server_fd, 1) < 0) {
		perror("shm-helper: listen failed");
		unlink(server_addr.sun_path);
		close(server_fd);
		_exit(1);
	}

	// 发送socket路径到proot
	write(STDOUT_FILENO, server_addr.sun_path, SYSVIPC_SHMHELPER_SOCKET_LEN);

	// 循环处理请求
	for (;;) {
		struct SysVIpcShmHelperRequest request;
		ssize_t ret = TEMP_FAILURE_RETRY(read(STDIN_FILENO, &request, sizeof(request)));
		if (ret == 0)
			break; // 管道关闭，退出
		if (ret < 0) {
			perror("shm-helper: read request failed");
			break;
		}
		if (ret != sizeof(request)) {
			fprintf(stderr, "shm-helper: incomplete request\n");
			break;
		}

		switch (request.op) {
		case SHMHELPER_ALLOC: {
			// 分配共享内存，返回FD
			int fd = sysvipc_shm_do_allocate(request.size, request.fd);
			write(STDOUT_FILENO, &fd, sizeof(fd));
			break;
		}

		case SHMHELPER_FREE: {
			// 释放共享内存FD
			close(request.fd);
			break;
		}

		case SHMHELPER_DISTRIBUTE: {
			// 接受客户端连接
			int client_fd = accept(server_fd, NULL, NULL);
			if (client_fd < 0) {
				perror("shm-helper: accept failed");
				break;
			}

			// 准备控制消息（包含共享内存FD）
			char dummy_data = '!';
			struct iovec iov = {.iov_base = &dummy_data, .iov_len = 1};

			// 辅助数据缓冲区（包含FD）
			struct {
				struct cmsghdr hdr;
				int fd[1];
			} ancillary_data;

			// 消息头部
			struct msghdr msg = {
				.msg_name = NULL,
				.msg_namelen = 0,
				.msg_iov = &iov,
				.msg_iovlen = 1,
				.msg_control = &ancillary_data,
				.msg_controllen = sizeof(ancillary_data),
				.msg_flags = 0
			};

			// 控制消息内容
			struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_len = msg.msg_controllen;
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			((int *)CMSG_DATA(cmsg))[0] = request.fd;

			// 发送消息（传递FD）
			sendmsg(client_fd, &msg, 0);
			close(client_fd);
			break;
		}

		default:
			fprintf(stderr, "shm-helper: unknown request op\n");
			break;
		}
	}

	// 清理资源
	unlink(server_addr.sun_path);
	close(server_fd);
	TALLOC_FREE(temp_path);
	_exit(0);
}
