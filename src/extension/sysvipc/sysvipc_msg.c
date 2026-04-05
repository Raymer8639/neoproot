#include "sysvipc_internal.h"
#include "sysvipc_sys.h"

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "tracee/tracee.h"
#include "extension/extension.h"

#include <sys/errno.h>
#include <sys/msg.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>

/* 消息队列配置限制 */
#define SYSVIPC_MAX_MSG_SIZE  0xFFFF    /* 单条消息最大长度 */
#define SYSVIPC_DEFAULT_QBYTES (1024 * 64) /* 默认队列总容量限制（不强制校验） */

/**
 * 匹配消息类型与接收者过滤规则
 * @param sender_type 发送者消息类型
 * @param receiver_filter 接收者类型过滤条件
 * @param receiver_flag 接收者标志（MSG_EXCEPT 等）
 * @return true-匹配成功，false-不匹配
 */
static bool sysvipc_msg_match(int sender_type, int receiver_filter, int receiver_flag)
{
    bool matched = (receiver_filter == 0) ||
                   (sender_type == receiver_filter) ||
                   (receiver_filter < 0 && sender_type <= -receiver_filter);

    // 处理 MSG_EXCEPT 标志（反向匹配）
    if (receiver_flag & MSG_EXCEPT) {
        matched = !matched;
    }

    return matched;
}

/**
 * 向接收者进程投递消息
 * @param tracee 接收者进程追踪句柄
 * @param config 接收者IPC配置
 * @param queue 消息队列
 * @param msg 待投递消息
 * @param delivery_time 投递时间戳
 * @return 成功返回消息实际写入长度，失败返回-errno
 */
static int sysvipc_msg_deliver(Tracee *tracee, struct SysVIpcConfig *config,
                               struct SysVIpcMsgQueue *queue, struct SysVIpcMsgQueueItem *msg,
                               time_t delivery_time)
{
    if (tracee == NULL || config == NULL || queue == NULL || msg == NULL)
        return -EINVAL;

    size_t recv_buf_len = (size_t)config->msgrcv_msgsz;
    size_t msg_data_len = msg->mtext_length;

    // 检查消息长度，处理 MSG_NOERROR 标志
    if (msg_data_len > recv_buf_len) {
        if (!(config->msgrcv_msgflg & MSG_NOERROR))
            return -E2BIG;
        msg_data_len = recv_buf_len; // 截断消息
    }

    // 写入消息类型（long 类型）
    int status = write_data(tracee, config->msgrcv_msgp, &msg->mtype, sizeof(long));
    if (status < 0)
        return status;

    // 写入消息数据
    status = write_data(tracee, config->msgrcv_msgp + sizeof(long), msg->mtext, msg_data_len);
    if (status < 0)
        return status;

    // 更新队列状态
    queue->stats.msg_lrpid = tracee->pid;
    queue->stats.msg_rtime = delivery_time;

    return (int)msg_data_len;
}

/**
 * 实际执行消息接收逻辑（内部辅助函数）
 * @param tracee 进程追踪句柄
 * @param config IPC配置
 * @param queue_index 消息队列索引
 * @param queue 消息队列
 * @return 成功返回消息长度，0-等待中，失败返回-errno
 */
static int sysvipc_do_msgrcv(Tracee *tracee, struct SysVIpcConfig *config,
                             size_t queue_index, struct SysVIpcMsgQueue *queue)
{
    if (tracee == NULL || config == NULL || queue == NULL)
        return -EINVAL;

    // 检查接收缓冲区长度有效性
    if (config->msgrcv_msgsz < 0)
        return -EINVAL;

    // 检查标志有效性（仅允许指定标志组合）
    int allowed_flags = IPC_NOWAIT | MSG_NOERROR | MSG_COPY | MSG_EXCEPT;
    if ((config->msgrcv_msgflg & ~allowed_flags) != 0)
        return -EINVAL;

    bool is_copy = (config->msgrcv_msgflg & MSG_COPY) != 0;
    // MSG_COPY 标志限制：必须配合 IPC_NOWAIT，且不能与 MSG_EXCEPT 共存
    if (is_copy) {
        if (!(config->msgrcv_msgflg & IPC_NOWAIT))
            return -EINVAL;
        if (config->msgrcv_msgflg & MSG_EXCEPT)
            return -EINVAL;
    }

    struct SysVIpcMsgQueueItem *target_msg = NULL;
    struct SysVIpcMsgQueueItem *candidate = NULL;

    // 查找匹配的消息
    if (is_copy) {
        // MSG_COPY：按索引查找消息（msgtyp 为索引值）
        int index = config->msgrcv_msgtyp;
        int curr_index = 0;
        STAILQ_FOREACH(candidate, queue->items, link) {
            if (curr_index == index) {
                target_msg = candidate;
                break;
            }
            curr_index++;
        }
    } else {
        // 按消息类型过滤查找
        STAILQ_FOREACH(candidate, queue->items, link) {
            if (sysvipc_msg_match(candidate->mtype, config->msgrcv_msgtyp, config->msgrcv_msgflg)) {
                target_msg = candidate;
                break;
            }
        }
    }

    // 未找到匹配消息
    if (target_msg == NULL) {
        if (config->msgrcv_msgflg & IPC_NOWAIT)
            return -ENOMSG; // 非阻塞模式，返回无消息
        else {
            // 阻塞模式，进入等待状态
            config->wait_reason = WR_WAIT_QUEUE_RECV;
            config->waiting_object_index = queue_index;
            return 0;
        }
    }

    // 投递消息
    time_t curr_time = time(NULL);
    int status = sysvipc_msg_deliver(tracee, config, queue, target_msg, curr_time);

    // 非 COPY 模式：消息投递后从队列移除
    if (status >= 0 && !is_copy) {
        queue->stats.msg_qnum--;
        queue->stats.msg_cbytes -= target_msg->mtext_length;
        STAILQ_REMOVE(queue->items, target_msg, SysVIpcMsgQueueItem, link);
        talloc_free(target_msg);
    }

    return status;
}

/**
 * 实现msgget系统调用：创建/获取消息队列
 * @param tracee 进程追踪句柄
 * @param config IPC配置
 * @return 成功返回msgid，失败返回-errno
 */
int sysvipc_msgget(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    word_t msg_key = peek_reg(tracee, CURRENT, SYSARG_1);
    word_t msg_flg = peek_reg(tracee, CURRENT, SYSARG_2);

    struct SysVIpcMsgQueue *queues = config->ipc_namespace->queues;
    size_t num_queues = talloc_array_length(queues);
    size_t unused_slot = 0;
    size_t queue_index = 0;
    bool found_unused = false;
    bool found_existing = false;

    // 查找已存在的消息队列或未使用的槽位
    for (; queue_index < num_queues; queue_index++) {
        if (queues[queue_index].valid) {
            // 找到匹配key的队列
            if (msg_key != IPC_PRIVATE && queues[queue_index].key == (int32_t)msg_key) {
                found_existing = true;
                break;
            }
        } else if (!found_unused) {
            unused_slot = queue_index;
            found_unused = true;
        }
    }

    struct SysVIpcMsgQueue *queue = NULL;
    // 未找到已存在的队列，需创建新队列
    if (!found_existing) {
        // 未指定 IPC_CREAT，返回不存在错误
        if (!(msg_flg & IPC_CREAT))
            return -ENOENT;

        // 分配新槽位
        if (found_unused) {
            queue_index = unused_slot;
            queue = &queues[queue_index];
            memset(queue, 0, sizeof(*queue));
        } else {
            // 扩展队列数组
            queues = talloc_realloc(config->ipc_namespace, queues,
                                  struct SysVIpcMsgQueue, num_queues + 1);
            if (queues == NULL)
                return -ENOMEM;
            config->ipc_namespace->queues = queues;
            queue_index = num_queues;
            queue = &queues[queue_index];
            memset(queue, 0, sizeof(*queue));
        }

        // 初始化新队列
        queue->key = msg_key;
        queue->valid = true;
        queue->items = talloc_zero(config->ipc_namespace, struct SysVIpcMsgQueueItems);
        if (queue->items == NULL) {
            queue->valid = false;
            return -ENOMEM;
        }
        STAILQ_INIT(queue->items);

        // 初始化队列状态
        memset(&queue->stats, 0, sizeof(queue->stats));
        queue->stats.msg_qbytes = SYSVIPC_DEFAULT_QBYTES;
    }
    // 找到已存在的队列
    else {
        queue = &queues[queue_index];
        // 同时指定 IPC_CREAT 和 IPC_EXCL，返回已存在错误
        if ((msg_flg & IPC_CREAT) && (msg_flg & IPC_EXCL))
            return -EEXIST;
    }

    // 生成 msgid：索引+1（避免0值） | 世代号左移12位
    return (int)((queue_index + 1) | (queue->generation << 12));
}

/**
 * 实现msgsnd系统调用：发送消息到队列
 * @param tracee 进程追踪句柄
 * @param config IPC配置
 * @return 成功返回0，失败返回-errno
 */
int sysvipc_msgsnd(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    // 查找目标消息队列
    size_t queue_index;
    struct SysVIpcMsgQueue *queue;
    LOOKUP_IPC_OBJECT(queue_index, queue, config->ipc_namespace->queues);

    // 读取msgsnd参数
    word_t msg_ptr = peek_reg(tracee, CURRENT, SYSARG_2);
    size_t msg_len = (size_t)peek_reg(tracee, CURRENT, SYSARG_3);
    // int msg_flg = (int)peek_reg(tracee, CURRENT, SYSARG_4); // 暂未使用

    // 检查消息长度限制
    if (msg_len == 0 || msg_len > SYSVIPC_MAX_MSG_SIZE)
        return -EINVAL;

    // 读取消息类型（必须为正整数）
    long msg_type = 0;
    int status = read_data(tracee, &msg_type, msg_ptr, sizeof(long));
    if (status < 0)
        return status;
    if (msg_type < 1)
        return -EINVAL;

    // 创建新消息节点
    struct SysVIpcMsgQueueItem *msg_item = talloc_zero(queue->items, struct SysVIpcMsgQueueItem);
    if (msg_item == NULL)
        return -ENOMEM;

    msg_item->mtype = msg_type;
    msg_item->mtext_length = msg_len;
    msg_item->mtext = talloc_array(msg_item, char, msg_len);
    if (msg_item->mtext == NULL) {
        talloc_free(msg_item);
        return -ENOMEM;
    }

    // 读取消息数据
    status = read_data(tracee, msg_item->mtext, msg_ptr + sizeof(long), msg_len);
    if (status < 0) {
        talloc_free(msg_item);
        return status;
    }

    // 更新队列状态
    time_t curr_time = time(NULL);
    queue->stats.msg_lspid = tracee->pid;
    queue->stats.msg_stime = curr_time;

    // 唤醒等待该队列的接收者进程
    Tracee *receiver_tracee;
    struct SysVIpcConfig *receiver_config;
    SYSVIPC_FOREACH_TRACEE(receiver_tracee, receiver_config, config->ipc_namespace) {
        if (receiver_config->wait_reason == WR_WAIT_QUEUE_RECV &&
            receiver_config->waiting_object_index == queue_index &&
            sysvipc_msg_match(msg_item->mtype, receiver_config->msgrcv_msgtyp, receiver_config->msgrcv_msgflg)) {
            receiver_config->chain_state = CSTATE_MSGRCV_RETRY;
            sysvipc_wake_tracee(receiver_tracee, receiver_config, -EAGAIN);
            break;
        }
    }

    // 将消息添加到队列尾部
    STAILQ_INSERT_TAIL(queue->items, msg_item, link);
    queue->stats.msg_qnum++;
    queue->stats.msg_cbytes += msg_len;

    return 0;
}

/**
 * 实现msgrcv系统调用：从队列接收消息
 * @param tracee 进程追踪句柄
 * @param config IPC配置
 * @return 成功返回消息长度，0-等待中，失败返回-errno
 */
int sysvipc_msgrcv(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    // 查找目标消息队列
    size_t queue_index;
    struct SysVIpcMsgQueue *queue;
    LOOKUP_IPC_OBJECT(queue_index, queue, config->ipc_namespace->queues);

    // 读取msgrcv参数并保存到配置
    config->msgrcv_msgp = peek_reg(tracee, CURRENT, SYSARG_2);
    config->msgrcv_msgsz = (int)peek_reg(tracee, CURRENT, SYSARG_3);
    config->msgrcv_msgtyp = (int)peek_reg(tracee, CURRENT, SYSARG_4);
    config->msgrcv_msgflg = (int)peek_reg(tracee, CURRENT, SYSARG_5);

    // 执行消息接收逻辑
    return sysvipc_do_msgrcv(tracee, config, queue_index, queue);
}

/**
 * 重试接收消息（唤醒后回调）
 * @param tracee 进程追踪句柄
 * @param config IPC配置
 * @return 成功返回消息长度，失败返回-errno
 */
int sysvipc_msgrcv_retry(Tracee *tracee, struct SysVIpcConfig *config)
{
    assert(config != NULL && config->chain_state == CSTATE_MSGRCV_RETRY);

    int status = config->status_after_wait;

    // 仅处理 -EAGAIN 唤醒（新消息到达）
    if (status == -EAGAIN) {
        size_t queue_index = config->waiting_object_index;
        assert(queue_index < talloc_array_length(config->ipc_namespace->queues));
        
        struct SysVIpcMsgQueue *queue = &config->ipc_namespace->queues[queue_index];
        assert(queue->valid);
        
        status = sysvipc_do_msgrcv(tracee, config, queue_index, queue);

        // 若仍需要等待（如消息被并发消费），返回 -EINTR 触发重试
        if (config->wait_reason != WR_NOT_WAITING) {
            status = -EINTR;
            config->wait_reason = WR_NOT_WAITING;
        }
    }

    // 重置链式调用状态
    config->chain_state = CSTATE_NOT_CHAINED;
    return status;
}

/**
 * 实现msgctl系统调用：控制消息队列
 * @param tracee 进程追踪句柄
 * @param config IPC配置
 * @return 成功返回0，失败返回-errno
 */
int sysvipc_msgctl(Tracee *tracee, struct SysVIpcConfig *config)
{
    if (tracee == NULL || config == NULL || config->ipc_namespace == NULL)
        return -EINVAL;

    // 查找目标消息队列
    size_t queue_index;
    struct SysVIpcMsgQueue *queue;
    LOOKUP_IPC_OBJECT(queue_index, queue, config->ipc_namespace->queues);

    int cmd = (int)peek_reg(tracee, CURRENT, SYSARG_2);
    word_t buf_ptr = peek_reg(tracee, CURRENT, SYSARG_3);

    // 剥离64位标志，统一处理命令
    cmd &= ~SYSVIPC_IPC_64;

    switch (cmd) {
    case IPC_RMID:
        // 删除消息队列
        {
            // 唤醒所有等待该队列的接收者进程
            Tracee *waiting_tracee;
            struct SysVIpcConfig *waiting_config;
            SYSVIPC_FOREACH_TRACEE(waiting_tracee, waiting_config, config->ipc_namespace) {
                if (waiting_config->wait_reason == WR_WAIT_QUEUE_RECV &&
                    waiting_config->waiting_object_index == queue_index) {
                    sysvipc_wake_tracee(waiting_tracee, waiting_config, -EIDRM);
                }
            }

            // 标记队列无效，释放资源
            queue->valid = false;
            queue->generation++;
            TALLOC_FREE(queue->items);
            return 0;
        }

    case IPC_STAT:
        // 获取队列状态信息
        {
            int status = write_data(tracee, buf_ptr, &queue->stats, sizeof(struct msqid_ds));
            return (status < 0) ? status : 0;
        }

    default:
        // 不支持的命令
        return -EINVAL;
    }
}
