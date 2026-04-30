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

#define SYSVIPC_MAX_MSG_SIZE  0xFFFFU
#define SYSVIPC_DEFAULT_QBYTES (1024U * 64U)

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ALWAYS_INLINE __attribute__((always_inline, flatten))
#define HOT __attribute__((hot))

static ALWAYS_INLINE bool msg_match(int sender_type, int receiver_filter, int receiver_flag) {
    bool matched = (receiver_filter == 0) ||
                   (sender_type == receiver_filter) ||
                   (receiver_filter < 0 && sender_type <= -receiver_filter);
    if (receiver_flag & MSG_EXCEPT) matched = !matched;
    return matched;
}

static ALWAYS_INLINE int msg_deliver(Tracee *restrict tracee, struct SysVIpcConfig *restrict config,
                                     struct SysVIpcMsgQueue *restrict queue,
                                     struct SysVIpcMsgQueueItem *restrict msg, time_t delivery_time) {
    if (UNLIKELY(!tracee || !config || !queue || !msg)) return -EINVAL;
    size_t recv_len = (size_t)config->msgrcv_msgsz;
    size_t data_len = msg->mtext_length;
    if (data_len > recv_len) {
        if (!(config->msgrcv_msgflg & MSG_NOERROR))
            return -E2BIG;
        data_len = recv_len;
    }
    int st = write_data(tracee, config->msgrcv_msgp, &msg->mtype, sizeof(long));
    if (UNLIKELY(st < 0)) return st;
    st = write_data(tracee, config->msgrcv_msgp + sizeof(long), msg->mtext, data_len);
    if (UNLIKELY(st < 0)) return st;
    queue->stats.msg_lrpid = tracee->pid;
    queue->stats.msg_rtime = delivery_time;
    return (int)data_len;
}

static int do_msgrcv(Tracee *restrict tracee, struct SysVIpcConfig *restrict config,
                     size_t queue_index, struct SysVIpcMsgQueue *restrict queue) {
    if (UNLIKELY(!tracee || !config || !queue)) return -EINVAL;
    if (config->msgrcv_msgsz < 0) return -EINVAL;
    static const int allowed = IPC_NOWAIT | MSG_NOERROR | MSG_COPY | MSG_EXCEPT;
    if ((config->msgrcv_msgflg & ~allowed) != 0) return -EINVAL;
    bool is_copy = (config->msgrcv_msgflg & MSG_COPY) != 0;
    if (is_copy && (!(config->msgrcv_msgflg & IPC_NOWAIT) || (config->msgrcv_msgflg & MSG_EXCEPT)))
        return -EINVAL;

    struct SysVIpcMsgQueueItem *target = NULL;
    struct SysVIpcMsgQueueItem *candidate = NULL;
    if (is_copy) {
        int idx = config->msgrcv_msgtyp;
        int cur = 0;
        STAILQ_FOREACH(candidate, queue->items, link) {
            if (cur == idx) { target = candidate; break; }
            cur++;
        }
    } else {
        STAILQ_FOREACH(candidate, queue->items, link) {
            if (msg_match(candidate->mtype, config->msgrcv_msgtyp, config->msgrcv_msgflg)) {
                target = candidate; break;
            }
        }
    }
    if (!target) {
        if (config->msgrcv_msgflg & IPC_NOWAIT) return -ENOMSG;
        config->wait_reason = WR_WAIT_QUEUE_RECV;
        config->waiting_object_index = queue_index;
        return 0;
    }
    time_t now = time(NULL);
    int st = msg_deliver(tracee, config, queue, target, now);
    if (st >= 0 && !is_copy) {
        queue->stats.msg_qnum--;
        queue->stats.msg_cbytes -= target->mtext_length;
        STAILQ_REMOVE(queue->items, target, SysVIpcMsgQueueItem, link);
        talloc_free(target);
    }
    return st;
}

HOT int sysvipc_msgget(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    word_t key = peek_reg(tracee, CURRENT, SYSARG_1);
    word_t flg = peek_reg(tracee, CURRENT, SYSARG_2);
    struct SysVIpcMsgQueue *queues = config->ipc_namespace->queues;
    size_t num = talloc_array_length(queues);
    size_t unused = 0, idx = 0;
    bool found_unused = false, found_existing = false;
    for (; idx < num; ++idx) {
        if (queues[idx].valid) {
            if (key != IPC_PRIVATE && queues[idx].key == (int32_t)key) {
                found_existing = true; break;
            }
        } else if (!found_unused) {
            unused = idx; found_unused = true;
        }
    }
    struct SysVIpcMsgQueue *q = NULL;
    if (!found_existing) {
        if (!(flg & IPC_CREAT)) return -ENOENT;
        if (found_unused) {
            idx = unused;
            q = &queues[idx];
            memset(q, 0, sizeof(*q));
        } else {
            queues = talloc_realloc(config->ipc_namespace, queues, struct SysVIpcMsgQueue, num + 1);
            if (!queues) return -ENOMEM;
            config->ipc_namespace->queues = queues;
            idx = num;
            q = &queues[idx];
            memset(q, 0, sizeof(*q));
        }
        q->key = key;
        q->valid = true;
        q->items = talloc_zero(config->ipc_namespace, struct SysVIpcMsgQueueItems);
        if (!q->items) { q->valid = false; return -ENOMEM; }
        STAILQ_INIT(q->items);
        memset(&q->stats, 0, sizeof(q->stats));
        q->stats.msg_qbytes = SYSVIPC_DEFAULT_QBYTES;
    } else {
        q = &queues[idx];
        if ((flg & IPC_CREAT) && (flg & IPC_EXCL)) return -EEXIST;
    }
    return (int)((idx + 1) | ((unsigned int)q->generation << 12));
}

HOT int sysvipc_msgsnd(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx;
    struct SysVIpcMsgQueue *q;
    LOOKUP_IPC_OBJECT(idx, q, config->ipc_namespace->queues);
    word_t msg_ptr = peek_reg(tracee, CURRENT, SYSARG_2);
    size_t len = (size_t)peek_reg(tracee, CURRENT, SYSARG_3);
    if (len == 0 || len > SYSVIPC_MAX_MSG_SIZE) return -EINVAL;
    long type = 0;
    int st = read_data(tracee, &type, msg_ptr, sizeof(long));
    if (UNLIKELY(st < 0)) return st;
    if (type < 1) return -EINVAL;
    struct SysVIpcMsgQueueItem *item = talloc_zero(q->items, struct SysVIpcMsgQueueItem);
    if (!item) return -ENOMEM;
    item->mtype = type;
    item->mtext_length = len;
    item->mtext = talloc_array(item, char, len);
    if (!item->mtext) { talloc_free(item); return -ENOMEM; }
    st = read_data(tracee, item->mtext, msg_ptr + sizeof(long), len);
    if (UNLIKELY(st < 0)) { talloc_free(item); return st; }
    time_t now = time(NULL);
    q->stats.msg_lspid = tracee->pid;
    q->stats.msg_stime = now;
    Tracee *rt;
    struct SysVIpcConfig *rcfg;
    SYSVIPC_FOREACH_TRACEE(rt, rcfg, config->ipc_namespace) {
        if (rcfg->wait_reason == WR_WAIT_QUEUE_RECV &&
            rcfg->waiting_object_index == idx &&
            msg_match(item->mtype, rcfg->msgrcv_msgtyp, rcfg->msgrcv_msgflg)) {
            rcfg->chain_state = CSTATE_MSGRCV_RETRY;
            sysvipc_wake_tracee(rt, rcfg, -EAGAIN);
            break;
        }
    }
    STAILQ_INSERT_TAIL(q->items, item, link);
    q->stats.msg_qnum++;
    q->stats.msg_cbytes += len;
    return 0;
}

HOT int sysvipc_msgrcv(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx;
    struct SysVIpcMsgQueue *q;
    LOOKUP_IPC_OBJECT(idx, q, config->ipc_namespace->queues);
    config->msgrcv_msgp = peek_reg(tracee, CURRENT, SYSARG_2);
    config->msgrcv_msgsz = (int)peek_reg(tracee, CURRENT, SYSARG_3);
    config->msgrcv_msgtyp = (int)peek_reg(tracee, CURRENT, SYSARG_4);
    config->msgrcv_msgflg = (int)peek_reg(tracee, CURRENT, SYSARG_5);
    return do_msgrcv(tracee, config, idx, q);
}

HOT int sysvipc_msgrcv_retry(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    assert(config && config->chain_state == CSTATE_MSGRCV_RETRY);
    int st = config->status_after_wait;
    if (st == -EAGAIN) {
        size_t idx = config->waiting_object_index;
        assert(idx < talloc_array_length(config->ipc_namespace->queues));
        struct SysVIpcMsgQueue *q = &config->ipc_namespace->queues[idx];
        assert(q->valid);
        st = do_msgrcv(tracee, config, idx, q);
        if (config->wait_reason != WR_NOT_WAITING) {
            st = -EINTR;
            config->wait_reason = WR_NOT_WAITING;
        }
    }
    config->chain_state = CSTATE_NOT_CHAINED;
    return st;
}

HOT int sysvipc_msgctl(Tracee *restrict tracee, struct SysVIpcConfig *restrict config) {
    if (UNLIKELY(!tracee || !config || !config->ipc_namespace)) return -EINVAL;
    size_t idx;
    struct SysVIpcMsgQueue *q;
    LOOKUP_IPC_OBJECT(idx, q, config->ipc_namespace->queues);
    int cmd = (int)peek_reg(tracee, CURRENT, SYSARG_2);
    word_t buf = peek_reg(tracee, CURRENT, SYSARG_3);
    cmd &= ~SYSVIPC_IPC_64;
    switch (cmd) {
    case IPC_RMID: {
        Tracee *wt;
        struct SysVIpcConfig *wcfg;
        SYSVIPC_FOREACH_TRACEE(wt, wcfg, config->ipc_namespace) {
            if (wcfg->wait_reason == WR_WAIT_QUEUE_RECV && wcfg->waiting_object_index == idx)
                sysvipc_wake_tracee(wt, wcfg, -EIDRM);
        }
        q->valid = false;
        q->generation++;
        TALLOC_FREE(q->items);
        return 0;
    }
    case IPC_STAT: {
        int st = write_data(tracee, buf, &q->stats, sizeof(struct msqid_ds));
        return st < 0 ? st : 0;
    }
    default:
        return -EINVAL;
    }
}
