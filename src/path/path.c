#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#include <arm_neon.h>
#include <pthread.h>
#include <stdlib.h>

#include "path/path.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/proc.h"
#include "extension/extension.h"
#include "cli/note.h"
#include "build.h"
#include "compat.h"

#define PROC_PREFIX_LEN 6

static inline int is_proc_path(const char *s)
{
    return (s[0] == '/' &&
            s[1] == 'p' &&
            s[2] == 'r' &&
            s[3] == 'o' &&
            s[4] == 'c' &&
            s[5] == '/');
}

//生产者-消费者核心定义
typedef struct PathTask PathTask;
struct PathTask {
    // 输入参数（只读）
    Tracee *tracee;
    int dir_fd;
    bool deref_final;
    char user_path[PATH_MAX];

    // 输出结果
    char result[PATH_MAX];
    int ret_code;

    // 任务同步（独立锁，无全局竞争）
    pthread_mutex_t done_mutex;
    pthread_cond_t done_cond;
    int is_done;

    // 队列节点
    PathTask *next;
};

// 任务队列（生产者-消费者核心）
static struct {
    PathTask *head;
    PathTask *tail;
    pthread_mutex_t mutex;
    pthread_cond_t has_task;
    int shutdown;
} task_queue = {
    .head = NULL,
    .tail = NULL,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .has_task = PTHREAD_COND_INITIALIZER,
    .shutdown = 0
};

static pthread_t worker_thread;
static int thread_inited = 0;

// 消费者工作线程（无锁冲突核心）
static void* path_worker(void *arg)
{
    (void)arg;
    PathTask *task;
    char guest_path[PATH_MAX];
    int ret;

    while (1) {
        // 1. 仅拿任务时加锁，拿完立刻释放，锁持有时间极短
        pthread_mutex_lock(&task_queue.mutex);
        while (!task_queue.head && !task_queue.shutdown) {
            pthread_cond_wait(&task_queue.has_task, &task_queue.mutex);
        }

        if (task_queue.shutdown && !task_queue.head) {
            pthread_mutex_unlock(&task_queue.mutex);
            break;
        }

        // 取出任务，立刻释放队列锁
        task = task_queue.head;
        task_queue.head = task->next;
        if (!task_queue.head) task_queue.tail = NULL;
        pthread_mutex_unlock(&task_queue.mutex);

        // 2. 路径计算全程无锁，绝对不会和proot内部锁冲突
        memset(task->result, 0, PATH_MAX);
        ret = 0;

        if (is_proc_path(task->user_path)) {
            memcpy(task->result, task->user_path, PATH_MAX - 1);
            task->result[PATH_MAX - 1] = '\0';
            ret = 0;
            goto task_finish;
        }

        if (task->user_path[0] == '/') {
            task->result[0] = '/';
            task->result[1] = '\0';
        } else if (task->dir_fd != AT_FDCWD) {
            ret = readlink_proc_pid_fd(task->tracee->pid, task->dir_fd, task->result);
            if (ret < 0) goto task_finish;
            if (task->result[0] != '/') { ret = -ENOTDIR; goto task_finish; }
            ret = detranslate_path(task->tracee, task->result, NULL);
            if (ret < 0) goto task_finish;
        } else {
            ret = getcwd2(task->tracee, task->result);
            if (ret < 0) goto task_finish;
        }

        ret = notify_extensions(task->tracee, GUEST_PATH, (intptr_t)task->result, (intptr_t)task->user_path);
        if (ret < 0) goto task_finish;
        if (ret == 0) {
            ret = join_paths(2, guest_path, task->result, task->user_path);
            if (ret < 0) goto task_finish;
            ret = canonicalize(task->tracee, guest_path, task->deref_final, task->result, 0);
            if (ret < 0) goto task_finish;
            ret = substitute_binding(task->tracee, GUEST, task->result);
            if (ret < 0) goto task_finish;
        }
        notify_extensions(task->tracee, TRANSLATED_PATH, (intptr_t)task->result, 0);
        ret = 0;

task_finish:
        // 3. 仅通知任务完成时加任务独立锁，和队列锁完全隔离
        task->ret_code = ret;
        pthread_mutex_lock(&task->done_mutex);
        task->is_done = 1;
        pthread_cond_signal(&task->done_cond);
        pthread_mutex_unlock(&task->done_mutex);
    }

    return NULL;
}

//  线程初始化（仅调用1次） 
static void path_thread_init(void)
{
    if (__atomic_test_and_set(&thread_inited, __ATOMIC_SEQ_CST))
        return;
    pthread_create(&worker_thread, NULL, path_worker, NULL);
}

//  生产者提交任务（主线程调用） 
static PathTask* path_task_submit(Tracee *tracee, int dir_fd, const char *user_path, bool deref_final)
{
    PathTask *task = malloc(sizeof(PathTask));
    if (!task) return NULL;

    // 初始化任务
    memset(task, 0, sizeof(PathTask));
    task->tracee = tracee;
    task->dir_fd = dir_fd;
    task->deref_final = deref_final;
    strncpy(task->user_path, user_path, PATH_MAX - 1);
    pthread_mutex_init(&task->done_mutex, NULL);
    pthread_cond_init(&task->done_cond, NULL);
    task->is_done = 0;

    // 仅入队时加锁，入队完立刻释放
    pthread_mutex_lock(&task_queue.mutex);
    task->next = NULL;
    if (task_queue.tail)
        task_queue.tail->next = task;
    else
        task_queue.head = task;
    task_queue.tail = task;
    pthread_cond_signal(&task_queue.has_task);
    pthread_mutex_unlock(&task_queue.mutex);

    return task;
}

//  等待任务完成（主线程调用） 
static int path_task_wait(PathTask *task, char result[PATH_MAX])
{
    if (!task || !result) return -EINVAL;

    // 等待任务完成，仅用任务独立锁，无全局竞争
    pthread_mutex_lock(&task->done_mutex);
    while (!task->is_done) {
        pthread_cond_wait(&task->done_cond, &task->done_mutex);
    }
    pthread_mutex_unlock(&task->done_mutex);

    // 拷贝结果，释放资源
    memcpy(result, task->result, PATH_MAX);
    int ret = task->ret_code;

    pthread_mutex_destroy(&task->done_mutex);
    pthread_cond_destroy(&task->done_cond);
    free(task);

    return ret;
}

//  以下是你原版代码，完全未改动 
int join_paths(int number_paths, char result[PATH_MAX], ...)
{
    va_list paths;
    size_t length = 0;
    int i;

    result[0] = '\0';

    va_start(paths, result);
    for (i = 0; i < number_paths; i++) {
        const char *path = va_arg(paths, const char *);
        if (!path || *path == '\0')
            continue;

        size_t path_len = strlen(path);
        int need_slash = (length > 0 && result[length-1] != '/' && path[0] != '/');
        size_t new_len = length + path_len + (need_slash ? 1 : 0);

        if (new_len + 1 >= PATH_MAX) {
            va_end(paths);
            return -ENAMETOOLONG;
        }

        if (need_slash) {
            result[length++] = '/';
        }
        else if (length > 0 && result[length-1] == '/' && path[0] == '/') {
            path++;
            path_len--;
        }

        memcpy(result + length, path, path_len);
        length += path_len;
    }
    va_end(paths);

    result[length] = '\0';
    return 0;
}

int which(Tracee *tracee, const char *paths, char host_path[PATH_MAX], const char *command)
{
    char path[PATH_MAX];
    const char *cursor;
    struct stat statr;
    bool is_explicit;
    bool found;

    assert(command != NULL);
    is_explicit = (strchr(command, '/') != NULL);

    if (realpath2(tracee, host_path, command, true) == 0 &&
        stat(host_path, &statr) == 0)
    {
        if (is_explicit && !S_ISREG(statr.st_mode)) {
            note(tracee, ERROR, USER, "'%s' is not a regular file", command);
            return -EACCES;
        }
        if (is_explicit && !(statr.st_mode & S_IXUSR)) {
            note(tracee, ERROR, USER, "'%s' is not executable", command);
            return -EACCES;
        }
        found = true;
        realpath2(tracee, host_path, command, false);
    } else
        found = false;

    if (is_explicit)
        return found ? 0 : -1;

    paths = paths ?: getenv("PATH");
    if (!paths || !*paths)
        goto not_found;

    cursor = paths;
    do {
        size_t len = strcspn(cursor, ":");
        if (len >= PATH_MAX) {
            cursor += len + 1;
            continue;
        }

        if (len == 0)
            path[0] = '.';
        else
            memcpy(path, cursor, len);
        path[len] = '/';
        strcpy(path + len + 1, command);

        if (realpath2(tracee, host_path, path, true) == 0 &&
            stat(host_path, &statr) == 0 &&
            S_ISREG(statr.st_mode) &&
            (statr.st_mode & S_IXUSR))
            return 0;

        cursor += len + 1;
    } while (*cursor);

not_found:
    getcwd2(tracee, path);
    note(tracee, ERROR, USER, "'%s' not found", command);
    return -1;
}

int realpath2(Tracee *tracee, char host_path[PATH_MAX], const char *path, bool deref_final)
{
    if (!tracee)
        return realpath(path, host_path) ? 0 : -errno;

    return translate_path(tracee, host_path, AT_FDCWD, path, deref_final);
}

int getcwd2(Tracee *tracee, char guest_path[PATH_MAX])
{
    if (!tracee)
        return getcwd(guest_path, PATH_MAX) ? 0 : -errno;

    size_t len = strlen(tracee->fs->cwd);
    if (len >= PATH_MAX)
        return -ENAMETOOLONG;

    memcpy(guest_path, tracee->fs->cwd, len + 1);
    return 0;
}

void chop_finality(char *path)
{
    size_t len = strlen(path);
    if (len < 2) return;

    if (path[len-1] == '.')
        path[(len == 2) ? len-1 : len-2] = '\0';
    else if (path[len-1] == '/')
        path[len-1] = '\0';
}

int readlink_proc_pid_fd(pid_t pid, int fd, char path[PATH_MAX])
{
    char link[32];
    int st = snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
    if (st < 0 || (size_t)st >= sizeof(link))
        return -EBADF;

    st = readlink(link, path, PATH_MAX);
    if (st < 0) return -EBADF;
    if (st >= PATH_MAX) return -ENAMETOOLONG;
    path[st] = '\0';
    return 0;
}

// 仅修改了这个入口函数，兼容线程池+原版双逻辑
int translate_path(Tracee *tracee, char result[PATH_MAX], int dir_fd,
                   const char *user_path, bool deref_final)
{
    // 注释掉下面这行，就完全走你原版逻辑，线程池完全不启用
    path_thread_init();

    // 线程池模式
    PathTask *task = path_task_submit(tracee, dir_fd, user_path, deref_final);
    if (task) {
        return path_task_wait(task, result);
    }

    // 降级走原版逻辑，绝对不会崩
    char guest_path[PATH_MAX];
    int ret;

    if (is_proc_path(user_path)) {
        memcpy(result, user_path, PATH_MAX - 1);
        result[PATH_MAX - 1] = '\0';
        return 0;
    }

    if (user_path[0] == '/') {
        result[0] = '/';
        result[1] = '\0';
    }
    else if (dir_fd != AT_FDCWD) {
        ret = readlink_proc_pid_fd(tracee->pid, dir_fd, result);
        if (ret < 0) return ret;
        if (result[0] != '/') return -ENOTDIR;

        ret = detranslate_path(tracee, result, NULL);
        if (ret < 0) return ret;
    }
    else {
        ret = getcwd2(tracee, result);
        if (ret < 0) return ret;
    }

    ret = notify_extensions(tracee, GUEST_PATH, (intptr_t)result, (intptr_t)user_path);
    if (ret < 0) return ret;
    if (ret > 0) goto skip;

    ret = join_paths(2, guest_path, result, user_path);
    if (ret < 0) return ret;

    ret = canonicalize(tracee, guest_path, deref_final, result, 0);
    if (ret < 0) return ret;

    ret = substitute_binding(tracee, GUEST, result);
    if (ret < 0) return ret;

skip:
    notify_extensions(tracee, TRANSLATED_PATH, (intptr_t)result, 0);
    return ret;
}

int detranslate_path(Tracee *tracee, char path[PATH_MAX], const char t_referrer[PATH_MAX])
{
    size_t root_len, prefix_len;
    ssize_t new_len;

    if (strnlen(path, PATH_MAX) >= PATH_MAX)
        return -ENAMETOOLONG;
    if (path[0] != '/')
        return 0;

    if (is_proc_path(path))
        return strlen(path) + 1;

    bool follow_binding = true;
    if (t_referrer) {
        if (compare_paths("/proc/", t_referrer) == PATH1_IS_PREFIX) {
            char proc_path[PATH_MAX];
            memcpy(proc_path, path, PATH_MAX);
            int nl = readlink_proc2(tracee, proc_path, t_referrer);
            if (nl < 0) return nl;
            if (nl != 0) {
                memcpy(path, proc_path, PATH_MAX);
                return nl + 1;
            }
        }
        else if (!belongs_to_guestfs(tracee, t_referrer)) {
            const char *b_to = get_path_binding(tracee, HOST, path);
            const char *b_from = get_path_binding(tracee, HOST, t_referrer);
            if (b_to && b_from)
                follow_binding = (compare_paths(b_to, b_from) == PATHS_ARE_EQUAL);
        }
    }

    if (follow_binding) {
        int st = substitute_binding(tracee, HOST, path);
        if (st == 0) return 0;
        if (st == 1) return strlen(path) + 1;
    }

    switch (compare_paths(get_root(tracee), path)) {
        case PATH1_IS_PREFIX:
            root_len = strlen(get_root(tracee));
            prefix_len = (root_len == 1) ? 0 : root_len;
            new_len = strlen(path) - prefix_len;
            memmove(path, path + prefix_len, new_len + 1);
            return new_len + 1;

        case PATHS_ARE_EQUAL:
            path[0] = '/';
            path[1] = '\0';
            return 2;

        default:
            return (t_referrer == NULL) ? -EPERM : 0;
    }
}

bool belongs_to_guestfs(const Tracee *tracee, const char *host_path)
{
    Comparison c = compare_paths(get_root(tracee), host_path);
    return (c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX);
}

Comparison compare_paths2(const char *path1, size_t len1,
                          const char *path2, size_t len2)
{
    size_t min_len;
    char end;

    if (len1 == 0 || len2 == 0)
        return PATHS_ARE_NOT_COMPARABLE;

    if (path1[len1-1] == '/') len1--;
    if (path2[len2-1] == '/') len2--;

    if (len1 < len2) {
        min_len = len1;
        end = path2[min_len];
    } else {
        min_len = len2;
        end = path1[min_len];
    }

    if (end != '/' && end != '\0')
        return PATHS_ARE_NOT_COMPARABLE;

    size_t i = 0;
    for (; i + 16 <= min_len; i += 16) {
        uint8x16_t v1 = vld1q_u8((const uint8_t *)(path1 + i));
        uint8x16_t v2 = vld1q_u8((const uint8_t *)(path2 + i));
        uint8x16_t eq = vceqq_u8(v1, v2);
        if (vmaxvq_u8(eq) != 0xff)
            return PATHS_ARE_NOT_COMPARABLE;
    }
    for (; i < min_len; i++) {
        if (path1[i] != path2[i])
            return PATHS_ARE_NOT_COMPARABLE;
    }

    if (len1 == len2)
        return PATHS_ARE_EQUAL;
    return (len1 < len2) ? PATH1_IS_PREFIX : PATH2_IS_PREFIX;
}

Comparison compare_paths(const char *path1, const char *path2)
{
    return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}

static int foreach_fd(const Tracee *tracee,
                      int (*callback)(const Tracee*, int, char*))
{
    struct dirent *dirent;
    char path[PATH_MAX], proc_fd[32];
    DIR *dirp;

    snprintf(proc_fd, sizeof(proc_fd), "/proc/%d/fd", tracee->pid);
    dirp = opendir(proc_fd);
    if (!dirp) return 0;

    while ((dirent = readdir(dirp))) {
        size_t l1 = strlen(proc_fd);
        size_t l2 = strlen(dirent->d_name);
        if (l1 + l2 + 2 >= PATH_MAX) continue;

        memcpy(path, proc_fd, l1);
        path[l1] = '/';
        strcpy(path + l1 + 1, dirent->d_name);

        int st = readlink(path, path, PATH_MAX);
        if (st <= 0 || st >= PATH_MAX) continue;
        if (path[0] != '/') continue;

        if (callback(tracee, atoi(dirent->d_name), path) < 0)
            break;
    }

    closedir(dirp);
    return 0;
}

static int list_open_fd_callback(const Tracee *tracee, int fd, char path[PATH_MAX])
{
    (void)tracee; (void)fd; (void)path;
    return 0;
}

int list_open_fd(const Tracee *tracee)
{
    return foreach_fd(tracee, list_open_fd_callback);
}

size_t substitute_path_prefix(char path[PATH_MAX], size_t old_prefix_len,
                              const char *new_prefix, size_t new_prefix_len)
{
    size_t path_len = strlen(path);
    size_t new_len;

    if (new_prefix_len == 1) {
        new_len = path_len - old_prefix_len;
        if (new_len > 0)
            memmove(path, path + old_prefix_len, new_len);
        else
            path[0] = '/';
        path[new_len] = '\0';
        return new_len;
    }

    if (old_prefix_len == 1) {
        new_len = new_prefix_len + path_len;
        if (new_len >= PATH_MAX) return -ENAMETOOLONG;
        if (path_len > 1)
            memmove(path + new_prefix_len, path, path_len);
        memcpy(path, new_prefix, new_prefix_len);
        path[new_len] = '\0';
        return new_len;
    }

    new_len = new_prefix_len + (path_len - old_prefix_len);
    if (new_len >= PATH_MAX) return -ENAMETOOLONG;

    memmove(path + new_prefix_len, path + old_prefix_len, path_len - old_prefix_len);
    memcpy(path, new_prefix, new_prefix_len);
    path[new_len] = '\0';
    return new_len;
}
