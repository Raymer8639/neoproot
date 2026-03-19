#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#include "tracee/reg.h"
#include "tracee/mem.h"
#include "extension/extension.h"
#include "extension/fake_id0/config.h"
#include "extension/fake_id0/getsockopt.h"

/**
 * 获取对应 pid 的 fake_id0 配置
 * 如果该进程不受 fake_id0 管理，返回 NULL
 */
static Config *get_fake_id_for_pid(pid_t pid)
{
    Tracee *tracee = get_tracee(NULL, pid, false);
    if (!tracee)
        return NULL;

    Extension *ext = get_extension(tracee, fake_id0_callback);
    if (!ext)
        return NULL;

    return talloc_get_type_abort(ext->config, Config);
}

int handle_getsockopt_exit_end(Tracee *tracee)
{
    int level  = peek_reg(tracee, ORIGINAL, SYSARG_2);
    int optname = peek_reg(tracee, ORIGINAL, SYSARG_3);
    word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);

    // 只处理成功的 SO_PEERCRED
    if (level != SOL_SOCKET || optname != SO_PEERCRED || result != 0)
        return 0;

    struct ucred cred;
    word_t cred_addr = peek_reg(tracee, ORIGINAL, SYSARG_4);

    if (read_data(tracee, &cred, cred_addr, sizeof(cred)) < 0)
        return 0;

    Config *cfg = get_fake_id_for_pid(cred.pid);
    if (!cfg)
        return 0;

    // 替换成虚拟的 euid/egid
    cred.uid = cfg->euid;
    cred.gid = cfg->egid;
    write_data(tracee, cred_addr, &cred, sizeof(cred));

    return 0;
}
