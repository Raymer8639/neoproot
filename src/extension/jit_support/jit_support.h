#pragma once
#include "tracee/tracee.h"
#include <stdbool.h>

// 检测设备是否支持JIT
bool is_jit_supported(void);
// JIT系统调用入口处理函数（在syscall_enter中调用）
int jit_handle_syscall_enter(Tracee *tracee);
