# 自动检测平台 + 架构 → 自动跳去对应编译
UNAME_OS := $(shell uname -o 2>/dev/null || echo GNU/Linux)
UNAME_ARCH := $(shell uname -m 2>/dev/null)

ifeq ($(UNAME_OS),Android)
  include TermuxMake
else
  ifeq ($(UNAME_ARCH),aarch64)
    include Linuxaarch64Make
  else
    include LinuxMake
  endif
endif
