# If you want to build outside of the source tree, use the -f option:
#     make -f ${SOMEWHERE}/proot/src/GNUmakefile

# the VPATH variable must point to the actual makefile directory
VPATH := $(dir $(lastword $(MAKEFILE_LIST)))
SRC    := $(dir $(firstword $(MAKEFILE_LIST)))

GIT      = git
RM       = rm
INSTALL  = install
CC       ?= $(CROSS_COMPILE)clang
CXX      ?= $(CROSS_COMPILE)clang++
LD       = $(CC)
STRIP    ?= $(CROSS_COMPILE)strip
OBJCOPY  ?= $(CROSS_COMPILE)objcopy
llvm-objdump  ?= $(CROSS_COMPILE)llvm-objdump

#自动压缩工具（可选：未安装 upx 时自动跳过压缩步骤）
UPX ?= upx
UPX_FLAGS ?= --ultra-brute --lzma --best --compress-icons=0 --no-reloc
HAVE_UPX := $(shell command -v $(UPX) 2>/dev/null)

# 目标架构优化参数，可被命令行覆盖，例如：
#   make MARCH="-march=native"            # 使用本机最优指令集
#   make MARCH="-march=armv8.4-a+memtag"  # 更高版本 ARM 指令集
# 默认针对 ARMv8.2（覆盖绝大多数 64 位 Android 设备）
MARCH ?= -march=armv8.2-a+fp16+dotprod+lse+rcpc+simd+crc+crypto -mtune=generic

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I. -I$(VPATH)

CFLAGS   += -std=c23 -Wall -Wextra -O3 -flto=thin -ffunction-sections -fdata-sections $(MARCH) -munaligned-access -ffast-math -D__ARM_NEON -D__ARM_FEATURE_DOTPROD
CXXFLAGS += -std=c++23 -Wall -Wextra -O3 -flto=thin -ffunction-sections -fdata-sections $(MARCH) -munaligned-access -ffast-math -D__ARM_NEON -D__ARM_FEATURE_DOTPROD

LDFLAGS += -ltalloc -lm -ldl -lc -lstdc++ -flto=thin -Wl,-z,noexecstack -Wl,--gc-sections -Wl,--icf=all,-z,relro,-z,now -Wl,--strip-all -lpthread -s

# --icf=all 仅 lld 支持：有 ld.lld 时显式启用 lld；否则自动移除该选项。
#（Termux 的 clang 默认链接器即为 lld，行为不变）
HAVE_LLD := $(shell command -v ld.lld 2>/dev/null)

# seccomp 过滤器检测（性能关键）：只停靠白名单 syscall，否则全量 ptrace
# 停靠每个 syscall（慢 100-1000 倍）。上游 proot 由 configure 检测，
# 魔改版丢失该检测导致从未启用——所有 syscall 全量停靠的性能根因。
HAVE_SECCOMP_FILTER := $(shell printf '#include <linux/seccomp.h>\n#include <linux/filter.h>\n#include <sys/syscall.h>\n#ifndef __NR_seccomp\n#error no seccomp\n#endif\nint main(void){return 0;}' | $(CC) -x c - -o /dev/null 2>/dev/null && echo 1)
ifeq ($(HAVE_SECCOMP_FILTER),1)
  CPPFLAGS += -DHAVE_SECCOMP_FILTER
endif
ifeq ($(HAVE_LLD),)
LDFLAGS := $(subst --icf=all,,$(LDFLAGS))
else
LDFLAGS += -fuse-ld=lld
endif

# cli/cli.o 去掉 flto 避免链接错误
cli/cli.o: CFLAGS := -std=c23 -Wall -Wextra -O3 -ffunction-sections -fdata-sections $(MARCH) -munaligned-access -ffast-math -D__ARM_NEON -D__ARM_FEATURE_DOTPROD

# syscall 专用高性能优化
syscall/%.o: CFLAGS   := -std=c23 -Wall -Wextra -O3 -flto=thin -ffunction-sections -fdata-sections -fomit-frame-pointer -funroll-loops -fno-stack-protector -fno-strict-overflow -fno-trapping-math $(MARCH) -munaligned-access -ffast-math -D__ARM_NEON -D__ARM_FEATURE_DOTPROD
syscall/%.o: CXXFLAGS := -std=c++23 -Wall -Wextra -O3 -flto=thin -ffunction-sections -fdata-sections -fomit-frame-pointer -funroll-loops -fno-stack-protector -fno-strict-overflow -fno-trapping-math $(MARCH) -munaligned-access -ffast-math -D__ARM_NEON -D__ARM_FEATURE_DOTPROD

OBJECTS += \
    cli/neoproot.o		\
	cli/cli.o		\
	cli/proot.o		\
	cli/note.o		\
	execve/enter.o		\
	execve/exit.o		\
	execve/shebang.o	\
	execve/elf.o		\
	execve/ldso.o		\
	execve/auxv.o		\
	execve/aoxp.o		\
	path/binding.o		\
	path/glue.o		\
	path/canon.o		\
	path/f2fs-bug.o		\
	path/path.o		\
	path/proc.o		\
	path/temp.o		\
	syscall/seccomp.o	\
	syscall/syscall.o	\
	syscall/chain.o		\
	syscall/enter.o		\
	syscall/exit.o		\
	syscall/sysnum.o	\
	syscall/socket.o	\
	syscall/heap.o		\
	syscall/rlimit.o	\
	syscall/pipe_shadow.o	\
	tracee/tracee.o		\
	tracee/mem.o		\
	tracee/reg.o		\
	tracee/event.o		\
	tracee/seccomp.o        \
	tracee/statx.o		\
	ptrace/ptrace.o		\
	ptrace/wait.o		\
	extension/netlink_route/netlink_route.o \
	extension/extension.o	\
	extension/ashmem_memfd/ashmem_memfd.o \
	extension/kompat/kompat.o \
	extension/fake_id0/chown.o \
	extension/fake_id0/chroot.o \
	extension/fake_id0/getsockopt.o \
	extension/fake_id0/sendmsg.o \
	extension/fake_id0/socket.o \
	extension/fake_id0/open.o \
	extension/fake_id0/unlink.o \
	extension/fake_id0/rename.o \
	extension/fake_id0/chmod.o \
	extension/fake_id0/utimensat.o \
	extension/fake_id0/access.o \
	extension/fake_id0/exec.o \
	extension/fake_id0/link.o \
	extension/fake_id0/symlink.o \
	extension/fake_id0/mk.o \
	extension/fake_id0/stat.o \
	extension/fake_id0/helper_functions.o \
	extension/fake_id0/fake_id0.o \
	extension/hidden_files/hidden_files.o \
	extension/mountinfo/mountinfo.o \
	extension/port_switch/port_switch.o \
	extension/sysvipc/sysvipc.o \
	extension/sysvipc/sysvipc_msg.o \
	extension/sysvipc/sysvipc_sem.o \
	extension/sysvipc/sysvipc_shm.o \
	extension/link2symlink/link2symlink.o \
	extension/fix_symlink_size/fix_symlink_size.o

# 仅 arm64：彻底移除 32bit loader 探测
define define_from_arch.h
$2$1 := $(shell $(CC) $1 -E -dM -DNO_LIBC_HEADER $(SRC)/arch.h | grep -w $2 | cut -f 3 -d ' ')
endef

ifdef PROOT_UNBUNDLE_LOADER
  CFLAGS += "-DPROOT_UNBUNDLE_LOADER=\"$(PROOT_UNBUNDLE_LOADER)\""
neoproot: | loader/loader
else
  OBJECTS += loader/loader-wrapped.o
endif

.DEFAULT_GOAL = neoproot
all: neoproot

######################################################################
# Beautified output

quiet_GEN = @echo "  GEN	$@"; $(GEN)
quiet_CC  = @echo "  CC	$@"; $(CC)
quiet_LD  = @echo "  LD	$@"; $(LD)
quiet_INSTALL = @echo "  INSTALL	$?"; $(INSTALL)
quiet_UPX = @echo "  UPX	$@"; $(UPX)

V = 0
ifeq ($(V), 0)
    quiet = quiet_
    Q     = @
    silently = >/dev/null 2>&1
else
    quiet =
    Q     =
    silently =
endif

######################################################################
# Auto-configuration - Disabled to prevent auto-generation of build.h

BUILD_ID_NONE := $(shell if ld --build-id=none --version >/dev/null 2>&1; then echo ',--build-id=none'; fi)

USE_BUILD_H := $(patsubst $(SRC)%.c,%.o,$(shell grep -E -sl 'include[[:space:]]+"build.h"' $(patsubst %.o,$(SRC)%.c,$(OBJECTS))))
$(USE_BUILD_H): build.h

######################################################################
# build.h 生成规则
# 原上游的自动配置（CHECK_*）已被禁用，这里提供轻量替代：
# VERSION 可由命令行覆盖（make VERSION="x.y.z-scicat"），
# 未指定时自动取 git 描述；cli/proot.h 中另有内置默认值兜底。

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo neoproot-unknown)

build.h:
	@echo "  GEN	$@"
	@echo "/* This file is auto-generated, edit at your own risk.  */" > $@
	@echo "#ifndef BUILD_H" >> $@
	@echo "#define BUILD_H" >> $@
	@echo "#define VERSION \"$(VERSION)\"" >> $@
	@echo "#endif /* BUILD_H */" >> $@

######################################################################
# Build rules

COMPILE = $($(quiet)CC) $(CPPFLAGS) $(CFLAGS) -MD -c $(SRC)$< -o $@
LINK    = $($(quiet)LD) -o $@ $^ $(LDFLAGS)

OBJIFY = $($(quiet)GEN)									\
	$(OBJCOPY)									\
		--input-target=binary								\
		--output-target=`env LANG=C $(llvm-objdump) -f cli/cli.o |				\
			grep 'file format' | awk '{print $$4}'`				\
		--binary-architecture `env LANG=C $(llvm-objdump) -f cli/cli.o |		\
				grep architecture | cut -f 1 -d , | awk '{print $$2}'`	\
		$< $@

#链接 + strip + 自动 upx 压缩（未安装 upx 时跳过压缩）
neoproot: $(OBJECTS)
	$(LINK)
	$(STRIP) --strip-all $@
ifeq ($(HAVE_UPX),)
	@echo "  SKIP	upx 未安装，跳过压缩（安装 upx 可进一步减小体积）"
else
	$(quiet_UPX) $(UPX_FLAGS) $@ $(silently)
	# 注意：UPX 压缩后不能再 strip（二进制已无节表，GNU strip 会报 "has no sections" 导致 CI 失败）
endif

%.o: $(SRC)%.c
	@mkdir -p $(dir $@)
	$(COMPILE)

# 显式 C++ 编译规则（tracee/mem.cpp、tracee/reg.cpp），避免依赖 make 隐式规则，
# 并启用 -MD 依赖跟踪
%.o: $(SRC)%.cpp
	@mkdir -p $(dir $@)
	$($(quiet)CC) $(CPPFLAGS) $(CXXFLAGS) -MD -c $(SRC)$< -o $@

cli/%-licenses.o: licenses cli/cli.o
	$(OBJIFY)

######################################################################
# Build rules for the loader (arm64 only, NO 32-bit)

LOADER_OBJECTS = loader/loader.o loader/assembly.o

$(eval $(call define_from_arch.h,,LOADER_ARCH_CFLAGS))
$(eval $(call define_from_arch.h,,LOADER_ADDRESS))

LOADER_CFLAGS  += -fPIC -ffreestanding $(LOADER_ARCH_CFLAGS)
LOADER_LDFLAGS += -static -nostdlib -Wl$(BUILD_ID_NONE),-Ttext=$(LOADER_ADDRESS),--rosegment,-z,noexecstack

# loader 链接同样需要 lld（--rosegment 是 lld 专属选项；
# LLVM 官方预编译 clang 默认链接器是自带 lld，但发行版 clang（如 Ubuntu）默认 GNU ld 会失败）。
# 注意：必须在 LOADER_LDFLAGS 赋值之后追加。
ifeq ($(HAVE_LLD),)
# 无 lld 时改用 GNU ld 可接受的选项（--rosegment 是 lld 专属，去掉后功能等价）
LOADER_LDFLAGS := -static -nostdlib -Wl$(BUILD_ID_NONE),-Ttext=$(LOADER_ADDRESS),-z,noexecstack
else
LOADER_LDFLAGS += -fuse-ld=lld
endif

loader/loader.o: $(SRC)loader/loader.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(filter-out -flto=thin,$(CXXFLAGS)) $(LOADER_CFLAGS) -MD -c $(SRC)$< -o $@

loader/assembly.o: $(SRC)loader/assembly.S
	@mkdir -p $(dir $@)
	$(COMPILE) $(LOADER_CFLAGS)

loader/loader: $(LOADER_OBJECTS)
	$($(quiet)LD) -o $@ $^ $(LOADER_LDFLAGS)

.INTERMEDIATE: loader.exe
loader.exe: loader/loader
	$(Q)cp $< $@
	$(Q)$(STRIP) $@

loader/loader-wrapped.o: loader.exe cli/cli.o
	$(OBJIFY)

######################################################################
# Dependencies

.DELETE_ON_ERROR:
$(OBJECTS) $(LOADER_OBJECTS): $(firstword $(MAKEFILE_LIST))

DEPS = $(OBJECTS:.o=.d) $(LOADER_OBJECTS:.o=.d)
-include $(DEPS)

######################################################################
# PHONY targets

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: clean distclean install uninstall
clean distclean:
	-$(RM) -f $(OBJECTS) $(LOADER_OBJECTS) neoproot loader/loader $(DEPS) licenses

install: neoproot
	$($(quiet)INSTALL) -D $< $(DESTDIR)$(BINDIR)/$<
ifdef PROOT_UNBUNDLE_LOADER
	$(INSTALL) -D loader/loader $(PROOT_UNBUNDLE_LOADER)/loader
endif

uninstall:
	-$(RM) -f $(DESTDIR)$(BINDIR)/neoproot
ifdef PROOT_UNBUNDLE_LOADER
	-$(RM) -f $(PROOT_UNBUNDLE_LOADER)/loader
endif
