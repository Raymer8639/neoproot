# If you want to build outside of the source tree, use the -f option:
#     make -f ${SOMEWHERE}/proot/src/GNUmakefile

# the VPATH variable must point to the actual makefile directory
VPATH := $(dir $(lastword $(MAKEFILE_LIST)))
SRC    := $(dir $(firstword $(MAKEFILE_LIST)))

GIT      = git
RM       = rm
INSTALL  = install
CC       ?= $(CROSS_COMPILE)gcc
LD       = $(CC)
STRIP    ?= $(CROSS_COMPILE)strip
OBJCOPY  ?= $(CROSS_COMPILE)objcopy
OBJDUMP  ?= $(CROSS_COMPILE)objdump

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -O3 -I. -I$(VPATH)
CFLAGS   += -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -O3
CXXFLAGS += -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -O3
LDFLAGS  += -ltalloc -Wl,-z,noexecstack -lm -ldl -lc

OBJECTS += \
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
	tracee/tracee.o		\
	tracee/mem.o		\
	tracee/reg.o		\
	tracee/event.o		\
	tracee/seccomp.o        \
	tracee/statx.o		\
	ptrace/ptrace.o		\
	ptrace/user.o		\
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
proot-scicat: | loader/loader
else
  OBJECTS += loader/loader-wrapped.o
endif

.DEFAULT_GOAL = proot-scicat
all: proot-scicat

######################################################################
# Beautified output

quiet_GEN = @echo "  GEN	$@"; $(GEN)
quiet_CC  = @echo "  CC	$@"; $(CC)
quiet_LD  = @echo "  LD	$@"; $(LD)
quiet_INSTALL = @echo "  INSTALL	$?"; $(INSTALL)

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
# Build rules

COMPILE = $($(quiet)CC) $(CPPFLAGS) $(CFLAGS) -MD -c $(SRC)$< -o $@
LINK    = $($(quiet)LD) -o $@ $^ $(LDFLAGS)

OBJIFY = $($(quiet)GEN)									\
	$(OBJCOPY)									\
		--input-target=binary								\
		--output-target=`env LANG=C $(OBJDUMP) -f cli/cli.o |				\
			grep 'file format' | awk '{print $$4}'`				\
		--binary-architecture `env LANG=C $(OBJDUMP) -f cli/cli.o |		\
				grep architecture | cut -f 1 -d , | awk '{print $$2}'`	\
		$< $@

proot-scicat: $(OBJECTS)
	$(LINK)
	$(STRIP) $@

%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE)

cli/%-licenses.o: licenses cli/cli.o
	$(OBJIFY)

######################################################################
# Build rules for the loader (arm64 only, NO 32-bit)

LOADER_OBJECTS = loader/loader.o loader/assembly.o

$(eval $(call define_from_arch.h,,LOADER_ARCH_CFLAGS))
$(eval $(call define_from_arch.h,,LOADER_ADDRESS))

LOADER_CFLAGS  += -fPIC -ffreestanding $(LOADER_ARCH_CFLAGS)
LOADER_LDFLAGS += -static -nostdlib -Wl$(BUILD_ID_NONE),-Ttext=$(LOADER_ADDRESS),--rosegment,-z,noexecstack

loader/loader.o: loader/loader.cpp
	@mkdir -p $(dir $@)
	$(COMPILE) $(LOADER_CFLAGS)

loader/assembly.o: loader/assembly.S
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
	-$(RM) -f $(OBJECTS) $(LOADER_OBJECTS) proot-scicat loader/loader $(DEPS) licenses

install: proot-scicat
	$($(quiet)INSTALL) -D $< $(DESTDIR)$(BINDIR)/$<
ifdef PROOT_UNBUNDLE_LOADER
	$(INSTALL) -D loader/loader $(PROOT_UNBUNDLE_LOADER)/loader
endif

uninstall:
	-$(RM) -f $(DESTDIR)$(BINDIR)/proot-scicat
ifdef PROOT_UNBUNDLE_LOADER
	-$(RM) -f $(PROOT_UNBUNDLE_LOADER)/loader
endif
