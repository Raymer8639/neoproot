project('neoproot', ['c', 'cpp'], version: '5.10.9', meson_version: '>=0.61.0', default_options: ['warning_level=2'])
cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')
if host_machine.cpu_family() not in ['aarch64', 'arm64']
  error('neoproot supports ARM64 only')
endif
srcdir = meson.project_source_root() / 'src'
gen = meson.current_build_dir() / 'generated'
fs = import('fs')
run = find_program('sh')
conf = configuration_data()
git = find_program('git', required: false)
version = meson.project_version()
if git.found()
  gv = run_command(git, '-C', srcdir, 'describe', '--tags', '--always', '--dirty', check: false)
  if gv.returncode() == 0
    version = gv.stdout().strip()
  endif
endif
conf.set_quoted('VERSION', version)
configure_file(output: 'build.h', configuration: conf)
if cc.has_header('linux/seccomp.h') and cc.has_header('linux/filter.h') and cc.has_header('sys/syscall.h')
  add_project_arguments('-DHAVE_SECCOMP_FILTER', language: ['c', 'cpp'])
endif
vm_probe = '''#include <sys/uio.h>
#include <stdlib.h>
int main(void){
  return process_vm_readv(0, NULL, 0, NULL, 0, 0)
       + process_vm_writev(0, NULL, 0, NULL, 0, 0);
}'''
if cc.compiles(vm_probe, args: ['-D_GNU_SOURCE'], name: 'process_vm_readv')
  add_project_arguments('-DHAVE_PROCESS_VM', language: ['c', 'cpp'])
endif
common = ['-D_FILE_OFFSET_BITS=64', '-D_GNU_SOURCE', '-I' + gen, '-I' + srcdir]
arm = get_option('march').split()
c_args = common + arm + ['-std=c23', '-Wall', '-Wextra', '-O3', '-flto=thin', '-ffunction-sections', '-fdata-sections', '-munaligned-access', '-ffast-math', '-D__ARM_NEON', '-D__ARM_FEATURE_DOTPROD']
cpp_args = common + arm + ['-std=c++23', '-Wall', '-Wextra', '-O3', '-flto=thin', '-ffunction-sections', '-fdata-sections', '-munaligned-access', '-ffast-math', '-D__ARM_NEON', '-D__ARM_FEATURE_DOTPROD']
dep = dependency('talloc', required: true)
c_sources = files('src/cli/neoproot.c',
  'src/cli/cli.c',
  'src/cli/proot.c',
  'src/cli/note.c',
  'src/execve/enter.c',
  'src/execve/exit.c',
  'src/execve/shebang.c',
  'src/execve/elf.c',
  'src/execve/ldso.c',
  'src/execve/auxv.c',
  'src/execve/aoxp.c',
  'src/path/binding.c',
  'src/path/glue.c',
  'src/path/canon.c',
  'src/path/f2fs-bug.c',
  'src/path/path.c',
  'src/path/proc.c',
  'src/path/temp.c',
  'src/syscall/seccomp.c',
  'src/syscall/seccomp_notify.c',
  'src/syscall/syscall.c',
  'src/syscall/chain.c',
  'src/syscall/enter.c',
  'src/syscall/exit.c',
  'src/syscall/sysnum.c',
  'src/syscall/socket.c',
  'src/syscall/heap.c',
  'src/syscall/rlimit.c',
  'src/syscall/pipe_shadow.c',
  'src/tracee/tracee.c',
  'src/tracee/event.c',
  'src/tracee/seccomp.c',
  'src/tracee/statx.c',
  'src/ptrace/ptrace.c',
  'src/ptrace/wait.c',
  'src/extension/netlink_route/netlink_route.c',
  'src/extension/extension.c',
  'src/extension/ashmem_memfd/ashmem_memfd.c',
  'src/extension/kompat/kompat.c',
  'src/extension/fake_id0/chown.c',
  'src/extension/fake_id0/chroot.c',
  'src/extension/fake_id0/getsockopt.c',
  'src/extension/fake_id0/sendmsg.c',
  'src/extension/fake_id0/socket.c',
  'src/extension/fake_id0/open.c',
  'src/extension/fake_id0/unlink.c',
  'src/extension/fake_id0/rename.c',
  'src/extension/fake_id0/chmod.c',
  'src/extension/fake_id0/utimensat.c',
  'src/extension/fake_id0/access.c',
  'src/extension/fake_id0/exec.c',
  'src/extension/fake_id0/link.c',
  'src/extension/fake_id0/symlink.c',
  'src/extension/fake_id0/mk.c',
  'src/extension/fake_id0/stat.c',
  'src/extension/fake_id0/helper_functions.c',
  'src/extension/fake_id0/fake_id0.c',
  'src/extension/hidden_files/hidden_files.c',
  'src/extension/mountinfo/mountinfo.c',
  'src/extension/port_switch/port_switch.c',
  'src/extension/sysvipc/sysvipc.c',
  'src/extension/sysvipc/sysvipc_msg.c',
  'src/extension/sysvipc/sysvipc_sem.c',
  'src/extension/sysvipc/sysvipc_shm.c',
  'src/extension/link2symlink/link2symlink.c',
  'src/extension/fix_symlink_size/fix_symlink_size.c')
cpp_sources = files('src/tracee/mem.cpp',
  'src/tracee/reg.cpp')
objcopy = find_program('objcopy', required: true)
strip = find_program('strip', required: true)
loader_cpp_args = common + arm + ['-std=c++23', '-Wall', '-Wextra', '-O3', '-ffunction-sections', '-fdata-sections', '-munaligned-access', '-ffast-math', '-D__ARM_NEON', '-D__ARM_FEATURE_DOTPROD', '-fPIC', '-ffreestanding']
loader_c_args = common + arm + ['-std=c23', '-Wall', '-Wextra', '-O3', '-ffunction-sections', '-fdata-sections', '-munaligned-access', '-ffast-math', '-D__ARM_NEON', '-D__ARM_FEATURE_DOTPROD', '-fPIC', '-ffreestanding']
# Build the freestanding AArch64 loader directly; GNUmake remains a compatibility entry point.
loader_cmd = ' '.join(cxx.cmd_array()) + ' ' + ' '.join(loader_cpp_args) + ' -c "' + srcdir + '/loader/loader.cpp" -o "@OUTDIR@/loader.o" && ' + ' '.join(cc.cmd_array()) + ' ' + ' '.join(loader_c_args) + ' -c "' + srcdir + '/loader/assembly.S" -o "@OUTDIR@/assembly.o" && ' + ' '.join(cc.cmd_array()) + ' -o "@OUTDIR@/loader.exe" "@OUTDIR@/loader.o" "@OUTDIR@/assembly.o" -static -nostdlib -Wl,-Ttext=0x2000000000,--rosegment,-z,noexecstack && ' + strip.full_path() + ' "@OUTDIR@/loader.exe" && cd "@OUTDIR@" && ' + objcopy.full_path() + ' --input-target=binary --output-target=elf64-littleaarch64 --binary-architecture=aarch64 loader.exe "@OUTPUT@"'
loader = custom_target('loader-wrapped', output: 'loader-wrapped.o', depend_files: files('src/loader/loader.cpp', 'src/loader/assembly.S', 'src/loader/assembly-arm64.h', 'src/loader/script.h', 'src/arch.h', 'src/compat.h'), command: [run, '-c', loader_cmd], build_by_default: true, console: true)
link_args = ['-flto=thin', '-fuse-ld=lld', '-Wl,--icf=all', '-Wl,-z,noexecstack', '-Wl,--gc-sections', '-Wl,-z,relro', '-Wl,-z,now', '-Wl,--strip-all', '-lpthread', '-s']
executable('neoproot', c_sources + cpp_sources + loader, dependencies: dep, c_args: c_args, cpp_args: cpp_args, link_args: link_args, install: true, install_dir: get_option('bindir'))
