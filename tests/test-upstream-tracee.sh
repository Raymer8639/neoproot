#!/bin/sh
# Host tests only: never launch neoproot, a guest, or UML.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(dirname -- "$script_dir")
case $(uname -m) in aarch64|arm64) ;; *) echo 'SKIP: ARM64-only tracer'; exit 125 ;; esac
build_dir=$(mktemp -d /tmp/test-upstream-tracee.XXXXXX)
trap 'rm -rf -- "$build_dir"' EXIT HUP INT TERM
# All compiler/test subprocesses receive a clean environment.
for filter in -DHAVE_SECCOMP_FILTER -UHAVE_SECCOMP_FILTER; do
    env -i PATH=/usr/bin:/bin clang -std=c23 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
        "$filter" -I"$repo_dir/src" -Wall -Wextra -fsyntax-only \
        "$repo_dir/src/tracee/event.c" "$repo_dir/src/tracee/tracee.c" \
        "$repo_dir/src/tracee/seccomp.c" "$repo_dir/src/tracee/statx.c"
done
env -i PATH=/usr/bin:/bin clang++ -std=c++23 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
    -Dptrace=tracee_test_ptrace -I"$repo_dir/src" -O1 -g \
    -ffunction-sections -fdata-sections -c "$repo_dir/src/tracee/reg.cpp" -o "$build_dir/reg.o"
env -i PATH=/usr/bin:/bin clang -std=c23 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
    -I"$repo_dir/src" -O1 -g -ffunction-sections -fdata-sections \
    -c "$repo_dir/src/syscall/sysnum.c" -o "$build_dir/sysnum.o"
env -i PATH=/usr/bin:/bin clang -std=c23 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
    -I"$repo_dir/src" -O1 -g -ffunction-sections -fdata-sections \
    -c "$repo_dir/src/tracee/statx.c" -o "$build_dir/statx.o"
for name in lifecycle events sigsys; do
    extra_objects=
    if [ "$name" = sigsys ]; then extra_objects="$build_dir/statx.o"; fi
    # Existing project inline wrappers use static functions with external linkage.
    env -i PATH=/usr/bin:/bin clang -std=c23 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
        -I"$repo_dir/src" -O1 -g -Wall -Wextra -Wno-static-in-inline \
        -ffunction-sections -fdata-sections \
        "$script_dir/test-upstream-tracee-$name.c" "$build_dir/reg.o" \
        "$build_dir/sysnum.o" $extra_objects \
        -Wl,--gc-sections -ltalloc -lstdc++ -pthread -o "$build_dir/$name"
    env -i PATH=/usr/bin:/bin "$build_dir/$name"
done
