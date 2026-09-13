#!/bin/sh
# Build the neoproot --stat-shim LD_PRELOAD library and its local self-test.
#
# The library must be built for the *guest* ABI (the container rootfs), not for
# the Termux host: an Arch/glibc aarch64 rootfs needs an aarch64 glibc compiler,
# an x86_64 rootfs needs that toolchain, and so on.  The source only uses stable
# libc/POSIX interfaces, so any C compiler targeting the guest works.
#
#   ./build.sh                      # ./libstatfast.so (+ ./shim_test)
#   CC=aarch64-linux-gnu-gcc ./build.sh
#   CC=gcc ./build.sh /tmp/out      # write artifacts into /tmp/out
#
# Cross compiling is fine; only the resulting .so is shipped, the self-test is
# for native builds.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="${1:-}"
if [ -z "$out" ]; then out="$here"; fi
if [ -z "${CC:-}" ]; then CC=gcc; fi

mkdir -p "$out"
"$CC" -O2 -Wall -Wextra -fPIC -shared -o "$out/libstatfast.so" "$here/shim.c"
"$CC" -O2 -Wall -Wextra -o "$out/shim_test" "$here/shim_test.c" "$here/shim.c"
printf 'built %s/libstatfast.so and %s/shim_test\n' "$out" "$out"
