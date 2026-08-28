#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
ROOTFS=${NEOPROOT_TEST_ROOTFS:-"$PREFIX/var/lib/proot-distro/containers/archlinuxarm/rootfs"}
SYSROOT=$(dirname "$ROOTFS")/sysdata

if [ ! -x "$PROOT" ] || [ ! -x "$ROOTFS/usr/sbin/bwrap" ] ||
   [ ! -x "$ROOTFS/usr/bin/env" ] || [ ! -x "$ROOTFS/usr/bin/find" ] ||
   [ ! -x "$ROOTFS/bin/sh" ] ||
   [ ! -x "$ROOTFS/usr/bin/cc" ] ||
   [ ! -d "$ROOTFS/home" ] || [ ! -d "$ROOTFS/tmp" ] ||
   [ ! -f "$SYSROOT/sysctl_kernel_overflowuid" ] ||
   [ ! -f "$SYSROOT/sysctl_kernel_overflowgid" ] ||
   [ ! -f "$SYSROOT/sysctl_entry_cap_last_cap" ]; then
    printf '%s\n' 'SKIP: bwrap cwd-dirfd test requires a Termux archlinuxarm rootfs'
    exit 125
fi

WORK=$(mktemp -d "$ROOTFS/home/neoproot-bwrap-cwd-dirfd.XXXXXX")
PRIVATE_SOURCE=$(mktemp -d "$ROOTFS/home/neoproot-bwrap-private.XXXXXX")
GUEST_WORK=/home/$(basename "$WORK")
GUEST_PRIVATE_SOURCE=/home/$(basename "$PRIVATE_SOURCE")

cleanup() {
    rm -rf "$WORK"
    rm -rf "$PRIVATE_SOURCE"
}
trap cleanup EXIT INT TERM

mkdir -p "$WORK/child" "$WORK/private"
printf c > "$WORK/child/marker"
printf w > "$WORK/private/marker"
printf p > "$PRIVATE_SOURCE/marker"
cp "$SCRIPT_DIR/test-bwrap-cwd-dirfd.c" "$WORK/openat-probe.c"
"$PROOT" --link2symlink --rootfs="$ROOTFS" --cwd="$GUEST_WORK" \
    --bind=/dev --bind=/proc --bind=/sys \
    --bind="$SYSROOT/sysctl_kernel_overflowuid:/proc/sys/kernel/overflowuid" \
    --bind="$SYSROOT/sysctl_kernel_overflowgid:/proc/sys/kernel/overflowgid" \
    --bind="$SYSROOT/sysctl_entry_cap_last_cap:/proc/sys/kernel/cap_last_cap" \
    /usr/bin/env PATH=/usr/bin:/bin /usr/bin/cc -O2 -Wall -Wextra \
    -o "$GUEST_WORK/openat-probe" \
    "$GUEST_WORK/openat-probe.c"

if ! output=$("$PROOT" --link2symlink --rootfs="$ROOTFS" --cwd="$GUEST_WORK" \
    --bind=/dev --bind=/proc --bind=/sys \
    --bind="$SYSROOT/sysctl_kernel_overflowuid:/proc/sys/kernel/overflowuid" \
    --bind="$SYSROOT/sysctl_kernel_overflowgid:/proc/sys/kernel/overflowgid" \
    --bind="$SYSROOT/sysctl_entry_cap_last_cap:/proc/sys/kernel/cap_last_cap" \
    /usr/sbin/bwrap --as-pid-1 --new-session --die-with-parent \
    --ro-bind / / --dev /dev --bind /tmp /tmp \
    --bind "$GUEST_WORK" "$GUEST_WORK" \
    --bind "$GUEST_PRIVATE_SOURCE" "$GUEST_WORK/private" \
    --unshare-user --unshare-pid --unshare-ipc --proc /proc --cap-drop ALL \
    /bin/sh -c 'exec 9<.; "$1"; /usr/bin/find . -maxdepth 2 -type f -name marker -print' \
    sh "$GUEST_WORK/openat-probe"); then
    printf '%s\n' 'bwrap cwd directory-fd regression failed' >&2
    exit 1
fi

if ! printf '%s\n' "$output" | grep -Fx './child/marker' >/dev/null; then
    printf '%s\n' 'bwrap cwd directory-fd regression did not find marker' >&2
    exit 1
fi

if ! printf '%s\n' "$output" | grep -Fx './private/marker' >/dev/null; then
    printf '%s\n' 'bwrap cwd nested binding was not traversed' >&2
    exit 1
fi

printf '%s\n' 'bwrap cwd directory-fd regression passed'
