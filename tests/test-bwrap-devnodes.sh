#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROOT=${PROOT:-"$SCRIPT_DIR/../src/neoproot"}
PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
ROOTFS=${NEOPROOT_TEST_ROOTFS:-"$PREFIX/var/lib/proot-distro/containers/archlinuxarm/rootfs"}
SYSROOT=$(dirname "$ROOTFS")/sysdata

if [ ! -x "$PROOT" ] || [ ! -x "$ROOTFS/usr/sbin/bwrap" ] ||
   [ ! -x "$ROOTFS/bin/sh" ] || [ ! -d "$ROOTFS/dev" ] ||
   [ ! -f "$SYSROOT/sysctl_kernel_overflowuid" ] ||
   [ ! -f "$SYSROOT/sysctl_kernel_overflowgid" ] ||
   [ ! -f "$SYSROOT/sysctl_entry_cap_last_cap" ]; then
    printf '%s\n' 'SKIP: bwrap device-node test requires a Termux archlinuxarm rootfs'
    exit 125
fi

if ! "$PROOT" --link2symlink --rootfs="$ROOTFS" --cwd=/ \
    --bind=/dev --bind=/proc --bind=/sys \
    --bind="$SYSROOT/sysctl_kernel_overflowuid:/proc/sys/kernel/overflowuid" \
    --bind="$SYSROOT/sysctl_kernel_overflowgid:/proc/sys/kernel/overflowgid" \
    --bind="$SYSROOT/sysctl_entry_cap_last_cap:/proc/sys/kernel/cap_last_cap" \
    /usr/sbin/bwrap --as-pid-1 --new-session --die-with-parent \
    --ro-bind / / --dev /dev --bind /tmp /tmp \
    --unshare-user --unshare-pid --unshare-ipc --proc /proc --cap-drop ALL \
    /bin/sh -c 'test -c /dev/null && test -w /dev/null && : > /dev/null'; then
    printf '%s\n' 'bwrap /dev/null is not a writable character device' >&2
    exit 1
fi

printf '%s\n' 'bwrap device-node regression passed'
