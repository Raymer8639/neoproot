#!/bin/sh
# Cross-build libstatfast-musl.so for an aarch64 Alpine/musl guest.
#
# The regular build.sh targets the *guest* libc of the container.  An Alpine
# guest runs musl, whose ABI differs from glibc: there is no struct stat64 and
# no __xstat/__lxstat/__fxstat family, so shim.c compiles those entry points
# only under __GLIBC__.  This script fetches the musl headers and libc from the
# Alpine 3.21 aarch64 repository and cross-compiles the library with the
# Termux clang (aarch64-linux-musl target), without needing a guest chroot.
#
#   ./build-musl.sh                 # -> ./libstatfast-musl.so
#   ./build-musl.sh /tmp/out        # -> /tmp/out/libstatfast-musl.so
#   CC=aarch64-linux-musl-gcc ./build-musl.sh
#
# Environment knobs (defaults in brackets):
#   CC                 compiler [clang]
#   ALPINE_VERSION     Alpine branch [3.21]
#   ALPINE_ARCH        package architecture [aarch64]
#   ALPINE_MIRROR      mirror root [https://mirrors.ustc.edu.cn/alpine]
#   MUSL_PKG_VERSION   musl/musl-dev version [auto: newest in APKINDEX]
#   MUSL_SYSROOT       extracted headers/libc [<scratch>/musl-sysroot]
#   MUSL_APK_CACHE     downloaded apks [<scratch>/musl-apk]
#
# <scratch> is the bench directory when the checkout lives next to a rootfs/
# directory (the benchmark layout), otherwise the checkout itself.
#
# Requires: curl, GNU tar, awk, a clang that can target aarch64-linux-musl
# (Termux's clang works and ships ld.lld), or a native *-linux-musl-gcc.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="${1:-$here}"
checkout=$(dirname -- "$here")
scratch=$checkout
if [ -d "$(dirname -- "$checkout")/rootfs" ]; then
    scratch=$(dirname -- "$checkout")
fi

: "${CC:=clang}"
: "${ALPINE_VERSION:=3.21}"
: "${ALPINE_ARCH:=aarch64}"
: "${ALPINE_MIRROR:=https://mirrors.ustc.edu.cn/alpine}"
: "${MUSL_PKG_VERSION:=auto}"
: "${MUSL_SYSROOT:=$scratch/musl-sysroot}"
: "${MUSL_APK_CACHE:=$scratch/musl-apk}"

die() { echo "build-musl: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

need curl
need tar
need awk

mkdir -p "$out" "$MUSL_APK_CACHE" "$MUSL_SYSROOT"

repo="$ALPINE_MIRROR/v$ALPINE_VERSION/main/$ALPINE_ARCH"
index="$MUSL_APK_CACHE/APKINDEX.tar.gz"

# Refresh the index; fall back to a cached copy when offline.
if curl -fsSL --retry 3 --max-time 60 -o "$index.part" "$repo/APKINDEX.tar.gz"; then
    mv -f "$index.part" "$index"
elif [ -f "$index" ]; then
    echo "build-musl: warning: using cached APKINDEX" >&2
else
    die "cannot download $repo/APKINDEX.tar.gz"
fi

if [ "$MUSL_PKG_VERSION" = auto ]; then
    MUSL_PKG_VERSION=$(tar -xzOf "$index" APKINDEX | awk '
        BEGIN { RS = ""; FS = "\n" }
        {
            p = ""; v = "";
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^P:/) p = substr($i, 3);
                if ($i ~ /^V:/) v = substr($i, 3);
            }
            if (p == "musl") print v;
        }' | head -n 1)
    [ -n "$MUSL_PKG_VERSION" ] || die "cannot find musl version in APKINDEX"
fi

for pkg in musl musl-dev; do
    apk="$MUSL_APK_CACHE/$pkg-$MUSL_PKG_VERSION.apk"
    if [ ! -s "$apk" ]; then
        echo "build-musl: downloading $pkg-$MUSL_PKG_VERSION.apk"
        curl -fsSL --retry 3 --max-time 300 -o "$apk.part" \
            "$repo/$pkg-$MUSL_PKG_VERSION.apk" || die "download failed: $pkg"
        mv -f "$apk.part" "$apk"
    fi
    tar --ignore-zeros -xzf "$apk" -C "$MUSL_SYSROOT" 2>/dev/null \
        || die "cannot extract $apk"
done
rm -f "$MUSL_SYSROOT/.PKGINFO" "$MUSL_SYSROOT"/.SIGN.*

[ -f "$MUSL_SYSROOT/usr/include/sys/stat.h" ] || die "incomplete sysroot"
[ -f "$MUSL_SYSROOT/lib/libc.musl-$ALPINE_ARCH.so.1" ] \
    || die "incomplete sysroot (no libc)"

# clang needs an explicit --target/--sysroot and -nostdlib: the Termux clang
# has no crtbeginS.o/libgcc for a *-linux-musl target, and shim.c needs neither.
# A native aarch64-linux-musl-gcc already targets the right libc.
cross_flags=
if "$CC" --version 2>/dev/null | grep -qi clang; then
    cross_flags="--target=$ALPINE_ARCH-linux-musl --sysroot=$MUSL_SYSROOT -nostdlib"
fi

# shellcheck disable=SC2086
"$CC" $cross_flags -O2 -Wall -Wextra -fPIC -shared -Wl,-z,noexecstack \
    -o "$out/libstatfast-musl.so" "$here/shim.c" -lc

printf 'built %s (musl %s, Alpine %s/%s)\n' \
    "$out/libstatfast-musl.so" "$MUSL_PKG_VERSION" \
    "$ALPINE_VERSION" "$ALPINE_ARCH"
file "$out/libstatfast-musl.so" 2>/dev/null || true
readelf -d "$out/libstatfast-musl.so" 2>/dev/null | grep NEEDED || true
