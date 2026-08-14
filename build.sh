#!/bin/sh
# neoproot (proot-scicat) Termux 一键构建脚本
# 用法: sh build.sh [install]
#   install 参数: 构建并安装到 $PREFIX/bin

set -e

echo "==> neoproot 构建脚本"
echo "    平台: $(uname -m) / $(uname -s)"

# 仅支持 64 位 ARM
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "错误: 本项目仅支持 aarch64/arm64 设备" >&2; exit 1 ;;
esac

# 检查依赖（注意：llvm/binutils 是包名不是命令名，用代表性命令检测）
MISSING=""
check_cmd() { # 用法: check_cmd <包名> <命令>...
    pkg=$1; shift
    for c in "$@"; do
        if command -v "$c" >/dev/null 2>&1; then
            return 0
        fi
    done
    MISSING="$MISSING $pkg"
}
check_cmd clang clang
check_cmd make make
check_cmd llvm llvm-config llvm-ar
check_cmd binutils as ld.bfd

# talloc 是头文件库依赖，检查 pkg-config
if ! pkg-config --exists talloc 2>/dev/null; then
    MISSING="$MISSING talloc"
fi

if [ -n "$MISSING" ]; then
    echo "==> 缺少依赖:$MISSING"
    echo "    请先安装: pkg install clang make llvm binutils talloc"
    echo "    （可选: pkg install upx，可显著减小二进制体积）"
    exit 1
fi

echo "==> 开始编译（多线程）..."
make -C src neoproot -j"$(nproc 2>/dev/null || echo 4)" V=1

echo ""
echo "==> 构建完成: $(pwd)/src/neoproot"
ls -lh src/neoproot

if [ "$1" = "install" ]; then
    echo ""
    echo "==> 安装到 $PREFIX/bin/neoproot ..."
    cp src/neoproot "$PREFIX/bin/neoproot"
    chmod 755 "$PREFIX/bin/neoproot"
    echo "==> 安装完成！使用 neoproot 命令启动容器。"
fi
