#!/bin/sh
# uproot (proot-scicat) Termux 一键构建脚本
# 用法: sh build.sh [install]
#   install 参数: 构建并安装到 $PREFIX/bin

set -e

echo "==> uproot 构建脚本"
echo "    平台: $(uname -m) / $(uname -s)"

# 仅支持 64 位 ARM
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "错误: 本项目仅支持 aarch64/arm64 设备" >&2; exit 1 ;;
esac

# 检查依赖
MISSING=""
for pkg in clang make llvm binutils; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        MISSING="$MISSING $pkg"
    fi
done

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
make -C src uproot -j"$(nproc 2>/dev/null || echo 4)" V=1

echo ""
echo "==> 构建完成: $(pwd)/src/uproot"
ls -lh src/uproot

if [ "$1" = "install" ]; then
    echo ""
    echo "==> 安装到 $PREFIX/bin/uproot ..."
    cp src/uproot "$PREFIX/bin/uproot"
    chmod 755 "$PREFIX/bin/uproot"
    echo "==> 安装完成！使用 uproot 命令启动容器。"
fi
