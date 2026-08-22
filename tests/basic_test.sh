#!/bin/sh
set -e
# SciCat PRoot 功能测试脚本
# 验证基本的路径重定向功能

echo "开始 SciCat PRoot 基本功能测试..."

# 检查是否提供了 proot 命令路径
if [ -z "$PROOT" ]; then
    PROOT="../src/neoproot"
fi

# 创建测试目录
TEST_ROOT=$(mktemp -d)
TEST_DIR="$TEST_ROOT/test-dir"
mkdir -p "$TEST_DIR"

echo "使用测试根目录: $TEST_ROOT"

# 在测试目录中创建一个文件
echo "SciCat PRoot 测试内容" > "$TEST_DIR/test-file.txt"

# 测试 1: 验证基本路径访问
echo "测试 1: 验证基本路径访问"
$PROOT -r "$TEST_ROOT" cat /test-dir/test-file.txt
if [ $? -eq 0 ]; then
    echo "测试 1: 通过"
else
    echo "测试 1: 失败"
fi

# 测试 2: 验证工作目录设置
echo "测试 2: 验证工作目录设置"
$PROOT -r "$TEST_ROOT" -w /test-dir pwd
if [ $? -eq 0 ]; then
    echo "测试 2: 通过"
else
    echo "测试 2: 失败"
fi

# 测试 3: 验证绑定挂载
echo "测试 3: 验证绑定挂载"
HOST_DIR=$(mktemp -d)
echo "绑定挂载测试" > "$HOST_DIR/host-file.txt"
$PROOT -r "$TEST_ROOT" -b "$HOST_DIR:/mnt/host" cat /mnt/host/host-file.txt
if [ $? -eq 0 ]; then
    echo "测试 3: 通过"
else
    echo "测试 3: 失败"
fi

# 清理
rm -rf "$TEST_ROOT" "$HOST_DIR"

echo "基本功能测试完成"