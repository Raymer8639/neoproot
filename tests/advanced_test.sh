#!/bin/sh
set -e
# SciCat PRoot 高级功能测试脚本
# 测试复杂的路径绑定和环境变量

echo "开始 SciCat PRoot 高级功能测试..."

# 检查 proot 命令
if [ -z "$PROOT" ]; then
    PROOT="../src/neoproot"
fi

# 创建复杂的测试环境
TEST_ROOT=$(mktemp -d)
mkdir -p "$TEST_ROOT/bin" "$TEST_ROOT/lib" "$TEST_ROOT/home" "$TEST_ROOT/etc" "$TEST_ROOT/usr/bin"

# 创建测试程序
cat > "$TEST_ROOT/test-script.sh" << 'EOF'
#!/bin/sh
echo "运行在 SciCat PRoot 环境中"
echo "当前路径: $(pwd)"
echo "根目录内容:"
ls /
echo "环境变量 TEST_VAR: $TEST_VAR"
EOF
chmod +x "$TEST_ROOT/test-script.sh"

# 设置环境变量进行测试
export TEST_VAR="SciCat_PRoot_Test_Value"

# 测试 1: 复杂路径绑定
echo "测试 1: 复杂路径绑定和环境变量"
if [ -n "${PREFIX:-}" ]; then
    HOST_SH=$(readlink -f "$PREFIX/bin/sh")
    RUNTIME_BINDS="-b $PREFIX:$PREFIX -b /system -b /apex"
else
    HOST_SH=$(readlink -f /bin/sh)
    RUNTIME_BINDS="-b /usr -b /lib -b /lib64"
fi
ln -s "$HOST_SH" "$TEST_ROOT/bin/sh"

$PROOT -r "$TEST_ROOT" -w / -b "/tmp:/host-tmp" $RUNTIME_BINDS env TEST_VAR="$TEST_VAR" /test-script.sh
if [ $? -eq 0 ]; then
    echo "测试 1: 通过"
else
    echo "测试 1: 失败"
fi

# 测试 2: 多层绑定
echo "测试 2: 多层路径绑定"
NESTED_DIR=$(mktemp -d)
mkdir -p "$NESTED_DIR/nested/subdir"
echo "多层绑定测试" > "$NESTED_DIR/nested/subdir/deep-file.txt"
$PROOT -r "$TEST_ROOT" -b "$NESTED_DIR:/nested" cat /nested/nested/subdir/deep-file.txt
if [ $? -eq 0 ]; then
    echo "测试 2: 通过"
else
    echo "测试 2: 失败"
fi

# 清理
rm -rf "$TEST_ROOT" "$NESTED_DIR"

echo "高级功能测试完成"