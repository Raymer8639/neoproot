# SciCat PRoot 测试套件 Makefile
# 用于编译和运行测试用例

CC ?= gcc
CFLAGS ?= -Wall -O2 -g
PROOT ?= ./scicat-proot

# 测试程序列表
TEST_PROGS = test_argv test_echo test_file_ops test_dir_ops

# 测试脚本列表
TEST_SCRIPTS = basic_test.sh advanced_test.sh

# 默认目标
all: $(TEST_PROGS)

# 编译测试程序
test_argv: test_argv.c
	$(CC) $(CFLAGS) -o $@ $<

test_echo: test_echo.c
	$(CC) $(CFLAGS) -o $@ $<

test_file_ops: test_file_ops.c
	$(CC) $(CFLAGS) -o $@ $<

test_dir_ops: test_dir_ops.c
	$(CC) $(CFLAGS) -o $@ $<

# 运行所有测试
test: all
	@echo "运行 SciCat PRoot 测试..."
	@for prog in $(TEST_PROGS); do \
		echo "运行 $$prog..."; \
		./$$prog; \
		if [ $$? -ne 0 ]; then \
			echo "测试 $$prog 失败"; \
		else \
			echo "测试 $$prog 成功"; \
		fi; \
	done
	@for script in $(TEST_SCRIPTS); do \
		if [ -x "$$script" ]; then \
			echo "运行测试脚本 $$script..."; \
			./$$script; \
		fi \
	done

# 清理编译产物
clean:
	rm -f $(TEST_PROGS)

# 深度清理，同时清理临时文件
distclean: clean
	rm -f *.txt *.log test_directory test_output.txt

.PHONY: all test clean distclean