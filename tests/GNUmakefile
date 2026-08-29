# SciCat PRoot 测试套件 Makefile
# 用于编译和运行测试用例

CC ?= gcc
CFLAGS ?= -Wall -O2 -g
PROOT ?= ../src/neoproot

# 测试程序列表
TEST_PROGS = test_argv test_echo test_file_ops test_dir_ops

# 测试脚本列表
TEST_SCRIPTS = test-build-script.sh basic_test.sh advanced_test.sh \
	test-runtime-bindings.sh test-security-regressions.sh \
	test-link2symlink-dirent.sh test-link2symlink-stat-guard.sh \
	test-link2symlink-node-workflow.sh \
	test-binding-cache.sh \
	test-openat2.sh \
	test-bwrap-oldroot-bind.sh \
	test-bwrap-proc-dirfd.sh test-bwrap-procfd-mount-target.sh \
	test-bwrap-resolve-in-root.sh test-bwrap-cwd-dirfd.sh \
	test-bwrap-devnodes.sh \
	test-tracer-guard.sh \
	test-8d3c07f5.sh \
	test-statx-empty-path-mount-id.sh \
	test-statx-empty-path-pipe.sh \
	test-brk-diagnostic.sh \
	test-event-regressions.sh \
	test-canon-asan.sh \
	test-i3-restart-asan.sh

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

test-openat2: test-openat2.c
	$(CC) $(CFLAGS) -o $@ $<

# 运行所有测试
test: all
	@echo "运行 SciCat PRoot 测试..."
	@for prog in $(TEST_PROGS); do \
		echo "运行 $$prog..."; \
		expected=0; \
		case "$$prog" in test_echo) expected=42;; esac; \
		./$$prog; status=$$?; \
		if [ "$$status" -ne "$$expected" ]; then \
			echo "测试 $$prog 失败"; \
			exit 1; \
		else \
			echo "测试 $$prog 成功"; \
		fi; \
	done
	@for script in $(TEST_SCRIPTS); do \
		echo "运行测试脚本 $$script..."; \
		if sh "$$script"; then \
			:; \
		else \
			status=$$?; \
			if [ "$$status" -eq 125 ]; then \
				echo "跳过测试脚本 $$script（缺少前置条件）"; \
			else \
				echo "测试脚本 $$script 失败（退出码 $$status）"; \
				exit "$$status"; \
			fi; \
		fi; \
	done

# 清理编译产物
clean:
	rm -f $(TEST_PROGS)

# 深度清理，同时清理临时文件
distclean: clean
	rm -f *.txt *.log test_directory test_output.txt

.PHONY: all test clean distclean
