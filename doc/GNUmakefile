# SciCat PRoot 文档生成 Makefile
# 用于生成各种格式的文档

# 输出文件定义
OUTPUTS = proot.1 proot.html articles.html

# 默认目标
all: $(OUTPUTS)

# 生成 man 页面
proot.1: proot/manual.txt
	rst2man $< $@

# 生成 HTML 页面
proot.html: proot/manual.txt
	rst2html $< $@

articles.html: articles/advanced_usage.txt articles/howto_migrate.txt
	rst2html $< $@

# 清理生成的文件
clean:
	rm -f $(OUTPUTS)

# 验证文档语法
check:
	for file in proot/manual.txt articles/*.txt; do \
		if [ -f "$$file" ]; then \
			rst2html --halt=info "$$file" > /dev/null || exit 1; \
		fi \
	done
	echo "文档语法检查完成"

.PHONY: all clean check