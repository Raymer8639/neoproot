.PHONY: all shell child
all:
	+$(MAKE) -f $(lastword $(MAKEFILE_LIST)) child
shell:
	+$(MAKE) -f $(lastword $(MAKEFILE_LIST)) child; :
child:
	@printf "recursive-make-ok\n"
