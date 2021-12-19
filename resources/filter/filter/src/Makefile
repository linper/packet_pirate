
obj-y += >>>FILTER_NAME<<<.o

$(info $(obj-y))

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"
