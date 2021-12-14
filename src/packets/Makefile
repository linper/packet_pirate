
obj-y += eth/
obj-$(CONFIG_SELECT_DEV) += ipv4/
#obj-y += ipv4/

inc-y += eth/
inc-y += ipv4/

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"
