
obj-$(CONFIG_FILTER_ETHERNET) += ethernet/
inc-$(CONFIG_FILTER_ETHERNET) += ethernet/
obj-$(CONFIG_FILTER_IPV4) += ipv4/
inc-$(CONFIG_FILTER_IPV4) += ipv4/

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"

