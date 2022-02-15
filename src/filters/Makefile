
obj-$(CONFIG_FILTER_ARP) += arp/
inc-$(CONFIG_FILTER_ARP) += arp/
obj-$(CONFIG_FILTER_ETHERNET) += ethernet/
inc-$(CONFIG_FILTER_ETHERNET) += ethernet/
obj-$(CONFIG_FILTER_ICMPV4) += icmpv4/
inc-$(CONFIG_FILTER_ICMPV4) += icmpv4/
obj-$(CONFIG_FILTER_IPV4) += ipv4/
inc-$(CONFIG_FILTER_IPV4) += ipv4/
obj-$(CONFIG_FILTER_TCP) += tcp/
inc-$(CONFIG_FILTER_TCP) += tcp/
obj-$(CONFIG_FILTER_UDP4) += udp4/
inc-$(CONFIG_FILTER_UDP4) += udp4/

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"

