
obj-$(CONFIG_FILTER_ARP) += arp/
inc-$(CONFIG_FILTER_ARP) += arp/
obj-$(CONFIG_FILTER_ETHERNET) += ethernet/
inc-$(CONFIG_FILTER_ETHERNET) += ethernet/
obj-$(CONFIG_FILTER_ICMPV4) += icmpv4/
inc-$(CONFIG_FILTER_ICMPV4) += icmpv4/
obj-$(CONFIG_FILTER_ICMPV6) += icmpv6/
inc-$(CONFIG_FILTER_ICMPV6) += icmpv6/
obj-$(CONFIG_FILTER_IGMP) += igmp/
inc-$(CONFIG_FILTER_IGMP) += igmp/
obj-$(CONFIG_FILTER_IPV4) += ipv4/
inc-$(CONFIG_FILTER_IPV4) += ipv4/
obj-$(CONFIG_FILTER_IPV6) += ipv6/
inc-$(CONFIG_FILTER_IPV6) += ipv6/
obj-$(CONFIG_FILTER_TCP) += tcp/
inc-$(CONFIG_FILTER_TCP) += tcp/
obj-$(CONFIG_FILTER_UDP) += udp/
inc-$(CONFIG_FILTER_UDP) += udp/

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"

