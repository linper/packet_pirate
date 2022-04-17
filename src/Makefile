
obj-y += report.o
obj-y += converter.o
obj-y += stash.o
obj-y += ef_tree.o
obj-y += ext_filter.o
obj-y += filter.o
obj-y += fhmap.o
obj-y += glist.o
obj-y += setup.o
obj-y += utils.o
obj-y += packet.o
obj-$(CONFIG_DFN_DEVEL_SANITY) += sanity.o
obj-y += core.o
obj-y += main.o

obj-y += filters/
obj-y += dump/

inc-y += filters/
 
.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"
