
obj-y += converter.o
obj-y += pkt_list.o
obj-y += core.o
obj-y += ef_tree.o
obj-y += ext_filter.o
obj-y += filter.o
obj-y += fhmap.o
obj-y += f_reg.o
obj-y += glist.o
obj-y += main.o
obj-y += packet.o
obj-y += setup.o
obj-y += utils.o

obj-y += filters/
obj-y += dump/

inc-y += filters/
 
.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"
