
obj-y += bpf.o
obj-y += converter.o
obj-y += core.o
obj-y += ef_tree.o
obj-y += ext_filter.o
obj-y += filter.o
obj-y += filter_hmap.o
obj-y += f_reg.o
obj-y += glist.o
obj-y += main.o
obj-y += packet.o
obj-y += params.o
obj-y += setup.o
obj-y += utils.o

obj-y += packets/

inc-y += packets/
 
.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"
