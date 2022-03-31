
obj-$(CONFIG_DFN_DUMP_TYPE_SQLITE3) += sqlite3.o
obj-$(CONFIG_DFN_DUMP_TYPE_MYSQL) += mysql.o
obj-$(CONFIG_DFN_DUMP_TYPE_PQ) += pq.o
obj-$(CONFIG_DFN_DUMP_TYPE_NONE) += none.o

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"

