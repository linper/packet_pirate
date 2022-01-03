
obj-y += dump.o
obj-$(CONFIG_DUMP_TYPE_SQLITE3) += sqlite3.o
obj-$(CONFIG_DUMP_TYPE_MYSQL) += mysql.o

.PHONY all:

all:
	$(MAKE) -f $(SCR_DIR)/Makefile.build dir=$(dir) obj=$(obj) objs="$($(obj)-y)"

