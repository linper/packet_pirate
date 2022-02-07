
######################
#  EXPORTS  #
######################
export ROOT_DIR = $(abspath ./)
export SRC_DIR = $(ROOT_DIR)/src
export SCR_DIR = $(ROOT_DIR)/scripts
export INC_DIR = $(ROOT_DIR)/include
export TMP_DIR = $(ROOT_DIR)/tmp
export RES_DIR = $(ROOT_DIR)/resources
export BLD_DIR = $(ROOT_DIR)/build
export BIN_DIR = $(BLD_DIR)/bin
export BLD_TMP_DIR = $(BLD_DIR)/tmp
export FIL_DIR = $(SRC_DIR)/filters

######################
#  MISC  #
######################
OBJ-Y = obj
INC-Y = inc
KCONFIG = .config
Q = @
#Q =

######################
#  COMPILE ARGS  #
######################
TARGET = pp
CC = gcc
LDFLAGS += -lpcap
CFLAGS += -Wall -Wextra -ggdb -std=gnu99
#CFLAGS += -Wall -Wextra -ggdb -std=c99
DEFS += -D_GNU_SOURCE -DDEBUG
RUNARGS = eno1
INC_PATH := -I$(INC_DIR)

######################
#  COMMAND MACROS  #
######################
RM = rm -f
MAKE = make

######################
#  PRE-BUILD  #
######################
$(foreach conf,$(shell grep -E '.*=.*' $(KCONFIG)),$(eval CONF += $(conf)))
$(foreach conf,$(CONF),$(eval export $(conf)))
CONF := $(patsubst %=y, %, $(CONF))
CONF := $(subst =",="\", $(CONF))
CONF := $(subst " ,\"" , $(CONF))
DEFS += $(patsubst CONFIG_DFN_%, -D%, $(filter CONFIG_DFN_%,$(CONF)))
# TODO add compilation flags from config

ifeq ($(CONFIG_DFN_DUMP_TYPE_SQLITE3),y)
   LDFLAGS += -lsqlite3
else ifeq ($(CONFIG_DFN_DUMP_TYPE_MYSQL),y)
   LDFLAGS += -lmysqlclient
else ifeq ($(CONFIG_DFN_DUMP_TYPE_PQ),y)
   LDFLAGS += -lpq
endif

######################
#  BUILD  #
######################
all: build

build: clean_tmp collect
	OBJ=$$(cat $(BLD_TMP_DIR)/$(OBJ-Y) | xargs); \
	INC=$$(cat $(BLD_TMP_DIR)/$(INC-Y) | xargs); \
	SRC=$$(echo $${OBJ} | sed 's/\.o/\.c/g'); \
	$(CC) -o $(BIN_DIR)/$(TARGET) $${INC} $${SRC} $(INC_PATH) $(LDFLAGS) $(CFLAGS) $(DEFS)

collect: collect_obj collect_inc

clean_tmp:
	$(Q)rm -rf $(BLD_TMP_DIR)/*

collect_inc:
	$(Q)$(MAKE) -C $(SRC_DIR) dir=$(SRC_DIR) obj=$(INC-Y)

collect_obj:
	$(Q)$(MAKE) -C $(SRC_DIR) dir=$(SRC_DIR) obj=$(OBJ-Y)

.PHONY: clean run menuconfig help

menuconfig:
	kconfig-mconf KConfig
	$(SCR_DIR)/generate_registry.sh

run: build
	$(Q)$(EVAL) ./$(TARGET) $(RUNARGS)

clean:
	$(Q)$(RM) $$(cat $(BLD_TMP_DIR)/$(OBJ-Y) | xargs) $(BIN_DIR)/$(TARGET) $(TMP_DIR)/*

help:
	$(Q)echo "help message not implemented yet"

