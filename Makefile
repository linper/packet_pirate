
######################
#  EXPORTS  #
######################
export ROOT_DIR = $(abspath ./)
export SRC_DIR = $(ROOT_DIR)/src
export TST_DIR = $(ROOT_DIR)/tests
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
export CC = gcc
export LDFLAGS += -lpcap
export CFLAGS += -Wall -Wextra -ggdb -std=gnu99
export DEFS += -D_GNU_SOURCE -DDEBUG
RUNARGS = eno1
export INC_PATH := -I$(INC_DIR)

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
all: clean compile

compile: clean_tmp collect
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


.PHONY: clean run menuconfig help test

menuconfig:
	kconfig-mconf KConfig

test:
	$(Q)$(MAKE) -C $(TST_DIR)

run: build
	$(Q)$(EVAL) $(BIN_DIR)/$(TARGET) $(RUNARGS)

clean:
	$(Q)$(RM) $$(cat $(BLD_TMP_DIR)/$(OBJ-Y) | xargs) $(BIN_DIR)/$(TARGET) $(TMP_DIR)/*

help:
	$(Q)echo -e "Usage : make [options]\n\
	Options:\n\
	    [none] | all   Cleans, builds, and tests project\n\
	    clean          Cleans compiled binaries and temporary data\n\
	    compile        Builds project\n\
	    help           Displays this message\n\
	    menuconfig     Opens 'mconf' based configuration tui\n\
	    run            Runs built project(for development purposes)\n\
	    test           Runs auto tests\
	"

