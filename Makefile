
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

######################
#  COMPILE ARGS  #
######################
export CC = gcc
export LDFLAGS += -lpcap
export CFLAGS += -Wall -Wextra -std=gnu99
export DEFS += -D_GNU_SOURCE -DDEBUG
RUNARGS = -d eno1
export INC_PATH := -I$(INC_DIR)

######################
#  COMMAND MACROS  #
######################
RM = rm -f
MAKE = make

######################
#  PRE-BUILD  #
######################

$(foreach conf,$(shell grep -E '.*=.*' $(KCONFIG) | cut -d '=' -f 1),$(eval CONF += $(conf)))

#This limits usage of '#' symbol. It is not the perfect solution
$(foreach conf,$(shell grep -E '.*=.*' $(KCONFIG) | tr ' ' '#'),$(eval export $(subst #, ,$(conf))))
$(foreach conf,$(shell grep -E 'CONFIG_DFN_.*=.*' $(KCONFIG) | tr ' ' '#'),$(eval export $(strip $(subst #, ,$(subst =",="\",$(subst " ,\"",$(conf) ))))))

$(foreach conf,$(filter CONFIG_DFN_%,$(CONF)),$(eval DEFS += $(patsubst CONFIG_DFN_%,-D%,$(conf)=$($(conf)))))

CFLAGS += $(subst ",,$(CONFIG_DEVEL_COMP_FLAGS))

TARGET = $(patsubst "%",%, $(CONFIG_TARGET_NAME))

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
	INC=$$(cat $(BLD_TMP_DIR)/$(INC-Y) 2> /dev/null | xargs); \
	SRC=$$(echo $${OBJ} | sed 's/\.o/\.c/g'); \
	$(CC) -o $(BIN_DIR)/$(TARGET) $${INC} $${SRC} $(INC_PATH) $(LDFLAGS) $(CFLAGS) $(DEFS) $(COMP_FL)

collect: collect_obj collect_inc

clean_tmp:
	$(Q)$(RM) $(BLD_TMP_DIR)/*

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

clean: clean_tmp
	$(Q)$(RM) $(BLD_TMP_DIR)/* $(BIN_DIR)/* $(TMP_DIR)/*

help:
	$(Q)echo -e "Usage: make [options]\n\
	Options:\n\
	    [none] | all   Cleans and builds project\n\
	    clean          Cleans compiled binaries and temporary data\n\
	    compile        Builds project\n\
	    help           Displays this message\n\
	    menuconfig     Opens 'mconf' based configuration TUI\n\
	    run            Runs built project(for development purposes)\n\
	    test           Runs auto tests\
	"


