
######################
#  EXPORTS  #
######################
export ROOT_DIR = $(abspath ./)
export SRC_DIR = $(ROOT_DIR)/src
export SCR_DIR = $(ROOT_DIR)/scripts
export INC_DIR = $(ROOT_DIR)/include
export BLD_DIR = $(ROOT_DIR)/build
export BIN_DIR = $(BLD_DIR)/bin
export BLD_TMP_DIR = $(BLD_DIR)/tmp
export PAC_DIR = $(SRC_DIR)/packets

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
CFLAGS += -Wall -Wextra -ggdb
#CFLAGS += -Wall -Wextra -ggdb -std=c99
DEFS += -DDEBUG
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
$(foreach conf,$(shell grep -E '.*=.*' $(KCONFIG)),$(eval export $(conf)))

######################
#  BUILD  #
######################
all: build

build: clean_tmp collect
	OBJ=$$(cat $(BLD_TMP_DIR)/$(OBJ-Y) | xargs); \
	INC=$$(cat $(BLD_TMP_DIR)/$(INC-Y) | xargs); \
	SRC=$$(echo $${OBJ} | sed 's/\.o/\.c/g'); \
	$(CC) -o $(TARGET) $${INC} $${SRC} $(INC_PATH) $(LDFLAGS) $(CFLAGS) $(DEFS); \
	cp $(TARGET) $(BIN_DIR)/$(TARGET)

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

run: build
	$(Q)$(EVAL) ./$(TARGET) $(RUNARGS)

clean:
	$(Q)$(RM) $$(cat $(BLD_TMP_DIR)/$(OBJ-Y) | xargs) $(BIN_DIR)/$(TARGET)

help:
	$(Q)echo "help message not implemented yet"

