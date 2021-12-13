
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
	rm -rf $(BLD_TMP_DIR)/*

collect_inc:
	$(MAKE) -C $(SRC_DIR) dir=$(SRC_DIR) obj=$(INC-Y)

collect_obj:
	$(MAKE) -C $(SRC_DIR) dir=$(SRC_DIR) obj=$(OBJ-Y)

.PHONY: clean run

run: build
	$(EVAL) ./$(TARGET) $(RUNARGS)

clean:
	$(RM) $$(cat $(BLD_TMP_DIR)/$(OBJ-Y) | xargs) $(BIN_DIR)/$(TARGET)

