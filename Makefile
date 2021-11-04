SRC_DIR = src
INC_DIR = include
PAC_DIR = packets


PAC_INC = $(wildcard $(INC_DIR)/$(PAC_DIR)/*/*.h)
PAC_SRC = $(wildcard $(SRC_DIR)/$(PAC_DIR)/*/*.c)

INC = $(wildcard $(INC_DIR)/*.h) $(PAC_INC)
SRC = $(wildcard $(SRC_DIR)/*.c) $(PAC_SRC)

#INC = $(wildcard $(INC_DIR)/*.h)
#SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

TARGET = pp
LDFLAGS += -lpcap
CFLAGS += -Wall -Wextra -ggdb
#CFLAGS += -Wall -Wextra -ggdb -std=c99
DEFS += -DDEBUG

RUNARGS = eno1

RM = rm -f
EVAL = eval

run: compile
	$(EVAL) ./$(TARGET) $(RUNARGS)

all: compile

compile: $(TARGET)

$.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS) $(DEFS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS) $(DEFS)

.PHONY: clean

clean:
	$(RM) $(OBJ) $(TARGET)
