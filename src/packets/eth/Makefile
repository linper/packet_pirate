
INC = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

#TARGET = sniff
LDFLAGS += 
CFLAGS += -Wall -Wextra -g -Og

RM = rm -f

all: compile

compile: $(OBJ)

$.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS)

#$(TARGET): $(OBJ)
	#$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

.PHONY: clean

clean:
	$(RM) $(OBJ)
