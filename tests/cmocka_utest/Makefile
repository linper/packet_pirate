
BIN = test
DEPS = $(wildcard *.h)
SRC = $(wildcard *.c) $(SRC_DIR)/converter.c $(SRC_DIR)/filter.c $(SRC_DIR)/utils.c $(SRC_DIR)/setup.c

LDFLAGS += -lcmocka
    
RM = rm -f
    
all: clean compile run

compile:
	$(CC) -o $(BIN) $(SRC) $(DEPS) $(INC_PATH) $(CFLAGS) $(LDFLAGS) $(DEFS)

#.PHONY: clean run
    
clean: 
	$(RM) $(BIN)

run:
	./$(BIN)

