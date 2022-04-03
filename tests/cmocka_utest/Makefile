
BIN = test
DEPS = $(wildcard *.h)
SRC = $(wildcard *.c) $(SRC_DIR)/converter.c $(SRC_DIR)/filter.c $(SRC_DIR)/utils.c $(SRC_DIR)/setup.c $(SRC_DIR)/glist.c $(SRC_DIR)/stash.c


LDFLAGS += -lcmocka
    
RM = rm -f
    
ifeq ($(CONFIG_TEST_CMOCKA),y)
all: clean compile run
else
all: skip
endif

skip:
	@echo Skipping cmocka unit tests 

compile:
	$(CC) -o $(BIN) $(SRC) $(DEPS) $(INC_PATH) $(CFLAGS) $(LDFLAGS) $(DEFS)

clean: 
	$(RM) $(BIN)

run:
	./$(BIN)

