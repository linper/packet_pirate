
ifeq ($(CONFIG_TEST_IMPROV),y)
all: test
else
all: skip
endif

skip:
	@echo Skipping imporvized integration tests

test:
	./test.sh
