# Sources
SRC_DIR = . polarssl libyaml
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c)))

# Compiler Settings
CFLAGS = --std=gnu99 -O2 -Wall -Wno-unused-value -Wno-unused-result -I.
CC = gcc

SYS := $(shell gcc -dumpmachine)
ifneq (, $(findstring linux, $(SYS)))
    # Linux
    CFLAGS += -Wno-unused-but-set-variable
else ifneq(, $(findstring cygwin, $(SYS)))
    # Cygwin
    CFLAGS += -Wno-unused-but-set-variable
    LIBS += -liconv
else ifneq(, $(findstring darwin, $(SYS)))
    # OS X
    LIBS += -liconv
else
    #Windows Build CFG
    CFLAGS += -Wno-unused-but-set-variable
    LIBS += -static-libgcc
endif

# MAKEROM Build Settings
OUTPUT = makerom

main: build

rebuild: clean build

build: $(OBJS)
	$(CC) -o $(OUTPUT) $(OBJS) $(LIBS)

clean:
	rm -rf $(OUTPUT) $(OBJS)