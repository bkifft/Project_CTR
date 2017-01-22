# Sources
SRC_DIR = . polarssl libyaml
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c)))

# Compiler Settings
CFLAGS = --std=gnu99 -O2 -Wall -Wno-unused-value -Wno-unused-result -I.
CC = gcc
ifeq ($(OS),Windows_NT)
    #Windows Build CFG
    CFLAGS += -Wno-unused-but-set-variable
    LIBS += -static-libgcc
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        # OS X
        LIBS += -liconv
    else
        # Linux
        CFLAGS += -Wno-unused-but-set-variable
    endif
endif


# MAKEROM Build Settings
OUTPUT = makerom

main: build

rebuild: clean build

build: $(OBJS)
	$(CC) -o $(OUTPUT) $(LIBS) $(OBJS)

install: $(OUTPUT)
	@cp ./$(OUTPUT) -t $(DEVKITARM)/bin/
	@echo "Installed."

clean:
	rm -rf $(OUTPUT) $(OBJS)
