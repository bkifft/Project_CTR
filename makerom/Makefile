# Sources
SRC_DIR = . polarssl libyaml
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c)))

# Compiler Settings
LIBS = -static-libgcc
CXXFLAGS = -I.
CFLAGS = --std=c99 -Wall -O2 -flto -static -Wno-unused-but-set-variable -Wno-unused-value -I. -DMAKEROM_VER_MAJOR=$(VER_MAJOR) -DMAKEROM_VER_MINOR=$(VER_MINOR) $(MAKEROM_BUILD_FLAGS) -m64
CC = gcc
 
# MAKEROM Build Settings
MAKEROM_BUILD_FLAGS = #-DDEBUG
VER_MAJOR = 0
VER_MINOR = 14
OUTPUT = makerom

main: build

rebuild: clean build

build: $(OBJS)
	g++ -o $(OUTPUT) $(LIBS) $(OBJS) -m64

clean:
	rm -rf $(OUTPUT) $(OBJS) *.cci *.cia *.cxi *.cfa
