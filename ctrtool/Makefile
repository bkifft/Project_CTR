# Sources
SRC_DIR = . polarssl tinyxml
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c))) $(foreach dir,$(SRC_DIR),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp)))

# Compiler Settings
OUTPUT = ctrtool
CXXFLAGS = -I.
CFLAGS = -O2 -Wall -Wno-unused-variable  -Wno-unused-result -I. -std=c11
CC = gcc
CXX = g++
SYS := $(shell gcc -dumpmachine)
ifneq (, $(findstring linux, $(SYS)))
    # Linux
    CFLAGS += -Wno-unused-but-set-variable
else ifneq(, $(findstring cygwin, $(SYS)))
    # Cygwin
    CFLAGS += -Wno-unused-but-set-variable -DUSE_FILE32API
    LIBS += -liconv -static-libgcc -static-libstdc++
else ifneq(, $(findstring darwin, $(SYS)))
    # OS X
    LIBS += -liconv
else
    #Windows Build CFG
    CFLAGS += -Wno-unused-but-set-variable
    LIBS += -static-libgcc -static-libstdc++
endif

main: $(OBJS)
	$(CXX) -o $(OUTPUT) $(OBJS) $(LIBS)

clean:
	rm -rf $(OUTPUT) $(OBJS)
