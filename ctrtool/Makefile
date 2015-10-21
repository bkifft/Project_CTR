# Sources
SRC_DIR = . polarssl tinyxml
OBJS = $(foreach dir,$(SRC_DIR),$(subst .c,.o,$(wildcard $(dir)/*.c))) $(foreach dir,$(SRC_DIR),$(subst .cpp,.o,$(wildcard $(dir)/*.cpp)))

# Compiler Settings
LIBS = -static-libgcc -static-libstdc++
CXXFLAGS = -I. 
CFLAGS = -O2 -flto -Wall -Wno-unused-variable -Wno-unused-but-set-variable -I.
OUTPUT = ctrtool
CC = gcc
CXX = g++

main: $(OBJS)
	$(CXX) -o $(OUTPUT) $(LIBS) $(OBJS)

clean:
	rm -rf $(OUTPUT) $(OBJS)
