# Makerom Sources
UTILS_OBJS = utils.o ctr_utils.o dir.o utf.o keyset.o titleid.o
CIA_OBJS = cia.o certs.o tik.o tmd.o
NCCH_OBJS = ncch.o exheader.o accessdesc.o exefs.o elf.o romfs.o romfs_import.o romfs_gen.o
NCSD_OBJS = ncsd.o cardinfo.o
SETTINGS_OBJS = user_settings.o rsf_settings.o
LIB_API_OBJS = crypto.o yaml_parser.o blz.o

OBJS = makerom.o $(UTILS_OBJS) $(LIB_API_OBJS) $(SETTINGS_OBJS) $(NCSD_OBJS) $(NCCH_OBJS) $(CIA_OBJS)

# Libraries
POLAR_OBJS = polarssl/aes.o polarssl/bignum.o polarssl/rsa.o polarssl/sha1.o polarssl/sha2.o polarssl/padlock.o polarssl/md.o polarssl/md_wrap.o polarssl/md2.o polarssl/md4.o polarssl/md5.o polarssl/sha4.o polarssl/base64.o polarssl/cipher.o polarssl/cipher_wrap.o polarssl/camellia.o polarssl/des.o polarssl/blowfish.o
YAML_OBJS = libyaml/api.o libyaml/dumper.o libyaml/emitter.o libyaml/loader.o libyaml/parser.o libyaml/reader.o libyaml/scanner.o libyaml/writer.o

# Compiler Settings
LIBS = -static-libgcc -static-libstdc++
CXXFLAGS = -I.
CFLAGS = --std=c99 -Wall -Wno-unused-but-set-variable -Wno-unused-value -I. -DMAKEROM_VER_MAJOR=$(VER_MAJOR) -DMAKEROM_VER_MINOR=$(VER_MINOR) $(MAKEROM_BUILD_FLAGS) -m64
CC = gcc
 
# MAKEROM Build Settings
MAKEROM_BUILD_FLAGS = #-DDEBUG
VER_MAJOR = 0
VER_MINOR = 12
OUTPUT = makerom

main: build

rebuild: clean build

build: $(OBJS) $(POLAR_OBJS) $(YAML_OBJS)
	g++ -o $(OUTPUT) $(LIBS) $(OBJS) $(POLAR_OBJS) $(YAML_OBJS) -m64

clean:
	rm -rf $(OUTPUT) $(OBJS) $(POLAR_OBJS) $(YAML_OBJS) *.cci *.cia *.cxi *.cfa