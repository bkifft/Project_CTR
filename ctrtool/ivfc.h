#ifndef __IVFC_H__
#define __IVFC_H__

#include "types.h"
#include "ctr.h"
#include "settings.h"

#define IVFC_HEADER_SIZE 0x60
#define IVFC_MAX_LEVEL 4
#define IVFC_MAX_BUFFERSIZE 0x4000

typedef struct
{
	u8 logicaloffset[8];
	u8 hashdatasize[8];
	u8 blocksize[4];
	u8 reserved[4];
} ivfc_levelheader;

typedef struct
{
	u64 dataoffset;
	u64 datasize;
	u64 hashoffset;
	u32 hashblocksize;
	int hashcheck;
} ivfc_level;

typedef struct
{
	u8 magic[4];
	u8 id[4];
	u8 masterhashsize[4];
	ivfc_levelheader level1;
	ivfc_levelheader level2;
	ivfc_levelheader level3;
	u8 reserved[4];
	u8 optionalsize[4];
} ivfc_header;

typedef struct
{
	FILE* file;
	u64 offset;
	u64 size;
	settings* usersettings;
	u8 counter[16];
	ctr_aes_context aes;
	int encrypted;

	ivfc_header header;

	u32 levelcount;
	ivfc_level level[IVFC_MAX_LEVEL];
	u64 bodyoffset;
	u64 bodysize;
	u8 buffer[IVFC_MAX_BUFFERSIZE];
} ivfc_context;

void ivfc_init(ivfc_context* ctx);
void ivfc_process(ivfc_context* ctx, u32 actions);
void ivfc_set_offset(ivfc_context* ctx, u64 offset);
void ivfc_set_size(ivfc_context* ctx, u64 size);
void ivfc_set_file(ivfc_context* ctx, FILE* file);
void ivfc_set_usersettings(ivfc_context* ctx, settings* usersettings);
void ivfc_set_encrypted(ivfc_context* ctx, u32 encrypted);
void ivfc_set_key(ivfc_context* ctx, u8 key[16]);
void ivfc_set_counter(ivfc_context* ctx, u8 counter[16]);
void ivfc_fseek(ivfc_context* ctx, u64 offset);
size_t ivfc_fread(ivfc_context* ctx, void* buffer, size_t size, size_t count);

void ivfc_verify(ivfc_context* ctx, u32 flags);
void ivfc_print(ivfc_context* ctx);

void ivfc_read(ivfc_context* ctx, u64 offset, u64 size, u8* buffer);
void ivfc_hash(ivfc_context* ctx, u64 offset, u64 size, u8* hash);

#endif // __IVFC_H__
