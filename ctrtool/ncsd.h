#ifndef _NCSD_H_
#define _NCSD_H_

#include "types.h"
#include "keyset.h"
#include "settings.h"
#include "ncch.h"

typedef struct
{
	u32 offset;
	u32 size;
} ncsd_partition_geometry;

typedef struct
{
	u8 signature[0x100];
	u8 magic[4];
	u8 mediasize[4];
	u8 mediaid[8];
	u8 partitionfstype[8];
	u8 partitioncrypttype[8];
	ncsd_partition_geometry partitiongeometry[8];
	u8 extendedheaderhash[0x20];
	u8 additionalheadersize[4];
	u8 sectorzerooffset[4];
	u8 flags[8];
	u8 titleid[0x40];
	u8 reserved[0x30];
} ctr_ncsdheader;


typedef struct
{
	FILE* file;
	u64 offset;
	u64 size;
	u32 ncch_index;
	ctr_ncsdheader header;
	settings* usersettings;
	int headersigcheck;
	ncch_context ncch;
} ncsd_context;


void ncsd_init(ncsd_context* ctx);
void ncsd_set_offset(ncsd_context* ctx, u64 offset);
void ncsd_set_size(ncsd_context* ctx, u64 size);
void ncsd_set_ncch_index(ncsd_context* ctx, u32 ncch_index);
void ncsd_set_file(ncsd_context* ctx, FILE* file);
void ncsd_set_usersettings(ncsd_context* ctx, settings* usersettings);
int ncsd_signature_verify(const void* blob, rsakey2048* key);
void ncsd_process(ncsd_context* ctx, u32 actions);
void ncsd_print(ncsd_context* ctx);
u64 ncsd_get_mediaunit_size(ncsd_context* ctx);

#endif // _NCSD_H_
