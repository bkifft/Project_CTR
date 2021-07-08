#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "utils.h"
#include "ivfc.h"
#include "ctr.h"

void ivfc_init(ivfc_context* ctx)
{
	memset(ctx, 0, sizeof(ivfc_context));
}

void ivfc_set_usersettings(ivfc_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void ivfc_set_offset(ivfc_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void ivfc_set_size(ivfc_context* ctx, u64 size)
{
	ctx->size = size;
}

void ivfc_set_file(ivfc_context* ctx, FILE* file)
{
	ctx->file = file;
}

void ivfc_set_encrypted(ivfc_context* ctx, u32 encrypted)
{
	ctx->encrypted = encrypted;
}

void ivfc_set_key(ivfc_context* ctx, u8 key[16])
{
	ctr_init_key(&ctx->aes, key);
}

void ivfc_set_counter(ivfc_context* ctx, u8 counter[16])
{
	memcpy(ctx->counter, counter, 16);
}

void ivfc_fseek(ivfc_context* ctx, u64 offset)
{
	u64 data_pos = offset - ctx->offset;
	fseeko64(ctx->file, offset, SEEK_SET);

	if (ctx->encrypted) {
		//printf("start fseek encrypted prep\n");
		ctr_init_counter(&ctx->aes, ctx->counter);
		//printf("middle fseek encrypted prep\n");
		ctr_add_counter(&ctx->aes, (u32)(data_pos / 0x10));
		//printf("finish fseek encrypted prep\n");
	}
}

size_t ivfc_fread(ivfc_context* ctx, void* buffer, size_t size, size_t count)
{
	size_t read;
	if ((read = fread(buffer, size, count, ctx->file)) != count) {
		//printf("ivfc_fread() fail\n");
		return read;
	}
	if (ctx->encrypted) {
		ctr_crypt_counter(&ctx->aes, buffer, buffer, size*read);
	}
	return read;
}


void ivfc_process(ivfc_context* ctx, u32 actions)
{
	ivfc_fseek(ctx, ctx->offset);
	ivfc_fread(ctx, &ctx->header, 1, sizeof(ivfc_header));

	if (getle32(ctx->header.magic) != MAGIC_IVFC)
	{
		fprintf(stdout, "Error, IVFC segment corrupted\n");
		return;
	}

	if (getle32(ctx->header.id) == 0x10000)
	{
		ctx->levelcount = 3;

		ctx->level[2].hashblocksize = 1 << getle32(ctx->header.level3.blocksize);
		ctx->level[1].hashblocksize = 1 << getle32(ctx->header.level2.blocksize);
		ctx->level[0].hashblocksize = 1 << getle32(ctx->header.level1.blocksize);

		ctx->bodyoffset = align64(IVFC_HEADER_SIZE + getle32(ctx->header.masterhashsize), ctx->level[2].hashblocksize);
		ctx->bodysize = getle64(ctx->header.level3.hashdatasize);
		
		ctx->level[2].dataoffset = ctx->bodyoffset;
		ctx->level[2].datasize = align64(ctx->bodysize, ctx->level[2].hashblocksize);

		ctx->level[0].dataoffset = ctx->level[2].dataoffset + ctx->level[2].datasize;
		ctx->level[0].datasize = align64(getle64(ctx->header.level1.hashdatasize), ctx->level[0].hashblocksize);

		ctx->level[1].dataoffset = ctx->level[0].dataoffset + ctx->level[0].datasize;
		ctx->level[1].datasize = align64(getle64(ctx->header.level2.hashdatasize), ctx->level[1].hashblocksize);

		ctx->level[0].hashoffset = IVFC_HEADER_SIZE;
		ctx->level[1].hashoffset = ctx->level[0].dataoffset;
		ctx->level[2].hashoffset = ctx->level[1].dataoffset;
	}

	if (actions & VerifyFlag)
		ivfc_verify(ctx, actions);

	if (actions & InfoFlag)
		ivfc_print(ctx);		

}

void ivfc_verify(ivfc_context* ctx, u32 flags)
{
	u32 i, j;
	u32 blockcount;

	for(i=0; i<ctx->levelcount; i++)
	{
		ivfc_level* level = ctx->level + i;

		level->hashcheck = Fail;
	}

	// Import IVFC level hashes
	uint8_t *levelhash[IVFC_MAX_LEVEL] = { NULL };

	for (i=0; i<ctx->levelcount; i++)
	{
		blockcount = (u32)(ctx->level[i].datasize / ctx->level[i].hashblocksize);
		u32 read_size = align(blockcount * 0x20, ctx->level[i].hashblocksize);
		levelhash[i] = malloc(read_size);
		ivfc_read(ctx, ctx->level[i].hashoffset, read_size, levelhash[i]);
	}

	// Verify blocks
	for (i=0; i<ctx->levelcount; i++)
	{
		blockcount = (u32) (ctx->level[i].datasize / ctx->level[i].hashblocksize);
		if (ctx->level[i].datasize % ctx->level[i].hashblocksize != 0)
		{
			fprintf(stderr, "Error, IVFC block size mismatch\n");
			return;
		}

		ctx->level[i].hashcheck = Good;

		for (j=0; j<blockcount; j++)
		{
			u8 calchash[32];
			
			// a hash level
			if (i < 2) {
				ctr_sha_256(levelhash[i+1] + ctx->level[i].hashblocksize * j, ctx->level[i].hashblocksize, calchash);
			}
			// a data level
			else {
				ivfc_read(ctx, ctx->level[i].dataoffset + j * ctx->level[i].hashblocksize, ctx->level[i].hashblocksize, ctx->buffer);
				ctr_sha_256(ctx->buffer, (u32)ctx->level[i].hashblocksize, calchash);
			}

			if (memcmp(calchash, levelhash[i] + 0x20 * j, 0x20) != 0) {
				ctx->level[i].hashcheck = Fail;
			}
				
		}
	}

	// Free level hashes
	for (int i = 0; i < 3; i++) {
		free(levelhash[i]);
	}
}

void ivfc_read(ivfc_context* ctx, u64 offset, u64 size, u8* buffer)
{
	if ( (offset > ctx->size) || (offset+size > ctx->size) )
	{
		fprintf(stderr, "Error, IVFC offset out of range (offset=0x%08"PRIx64", size=0x%08"PRIx64")\n", offset, size);
		return;
	}

	ivfc_fseek(ctx, ctx->offset + offset);
	if (size != ivfc_fread(ctx, buffer, 1, (size_t) size))
	{
		fprintf(stderr, "Error, IVFC could not read file\n");
		return;
	}
}

void ivfc_hash(ivfc_context* ctx, u64 offset, u64 size, u8* hash)
{
	if (size > IVFC_MAX_BUFFERSIZE)
	{
		fprintf(stderr, "Error, IVFC hash block size too big.\n");
		return;
	}

	ivfc_read(ctx, offset, size, ctx->buffer);

	ctr_sha_256(ctx->buffer, (u32) size, hash);
}

void ivfc_print(ivfc_context* ctx)
{
	u32 i;
	ivfc_header* header = &ctx->header;

	fprintf(stdout, "\nIVFC:\n");

	fprintf(stdout, "Header:                 %.4s\n", header->magic);
	fprintf(stdout, "Id:                     %08x\n", getle32(header->id));

	for(i=0; i<ctx->levelcount; i++)
	{
		ivfc_level* level = ctx->level + i;

		fprintf(stdout, "\n");
		if (level->hashcheck == Unchecked)
			fprintf(stdout, "Level %d:               \n", i);
		else
			fprintf(stdout, "Level %d (%s):          \n", i, level->hashcheck == Good? "GOOD" : "FAIL");
		fprintf(stdout, " Data offset:           0x%08"PRIx64"\n", ctx->offset + level->dataoffset);
		fprintf(stdout, " Data size:             0x%08"PRIx64"\n", level->datasize);
		fprintf(stdout, " Hash offset:           0x%08"PRIx64"\n", ctx->offset + level->hashoffset);
		fprintf(stdout, " Hash block size:       0x%08x\n", level->hashblocksize);
	}
}

u64 ivfc_get_body_offset(ivfc_context* ctx)
{
	return ctx->bodyoffset;
}

u64 ivfc_get_body_size(ivfc_context* ctx)
{
	return ctx->bodysize;
}

