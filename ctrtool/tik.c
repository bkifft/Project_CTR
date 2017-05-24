#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes_keygen.h"
#include "tik.h"
#include "ctr.h"
#include "utils.h"

void tik_init(tik_context* ctx)
{
	memset(ctx, 0, sizeof(tik_context));
}

void tik_set_file(tik_context* ctx, FILE* file)
{
	ctx->file = file;
}

void tik_set_offset(tik_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void tik_set_size(tik_context* ctx, u32 size)
{
	ctx->size = size;
}

void tik_set_usersettings(tik_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void tik_get_titlekey(tik_context* ctx, u8 key[0x10])
{
	memcpy(key, ctx->titlekey, 0x10);
}

void tik_get_titleid(tik_context* ctx, u8 titleid[8])
{
	memcpy(titleid, ctx->tik.title_id, 8);
}

void tik_get_iv(tik_context* ctx, u8 iv[16])
{
	memset(iv, 0, 16);
	memcpy(iv, ctx->tik.title_id, 8);
}

void tik_decrypt_titlekey(tik_context* ctx, u8 decryptedkey[0x10]) 
{
	u8 iv[16];
	u8* keyX = settings_get_common_keyX(ctx->usersettings);
	const u8 keyYs[6][16] = {
		// application titles (eShop titles)
		{0xd0, 0x7b, 0x33, 0x7f, 0x9c, 0xa4, 0x38, 0x59, 0x32, 0xa2, 0xe2, 0x57, 0x23, 0x23, 0x2e, 0xb9},
		// system titles
		{0x0c, 0x76, 0x72, 0x30, 0xf0, 0x99, 0x8f, 0x1c, 0x46, 0x82, 0x82, 0x02, 0xfa, 0xac, 0xbe, 0x4c},
		// these are unused
		{0xc4, 0x75, 0xcb, 0x3a, 0xb8, 0xc7, 0x88, 0xbb, 0x57, 0x5e, 0x12, 0xa1, 0x09, 0x07, 0xb8, 0xa4},
		{0xe4, 0x86, 0xee, 0xe3, 0xd0, 0xc0, 0x9c, 0x90, 0x2f, 0x66, 0x86, 0xd4, 0xc0, 0x6f, 0x64, 0x9f},
		{0xed, 0x31, 0xba, 0x9c, 0x04, 0xb0, 0x67, 0x50, 0x6c, 0x44, 0x97, 0xa3, 0x5b, 0x78, 0x04, 0xfc},
		{0x5e, 0x66, 0x99, 0x8a, 0xb4, 0xe8, 0x93, 0x16, 0x06, 0x85, 0x0f, 0xd7, 0xa1, 0x6d, 0xd7, 0x55},
	};
	u8 key[16];

	memset(decryptedkey, 0, 0x10);

	if (!keyX)
	{
		fprintf(stdout, "Warning, could not read common key.\n");
	}
	else
	{
		ctr_aes_keygen(keyX, keyYs[(ctx->tik.title_id[3] & 0x10) ? 1 : 0], key);
		memset(iv, 0, 0x10);
		memcpy(iv, ctx->tik.title_id, 8);

		ctr_init_cbc_decrypt(&ctx->aes, key, iv);
		ctr_decrypt_cbc(&ctx->aes, ctx->tik.encrypted_title_key, decryptedkey, 0x10);
	}
}

void tik_process(tik_context* ctx, u32 actions)
{
	if (ctx->size < sizeof(eticket))
	{
		fprintf(stderr, "Error, ticket size too small\n");
		goto clean;
	}

	fseeko64(ctx->file, ctx->offset, SEEK_SET);
	fread((u8*)&ctx->tik, 1, sizeof(eticket), ctx->file);

	tik_decrypt_titlekey(ctx, ctx->titlekey);

	if (actions & InfoFlag)
	{
		tik_print(ctx); 
	}

clean:
	return;
}

void tik_print(tik_context* ctx)
{
	int i;
	eticket* tik = &ctx->tik;

	fprintf(stdout, "\nTicket content:\n");
	fprintf(stdout,
		"Signature Type:         %08x\n"
		"Issuer:                 %s\n",
		getle32(tik->sig_type), tik->issuer
	);

	fprintf(stdout, "Signature:\n");
	hexdump(tik->signature, 0x100);
	fprintf(stdout, "\n");

	memdump(stdout, "Encrypted Titlekey:     ", tik->encrypted_title_key, 0x10);
	
	if (settings_get_common_keyX(ctx->usersettings))
		memdump(stdout, "Decrypted Titlekey:     ", ctx->titlekey, 0x10);

	memdump(stdout,	"Ticket ID:              ", tik->ticket_id, 0x08);
	fprintf(stdout, "Ticket Version:         %d\n", getle16(tik->ticket_version));
	memdump(stdout,	"Title ID:               ", tik->title_id, 0x08);
	fprintf(stdout, "Common Key Index:       %d\n", tik->commonkey_idx);

	fprintf(stdout, "Content permission map:\n");
	for(i = 0; i < 0x40; i++) {
		printf(" %02x", tik->content_permissions[i]);

		if ((i+1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
}
