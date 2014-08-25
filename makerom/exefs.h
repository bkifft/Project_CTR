#pragma once

#define MAX_EXEFS_SECTIONS 10 // DO NOT CHANGE

typedef struct
{
	char name[8];
	u8 offset[4];
	u8 size[4];
} exefs_filehdr;

typedef struct
{
	exefs_filehdr fileHdr[MAX_EXEFS_SECTIONS];
	u8 reserved[0x20];
	u8 fileHashes[MAX_EXEFS_SECTIONS][0x20];
} exefs_hdr;
