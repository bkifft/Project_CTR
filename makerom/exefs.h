#pragma once

#define MAX_EXEFS_SECTIONS 10 // DO NOT CHANGE

typedef enum
{
	PTR_ERROR = -10,
	EXEFS_MAX_REACHED = -11,
	EXEFS_SECTION_NAME_ERROR = -12,

} exefs_errors;

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

typedef struct
{
	//Input
	int fileCount;
	u8 *file[MAX_EXEFS_SECTIONS];
	u32 fileSize[MAX_EXEFS_SECTIONS];
	u32 fileOffset[MAX_EXEFS_SECTIONS];
	char fileName[MAX_EXEFS_SECTIONS][8];
	u32 mediaUnit;
	
	//Working Data
	exefs_filehdr fileHdr[MAX_EXEFS_SECTIONS];
	u8 fileHashes[MAX_EXEFS_SECTIONS][0x20];
	
} exefs_buildctx;

/* ExeFs Build Functions */
int BuildExeFs(ncch_settings *ncchset);

/* ExeFs Read Functions */
bool DoesExeFsSectionExist(char *section, u8 *ExeFs);
u8* GetExeFsSection(char *section, u8 *ExeFs);
u8* GetExeFsSectionHash(char *section, u8 *ExeFs);
u32 GetExeFsSectionSize(char *section, u8 *ExeFs);
u32 GetExeFsSectionOffset(char *section, u8 *ExeFs);
