#pragma once

static const int CIA_ALIGN_SIZE = 0x40;

// Enums
typedef enum
{
	CIA_NO_NCCH0 = -1,
	CIA_INVALID_NCCH0 = -2,
	CIA_CONFILCTING_CONTENT_IDS = -3,
	CIA_BAD_VERSION = -4,
} cia_errors;

// Structs
typedef struct
{
	u8 hdrSize[4];
	u8 type[2];
	u8 version[2];
	u8 certChainSize[4];
	u8 tikSize[4];
	u8 tmdSize[4];
	u8 metaSize[4];
	u8 contentSize[8];
	u8 contentIndex[0x2000];
} cia_hdr;

typedef struct
{
	u8 dependencyList[0x30*0x8];
	u8 padding0[0x180];
	u8 coreVersion[4];
	u8 padding1[0xfc];
} cia_metadata;

typedef struct
{
	u8 *inFile;
	u64 inFileSize;

	FILE *out;

	rsf_settings *rsf;
	keys_struct *keys;

	struct{
		u8 titleId[8];
		u16 titleVersion[4];
		u8 titleKey[16];
	} common;
	

	struct{
		u8 caCrlVersion;
		u8 signerCrlVersion;
	} cert;

	struct{
		u8 issuer[0x40];
		u8 formatVersion;

		u16 version;

		u8 ticketId[8];
		u8 deviceId[8];
		u8 licenceType;
		u8 audit;
		u8 eshopAccId[4];
	} tik;

	struct{
		u8 issuer[0x40];
		u8 formatVersion;

		u16 version;

		u8 titleType[4];
		u8 savedataSize[4];
		u8 privSavedataSize[4];
		u8 twlFlag;
	} tmd;

	struct{
		bool IsCfa;
		bool IsDlc;
		bool encryptCia;

		bool keyNotFound;

		FILE **filePtrs;
		u64 fileSize[CIA_MAX_CONTENT];

		/* Misc Records */
		u16 count;
		u64 offset[CIA_MAX_CONTENT];
		u64 totalSize;

		/* Content Chunk Records */
		u64 size[CIA_MAX_CONTENT];
		u16 index[CIA_MAX_CONTENT];
		u16 flags[CIA_MAX_CONTENT];
		u32 id[CIA_MAX_CONTENT];
		u8 hash[CIA_MAX_CONTENT][0x20];		
	} content;

	struct{
		buffer_struct ciaHdr;
		
		u32 certChainOffset;
		buffer_struct certChain;

		u32 tikOffset;
		buffer_struct tik;

		u32 tmdOffset;
		buffer_struct tmd;

		u32 metaOffset;
		buffer_struct meta;

		u64 contentOffset;
		buffer_struct content;
	} ciaSections;
} cia_settings;

// Public Prototypes
int build_CIA(user_settings *usrset);

// Cia Read Functions
u64 GetCiaCertOffset(cia_hdr *hdr);
u64 GetCiaCertSize(cia_hdr *hdr);
u64 GetTikOffset(cia_hdr *hdr);
u64 GetTikSize(cia_hdr *hdr);
u64 GetTmdOffset(cia_hdr *hdr);
u64 GetTmdSize(cia_hdr *hdr);
u64 GetContentOffset(cia_hdr *hdr);
u64 GetContentSize(cia_hdr *hdr);
u64 GetMetaOffset(cia_hdr *hdr);
u64 GetMetaSize(cia_hdr *hdr);