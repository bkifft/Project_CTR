#pragma once

typedef enum
{
	NCCH_MEMERROR = -1,
	SAVE_DATA_TOO_LARGE = -2,
	NCCH_SECTION_NOT_EXIST = -3,
	UNABLE_TO_LOAD_NCCH_KEY = -4,
	NCCH_EXPORT_BUFFER_TOO_SMALL = -5,
	NO_ROMFS_IN_CFA = -6,
	NO_EXHEADER_IN_CXI = -7,
	NO_EXEFS_IN_CXI = -8,
	// SigCheck Errors
	CXI_CORRUPT = -9,
	ACCESSDESC_SIG_BAD = -10,
	NCCH_HDR_SIG_BAD = -11,
	// HashCheck Errors
	ExHeader_Hashfail = -12,
	Logo_Hashfail = -13,
	ExeFs_Hashfail = -14,
	RomFs_Hashfail = -15,
	// Others
	NCCH_BAD_YAML_SET = -16,
	DATA_POS_DNE = -17,
} ncch_errors;

typedef enum
{
	ncch_exhdr = 1,
	ncch_exefs,
	ncch_romfs,
	ncch_Logo,
	ncch_PlainRegion,
} ncch_section;

typedef enum
{
	NoKey,
	KeyIsNormalFixed,
	KeyIsSystemFixed,
	KeyIsUnFixed,
	KeyIsUnFixed2,
} ncch_key_type;

typedef enum
{
	SecureCrypto2 = 3,
	ContentPlatform = 4,
	ContentType = 5,
	ContentUnitSize = 6,
	OtherFlag = 7
} ncch_flags;

typedef enum
{
	UnFixedCryptoKey = 0x0,
	FixedCryptoKey = 0x1,
	NoMountRomFs = 0x2,
	NoCrypto = 0x4,
} ncch_otherflag_bitmask;

typedef enum
{
	content_Data = 0x1,
	content_Executable = 0x2,
	content_SystemUpdate = 0x4,
	content_Manual = 0x8,
	content_Child = (0x4|0x8),
	content_Trial = 0x10
} ncch_content_bitmask;

typedef struct
{
	u16 formatVersion;
	u32 exhdrOffset;
	u32 exhdrSize;
	u32 acexOffset;
	u32 acexSize;
	u64 logoOffset;
	u64 logoSize;
	u64 plainRegionOffset;
	u64 plainRegionSize;
	u64 exefsOffset;
	u64 exefsSize;
	u64 exefsHashDataSize;
	u64 romfsOffset;
	u64 romfsSize;
	u64 romfsHashDataSize;
	u8 titleId[8];
	u8 programId[8];
} ncch_struct;

typedef struct
{
	u8 magic[4];
	u8 ncchSize[4];
	u8 titleId[8];
	u8 makerCode[2];
	u8 formatVersion[2];
	u8 padding0[4];
	u8 programId[8];
	u8 padding1[0x10];
	u8 logoHash[0x20]; // SHA-256 over the entire logo region
	u8 productCode[0x10];
	u8 exhdrHash[0x20]; // SHA-256 over exhdrSize of the exhdr region
	u8 exhdrSize[4];
	u8 padding2[4];
	u8 flags[8];
	u8 plainRegionOffset[4];
	u8 plainRegionSize[4];
	u8 logoOffset[4];
	u8 logoSize[4];
	u8 exefsOffset[4];
	u8 exefsSize[4];
	u8 exefsHashSize[4];
	u8 padding4[4];
	u8 romfsOffset[4];
	u8 romfsSize[4];
	u8 romfsHashSize[4];
	u8 padding5[4];
	u8 exefsHash[0x20];
	u8 romfsHash[0x20];
} ncch_hdr;


typedef struct
{
	buffer_struct *out;
	keys_struct *keys;
	rsf_settings *rsfSet;

	struct
	{
		u32 mediaSize;
		bool IncludeExeFsLogo;
		bool CompressCode;
		bool UseOnSD;
		bool Encrypt;
		bool FreeProductCode;
		bool IsCfa;
		bool IsBuildingCodeSection;
		bool UseRomFS;
	} options;

	struct
	{
		FILE *elf;
		u64 elfSize;

		FILE *banner;
		u64 bannerSize;

		FILE *icon;
		u64 iconSize;

		FILE *logo;
		u64 logoSize;

		FILE *code;
		u64 codeSize;

		FILE *exhdr;
		u64 exhdrSize;

		FILE *romfs;
		u64 romfsSize;

		FILE *plainregion;
		u64 plainregionSize;
	} componentFilePtrs;

	struct
	{
		buffer_struct code;
		buffer_struct banner;
		buffer_struct icon;
	} exefsSections;

	struct
	{
		u32 textAddress;
		u32 textSize;
		u32 textMaxPages;
		u32 roAddress;
		u32 roSize;
		u32 roMaxPages;
		u32 rwAddress;
		u32 rwSize;
		u32 rwMaxPages;
		u32 bssSize;
	} codeDetails;

	struct
	{
		buffer_struct exhdr;
		buffer_struct acexDesc;
		buffer_struct logo;
		buffer_struct plainRegion;
		buffer_struct exeFs;
	} sections;
	
	ncch_struct cryptoDetails;


} ncch_settings;

// NCCH Build Functions
int build_NCCH(user_settings *usrset);


// NCCH Read Functions
int VerifyNCCH(u8 *ncch, keys_struct *keys, bool CheckHash, bool SuppressOutput);

u8* RetargetNCCH(FILE *fp, u64 size, u8 *TitleId, u8 *ProgramId, keys_struct *keys);
int ModifyNcchIds(u8 *ncch, u8 *titleId, u8 *programId, keys_struct *keys);


ncch_hdr* GetNCCH_CommonHDR(void *out, FILE *fp, u8 *buf);
bool IsNCCH(FILE *fp, u8 *buf);
bool IsCfa(ncch_hdr* hdr);
u32 GetNCCH_MediaUnitSize(ncch_hdr* hdr);
u32 GetNCCH_MediaSize(ncch_hdr* hdr);
ncch_key_type GetNCCHKeyType(ncch_hdr* hdr);

u8* GetNCCHKey0(ncch_key_type keytype, keys_struct *keys);
u8* GetNCCHKey1(ncch_key_type keytype, keys_struct *keys);

int GetNCCHStruct(ncch_struct *ctx, ncch_hdr *header);
void ncch_get_counter(ncch_struct *ctx, u8 counter[16], u8 type);
void CryptNCCHSection(u8 *buffer, u64 size, u64 src_pos, ncch_struct *ctx, u8 key[16], u8 type);