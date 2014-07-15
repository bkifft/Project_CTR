#pragma once

typedef enum
{
	CCI_MAX_CONTENT = 8,
	CIA_MAX_CONTENT = MAX_U16,
} content_limits;

typedef enum
{
	VER_MAJOR,
	VER_MINOR,
	VER_MICRO
} title_ver_index;

typedef enum
{
	VER_MAJOR_MAX = 63,
	VER_MINOR_MAX = 63,
	VER_MICRO_MAX = 15,
	VER_DVER_MAX = 4095,
} title_ver_max;

typedef enum
{
	USR_PTR_PASS_FAIL = -1,
	USR_HELP = -2,
	USR_ARG_REQ_PARAM = -3,
	USR_UNK_ARG = -4,
	USR_BAD_ARG = -5,
	USR_MEM_ERROR = -6,
} user_settings_errors;

typedef enum
{
	infile_none,
	infile_ncch,
	infile_ncsd,
	infile_srl,
} infile_type;

typedef enum
{
	format_not_set,
	CXI,
	CFA,
	CCI,
	CIA,
	NCCH
} output_format;

typedef struct
{
	char *name;
	char *value;
} dname_item;


typedef struct
{ 
	dname_item *items;
	u32 m_items;
	u32 u_items;
} dname_struct; 

static const char output_extention[4][5] = {".cxi",".cfa",".cci",".cia"};

/* This does not follow style, so the rsf string names match the variables where they're stored */
typedef struct
{	
	struct{
		// Booleans
		// Booleans
		bool MediaFootPadding;
		//bool NoPadding; // DELETE
		bool AllowUnalignedSection;
		bool EnableCrypt;
		bool EnableCompress;
		bool FreeProductCode;
		bool UseOnSD;

		// Strings
		char *PageSize;
		
		// String Collections
		//u32 AppendSystemCallNum; // DELETE
		//char **AppendSystemCall; // DELETE
	} Option;
	
	struct{
		// Booleans
		bool DisableDebug;
		bool EnableForceDebug;
		bool CanWriteSharedPage;
		bool CanUsePrivilegedPriority;
		bool CanUseNonAlphabetAndNumber;
		bool PermitMainFunctionArgument;
		bool CanShareDeviceMemory;
		bool UseOtherVariationSaveData;
		bool UseExtSaveData;
		bool UseExtendedSaveDataAccessControl;
		bool RunnableOnSleep;
		bool SpecialMemoryArrange;
		
		// Strings
		//char *ProgramId; // DELETE
		char *IdealProcessor;
		char *Priority;
		char *MemoryType;
		char *SystemMode;
		char *CoreVersion;
		char *HandleTableSize;
		char *SystemSaveDataId1;
		char *SystemSaveDataId2;
		char *OtherUserSaveDataId1;
		char *OtherUserSaveDataId2;
		char *OtherUserSaveDataId3;
		char *ExtSaveDataId;
		char *AffinityMask;
		// Strings From DESC
		char *DescVersion;
		//char *CryptoKey; // DELETE
		char *ResourceLimitCategory;
		char *ReleaseKernelMajor;
		char *ReleaseKernelMinor;
		char *MaxCpu;
		
		// String Collections
		u32 MemoryMappingNum;
		char **MemoryMapping;
		u32 IORegisterMappingNum;
		char **IORegisterMapping;
		u32 FileSystemAccessNum;
		char **FileSystemAccess;
		u32 IoAccessControlNum;
		char **IoAccessControl; //Equiv to Arm9AccessControl
		u32 InterruptNumbersNum;
		char **InterruptNumbers;
		u32 SystemCallAccessNum;
		char **SystemCallAccess;
		u32 ServiceAccessControlNum;
		char **ServiceAccessControl;
		u32 StorageIdNum; // DELETE
		char **StorageId; // DELETE
		u32 AccessibleSaveDataIdsNum;
		char **AccessibleSaveDataIds;
	} AccessControlInfo;

	struct{
		// Strings
		char *AppType;
		char *StackSize;
		char *RemasterVersion;
		char *SaveDataSize;
		char *JumpId;
		
		// String Collections
		u32 DependencyNum;
		char **Dependency;
	} SystemControlInfo;
	
	struct{
		// Strings
		char *Title;
		char *CompanyCode;
		char *ProductCode;
		char *ContentType;
		char *Logo;
		//char *BackupMemoryType;// Delete
		//char *InitialCode;// Delete
	} BasicInfo;
	
	struct{
		// Strings
		char *HostRoot;
		//char *Padding; // DELETE
		
		// String Collections
		u32 DefaultRejectNum;
		char **DefaultReject;
		u32 RejectNum;
		char **Reject;
		u32 IncludeNum;
		char **Include;
		u32 FileNum;
		char **File;
	} Rom;
	
	struct{
		u32 TextNum;
		char **Text;
		u32 ReadOnlyNum;
		char **ReadOnly;
		u32 ReadWriteNum;
		char **ReadWrite;
	} ExeFs;
	
	u32 PlainRegionNum;
	char **PlainRegion;
	
	struct{
		// Strings
		//char *Platform; // DELETE
		char *Category;
		char *UniqueId;
		char *Version;
		char *ContentsIndex;
		char *Variation;
		//char *Use; // DELETE
		char *ChildIndex;
		char *DemoIndex;
		char *TargetCategory;
		
		// String Collections
		u32 CategoryFlagsNum;
		char **CategoryFlags;
	} TitleInfo;
	
	struct{
		char *WritableAddress;
		char *CardType;
		char *CryptoType;
		char *CardDevice;
		char *MediaType;
		char *MediaSize;
		char *BackupWriteWaitTime;
		char *SaveCrypto;
	} CardInfo;
	
	struct{
		bool Found;

		char *D;
		char *P;
		char *Q;
		char *DP;
		char *DQ;
		char *InverseQ;
		char *Modulus;
		char *Exponent;

		char *AccCtlDescSign;
		char *AccCtlDescBin;
	} CommonHeaderKey;
} rsf_settings;

typedef struct
{
	struct{
		char *rsfPath;
		bool outFileName_mallocd;
		char *outFileName;
		output_format outFormat;

		// Keys
		keys_struct keys; 
	
		// RSF Imported Settings
		rsf_settings rsfSet;

		// Content Details
		char **contentPath;

		char *workingFilePath;
		infile_type workingFileType; // Could Be ncch/ncsd/srl. This is mainly used for CIA gen
		buffer_struct workingFile;
	} common;
	
	dname_struct dname; // For RSF value subsitution

	struct{
		bool buildNcch0;
		output_format ncchType;
		char *elfPath;
		char *iconPath;
		char *bannerPath;
		char *logoPath; // override logo specs in RSF

		bool includeExefsLogo; // for <5.x compatibility
	
		// ncch rebuild settings
		char *codePath; // uncompressed exefs .code
		char *exheaderPath; // for .code details
		char *plainRegionPath; // prebuilt Plain Region
		char *romfsPath; // Prebuild _cleartext_ romfs binary
	} ncch; // Ncch0 Build
	
	struct{ 
		bool useSDKStockData;  // incase we want to use the SDK stock data, for whatever reason.
		bool dontModifyNcchTitleID;
		bool closeAlignWritableRegion;
		char *cverCiaPath;
	} cci; // CCI Settings
	
	struct{
		bool randomTitleKey;
		bool encryptCia;
		bool DlcContent;

		bool useNormTitleVer;
		bool useDataTitleVer;
		u16 titleVersion[3];

		u64 contentId[CIA_MAX_CONTENT]; // For CIA
	} cia; // CIA Settings
	
	
} user_settings;

// Prototypes

void init_UserSettings(user_settings *usr_settings);
void free_UserSettings(user_settings *usr_settings);
int ParseArgs(int argc, char *argv[], user_settings *usr_settings);
void ReadYAMLtest(char *filepath);

void free_RsfSettings(rsf_settings *set);
