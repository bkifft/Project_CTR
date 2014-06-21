#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "accessdesc.h"
#include "titleid.h"


/* Prototypes */
void free_ExHeaderSettings(exheader_settings *exhdrset);
int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset);
int get_ExHeaderSettingsFromRsf(exheader_settings *exhdrset);

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, rsf_settings *rsf);
int get_ExHeaderDependencyList(u8 *DependencyList, rsf_settings *rsf);
int get_ExHeaderSystemInfo(exhdr_SystemInfo *SystemInfo, rsf_settings *rsf);
int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf, bool useAccessDescPreset);
int SetARM11SystemLocalInfoFlags(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int GetAppType(int *AppType, rsf_settings *rsf);
int SetARM11ResLimitDesc(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11StorageInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11StorageInfoSystemSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11StorageInfoExtSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11StorageInfoOtherUserSaveData(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
bool CheckCondiditionsForNewAccessibleSaveDataIds(rsf_settings *rsf);
int SetARM11StorageInfoAccessibleSaveDataIds(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int SetARM11ServiceAccessControl(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf);
int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, rsf_settings *rsf);
int SetARM11KernelDescSysCallControl(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11SysCalls(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
void EnableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall);
void DisableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall);
int SetARM11KernelDescInteruptNumList(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11Interupts(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
void EnableInterupt(ARM11KernelCapabilityDescriptor *desc, int Interrupt, int i);
int SetARM11KernelDescAddressMapping(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11IOMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int GetARM11StaticMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
bool IsEndAddress(u32 Address);
bool IsStartAddress(u32 Address);
u32 GetIOMappingDesc(u32 Address);
u32 GetStaticMappingDesc(u32 Address, bool IsReadOnly);
u32 GetMappingDesc(u32 Address, u32 PrefixVal, s32 numPrefixBits, bool IsRO);
int SetARM11KernelDescOtherCapabilities(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int SetARM11KernelDescHandleTableSize(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
int SetARM11KernelDescReleaseKernelVersion(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf);
void SetARM11KernelDescValue(ARM11KernelCapabilityDescriptor *desc, u16 Index, u32 Value);
void SetARM11KernelDescBitmask(ARM11KernelCapabilityDescriptor *desc, u32 Bitmask);
void AllocateARM11KernelDescMemory(ARM11KernelCapabilityDescriptor *desc, u16 Num);
u32 GetDescPrefixMask(int numPrefixBits);
u32 GetDescPrefixBits(int numPrefixBits, u32 PrefixVal);
int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, rsf_settings *rsf);

/* ExHeader Signature Functions */
int SignAccessDesc(access_descriptor *acexDesc, keys_struct *keys)
{
	u8 *AccessDesc = (u8*) &acexDesc->ncchRsaPubKey;
	u8 *Signature = (u8*) &acexDesc->signature;
	return ctr_sig(AccessDesc,0x300,Signature,keys->rsa.acexPub,keys->rsa.acexPvt,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckAccessDescSignature(access_descriptor *acexDesc, keys_struct *keys)
{
	u8 *AccessDesc = (u8*) &acexDesc->ncchRsaPubKey;
	u8 *Signature = (u8*) &acexDesc->signature;
	return ctr_sig(AccessDesc,0x300,Signature,keys->rsa.acexPub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

/* ExHeader Build Functions */
int BuildExHeader(ncch_settings *ncchset)
{
	int result = 0;

	if(ncchset->options.IsCfa)
		return 0;

	exheader_settings *exhdrset = calloc(1,sizeof(exheader_settings));
	if(!exhdrset) {
		fprintf(stderr,"[EXHEADER ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	// Get Settings
	result = get_ExHeaderSettingsFromNcchset(exhdrset,ncchset);
	if(result) goto finish;

	result = get_ExHeaderSettingsFromRsf(exhdrset);
	if(result) goto finish;

	result = set_AccessDesc(exhdrset);
	if(result) goto finish;

finish:
	if(result) fprintf(stderr,"[EXHEADER ERROR] Failed to create ExHeader\n");
	free_ExHeaderSettings(exhdrset);
	return result;
}

void free_ExHeaderSettings(exheader_settings *exhdrset)
{
	free(exhdrset);
}

int get_ExHeaderSettingsFromNcchset(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Transfer settings */
	exhdrset->keys = ncchset->keys;
	exhdrset->rsf = ncchset->rsfSet;
	exhdrset->useAccessDescPreset = ncchset->keys->accessDescSign.presetType != desc_preset_NONE;

	/* Creating Output Buffer */
	ncchset->sections.exhdr.size = sizeof(extended_hdr);
	ncchset->sections.exhdr.buffer = calloc(1,ncchset->sections.exhdr.size);
	if(!ncchset->sections.exhdr.buffer) {
		fprintf(stderr,"[EXHEADER ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}
	
	ncchset->sections.acexDesc.size = sizeof(access_descriptor);
	ncchset->sections.acexDesc.buffer = calloc(1,ncchset->sections.acexDesc.size);
	if(!ncchset->sections.acexDesc.buffer) {
		fprintf(stderr,"[EXHEADER ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}
	
	/* Import ExHeader Code Section template */
	if(ncchset->componentFilePtrs.exhdrSize){ 
		u32 import_size = 0x30; //min_u64(0x30,ncchset->componentFilePtrs.exhdrSize);
		u32 import_offset = 0x10;
		if((import_size+import_offset) > ncchset->componentFilePtrs.exhdrSize){
			fprintf(stderr,"[EXHEADER ERROR] Exheader Template is too small\n");
			return FAILED_TO_IMPORT_FILE;
		}
		ReadFile_64((ncchset->sections.exhdr.buffer+import_offset),import_size,import_offset,ncchset->componentFilePtrs.exhdr);
	}

	/* Create ExHeader Struct for output */
	exhdrset->exHdr = (extended_hdr*)ncchset->sections.exhdr.buffer;
	exhdrset->acexDesc = (access_descriptor*)ncchset->sections.acexDesc.buffer;

	/* Set Code Info if Code Section was built not imported */
	if(ncchset->options.IsBuildingCodeSection){
		/* BSS Size */
		u32_to_u8(exhdrset->exHdr->codeSetInfo.bssSize,ncchset->codeDetails.bssSize,LE);
		/* Data */
		u32_to_u8(exhdrset->exHdr->codeSetInfo.dataSectionInfo.address,ncchset->codeDetails.rwAddress,LE);
		u32_to_u8(exhdrset->exHdr->codeSetInfo.dataSectionInfo.codeSize,ncchset->codeDetails.rwSize,LE);
		u32_to_u8(exhdrset->exHdr->codeSetInfo.dataSectionInfo.numMaxPages,ncchset->codeDetails.rwMaxPages,LE);
		/* RO */
		u32_to_u8(exhdrset->exHdr->codeSetInfo.readOnlySectionInfo.address,ncchset->codeDetails.roAddress,LE);
		u32_to_u8(exhdrset->exHdr->codeSetInfo.readOnlySectionInfo.codeSize,ncchset->codeDetails.roSize,LE);
		u32_to_u8(exhdrset->exHdr->codeSetInfo.readOnlySectionInfo.numMaxPages,ncchset->codeDetails.roMaxPages,LE);
		/* Text */
		u32_to_u8(exhdrset->exHdr->codeSetInfo.textSectionInfo.address,ncchset->codeDetails.textAddress,LE);
		u32_to_u8(exhdrset->exHdr->codeSetInfo.textSectionInfo.codeSize,ncchset->codeDetails.textSize,LE);
		u32_to_u8(exhdrset->exHdr->codeSetInfo.textSectionInfo.numMaxPages,ncchset->codeDetails.textMaxPages,LE);
	}

	/* Set Simple Flags */
	if(ncchset->options.CompressCode)
		exhdrset->exHdr->codeSetInfo.flag |= infoflag_COMPRESS_EXEFS_0;
	if(ncchset->options.UseOnSD)
		exhdrset->exHdr->codeSetInfo.flag |= infoflag_SD_APPLICATION;
	if(!ncchset->options.UseRomFS) // Move this later
		exhdrset->exHdr->arm11SystemLocalCapabilities.storageInfo.otherAttributes |= attribute_NOT_USE_ROMFS;

	return 0;
}

int get_ExHeaderSettingsFromRsf(exheader_settings *exhdrset)
{
	int result = 0;
	result = get_ExHeaderCodeSetInfo(&exhdrset->exHdr->codeSetInfo, exhdrset->rsf);
	if(result) goto finish;

	if(!exhdrset->useAccessDescPreset){
		result = get_ExHeaderDependencyList((u8*)&exhdrset->exHdr->dependencyList[0], exhdrset->rsf);
		if(result) goto finish;
	}

	result = get_ExHeaderSystemInfo(&exhdrset->exHdr->systemInfo, exhdrset->rsf);
	if(result) goto finish;

	result = get_ExHeaderARM11SystemLocalInfo(&exhdrset->exHdr->arm11SystemLocalCapabilities, exhdrset->rsf, exhdrset->useAccessDescPreset);
	if(result) goto finish;

	if(!exhdrset->useAccessDescPreset){
		result = get_ExHeaderARM11KernelInfo(&exhdrset->exHdr->arm11KernelCapabilities, exhdrset->rsf);
		if(result) goto finish;
	}
	result = get_ExHeaderARM9AccessControlInfo(&exhdrset->exHdr->arm9AccessControlInfo, exhdrset->rsf);
		if(result) goto finish;

finish:
	return result;
}

int get_ExHeaderCodeSetInfo(exhdr_CodeSetInfo *CodeSetInfo, rsf_settings *rsf)
{
	/* Name */
	if(rsf->BasicInfo.Title){
		//if(strlen(rsf->BasicInfo.Title) > 8){
		//	fprintf(stderr,"[EXHEADER ERROR] Parameter Too Long \"BasicInfo/Title\"\n");
		//	return EXHDR_BAD_YAML_OPT;
		//}
		strncpy((char*)CodeSetInfo->name,rsf->BasicInfo.Title,8);
	}
	else{
		ErrorParamNotFound("BasicInfo/Title");
		return EXHDR_BAD_YAML_OPT;
	}
	/* Stack Size */
	if(rsf->SystemControlInfo.StackSize){
		u32 StackSize = strtoul(rsf->SystemControlInfo.StackSize,NULL,0);
		u32_to_u8(CodeSetInfo->stackSize,StackSize,LE);
	}
	else{
		ErrorParamNotFound("SystemControlInfo/StackSize");
		return EXHDR_BAD_YAML_OPT;
	}
	/* Remaster Version */
	if(rsf->SystemControlInfo.RemasterVersion){
		u16 RemasterVersion = strtol(rsf->SystemControlInfo.RemasterVersion,NULL,0);
		u16_to_u8(CodeSetInfo->remasterVersion,RemasterVersion,LE);
	}
	else{
		u16_to_u8(CodeSetInfo->remasterVersion,0,LE);
	}
	return 0;
}

int get_ExHeaderDependencyList(u8 *DependencyList, rsf_settings *rsf)
{
	if(rsf->SystemControlInfo.DependencyNum > 0x30){
		fprintf(stderr,"[EXHEADER ERROR] Too Many Dependency IDs\n");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < rsf->SystemControlInfo.DependencyNum; i++){
		u8 *pos = (DependencyList + 0x8*i);
		u64 TitleID = strtoull(rsf->SystemControlInfo.Dependency[i],NULL,0);
		u64_to_u8(pos,TitleID,LE);
	}
	return 0;
}

int get_ExHeaderSystemInfo(exhdr_SystemInfo *SystemInfo, rsf_settings *rsf)
{
	/* SaveDataSize */
	if(rsf->SystemControlInfo.SaveDataSize){
		u64 SaveDataSize = 0;
		int ret = GetSaveDataSizeFromString(&SaveDataSize,rsf->SystemControlInfo.SaveDataSize,"EXHEADER");
		if(ret) return ret;
		u64_to_u8(SystemInfo->savedataSize,SaveDataSize,LE);
	}
	else{
		u64_to_u8(SystemInfo->savedataSize,0,LE);
	}
	/* Jump Id */
	if(rsf->SystemControlInfo.JumpId){
		u64 JumpId = strtoull(rsf->SystemControlInfo.JumpId,NULL,0);
		u64_to_u8(SystemInfo->jumpId,JumpId,LE);
	}
	else{
		u64 JumpId = 0;
		int result = GetProgramID(&JumpId,rsf,false); 
		if(result) return result;
		u64_to_u8(SystemInfo->jumpId,JumpId,LE);
	}
	return 0;
}

int get_ExHeaderARM11SystemLocalInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf, bool useAccessDescPreset)
{
	/* Program Id */
	u64 ProgramId = 0;
	int result = GetProgramID(&ProgramId,rsf,true); 
	if(result) return result;
	u64_to_u8(arm11->programId,ProgramId,LE);
	
	if(!useAccessDescPreset){
		/* Flags */
		result = SetARM11SystemLocalInfoFlags(arm11, rsf);
		if(result) return result;

		/* Resource Limit Descriptors */
		result = SetARM11ResLimitDesc(arm11, rsf);
		if(result) return result;
	}

	/* Storage Info */
	result = SetARM11StorageInfo(arm11, rsf);
	if(result) return result;

	if(!useAccessDescPreset){
		/* Service Access Control */
		result = SetARM11ServiceAccessControl(arm11, rsf);
		if(result) return result;

		/* Resource Limit Category */
		if(rsf->AccessControlInfo.ResourceLimitCategory){
			if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"application") == 0) arm11->resourceLimitCategory = resrc_limit_APPLICATION;
			else if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"sysapplet") == 0) arm11->resourceLimitCategory = resrc_limit_SYS_APPLET;
			else if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"libapplet") == 0) arm11->resourceLimitCategory = resrc_limit_LIB_APPLET;
			else if(strcasecmp(rsf->AccessControlInfo.ResourceLimitCategory,"other") == 0) arm11->resourceLimitCategory = resrc_limit_OTHER;
		}
	}
	/* Finish */
	return 0;
}

int SetARM11SystemLocalInfoFlags(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	/* Core Version */
	if(rsf->AccessControlInfo.CoreVersion){
		u32 Version = strtoul(rsf->AccessControlInfo.CoreVersion,NULL,0);
		u32_to_u8(arm11->coreVersion,Version,LE);
	}
	else{
		ErrorParamNotFound("AccessControlInfo/CoreVersion");
		return EXHDR_BAD_YAML_OPT;
	}

	/* Flag */
	u8 AffinityMask = 0;
	u8 IdealProcessor = 0;
	u8 SystemMode = 0;
	if(rsf->AccessControlInfo.AffinityMask){
		AffinityMask = strtol(rsf->AccessControlInfo.AffinityMask,NULL,0);
		if(AffinityMask > 1){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected AffinityMask: %d. Expected range: 0x0 - 0x1\n",AffinityMask);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	if(rsf->AccessControlInfo.IdealProcessor){
		IdealProcessor = strtol(rsf->AccessControlInfo.IdealProcessor,NULL,0);
		if(IdealProcessor > 1){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected IdealProcessor: %d. Expected range: 0x0 - 0x1\n",IdealProcessor);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	if(rsf->AccessControlInfo.SystemMode){
		SystemMode = strtol(rsf->AccessControlInfo.SystemMode,NULL,0);
		if(SystemMode > 15){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected SystemMode: 0x%x. Expected range: 0x0 - 0xf\n",SystemMode);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	arm11->flag = (u8)(SystemMode << 4 | AffinityMask << 2 | IdealProcessor);

	/* Thread Priority */
	if(rsf->AccessControlInfo.Priority){
		u8 Priority = strtoul(rsf->AccessControlInfo.Priority,NULL,0);
		int ProccessType = 0;
		GetAppType(&ProccessType,rsf);
		if(ProccessType == processtype_APPLICATION || ProccessType == processtype_DEFAULT){
			Priority += 32;
		}
		if(Priority > 127){
			fprintf(stderr,"[EXHEADER ERROR] Invalid Priority: %d\n",Priority);
			return EXHDR_BAD_YAML_OPT;
		}
		arm11->priority = Priority;
	}
	else{
		ErrorParamNotFound("AccessControlInfo/Priority");
		return EXHDR_BAD_YAML_OPT;
	}

	return 0;
}

int GetAppType(int *AppType, rsf_settings *rsf)
{
	*AppType = processtype_DEFAULT;
	if(rsf->SystemControlInfo.AppType){
		if(strcasecmp(rsf->SystemControlInfo.AppType,"application") == 0) *AppType = processtype_APPLICATION;
		else if(strcasecmp(rsf->SystemControlInfo.AppType,"system") == 0) *AppType = processtype_SYSTEM;
	}
	return 0;
}

int SetARM11ResLimitDesc(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	for(int i = 0; i < 16; i++){
		if(i == 0){
			/* MaxCpu */
			// N's makerom actually reads this from the pre-made accessdesc. Damn cheaters. But we can improvise
			if(rsf->AccessControlInfo.MaxCpu){
				arm11->resourceLimitDescriptor[i][0] = strtol(rsf->AccessControlInfo.MaxCpu,NULL,0);
			}
		}
	}
	
	return 0;
}

int SetARM11StorageInfo(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.UseExtendedSaveDataAccessControl || rsf->AccessControlInfo.AccessibleSaveDataIds){
		/* Accessible SaveData IDs */
		if(!CheckCondiditionsForNewAccessibleSaveDataIds(rsf))
			return EXHDR_BAD_YAML_OPT;
		SetARM11StorageInfoAccessibleSaveDataIds(arm11,rsf);
	}
	else{
		/* Extdata Id */
		int ret = SetARM11StorageInfoExtSaveDataId(arm11,rsf);
		if(ret) return ret;
		/* OtherUserSaveData */
		SetARM11StorageInfoOtherUserSaveData(arm11,rsf);
	}

	/* System Savedata Id */
	SetARM11StorageInfoSystemSaveDataId(arm11,rsf);	

	/* FileSystem Access Info */
	u32 AccessInfo = 0;
	for(int i = 0; i < rsf->AccessControlInfo.FileSystemAccessNum; i++){
		if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategorySystemApplication") == 0)
			AccessInfo |= fsaccess_CATEGORY_SYSTEM_APPLICATION;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategoryHardwareCheck") == 0)
			AccessInfo |= fsaccess_CATEGORY_HARDWARE_CHECK;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategoryFileSystemTool") == 0)
			AccessInfo |= fsaccess_CATEGORY_FILE_SYSTEM_TOOL;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Debug") == 0)
			AccessInfo |= fsaccess_DEBUG;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"TwlCardBackup") == 0)
			AccessInfo |= fsaccess_TWL_CARD_BACKUP;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"TwlNandData") == 0)
			AccessInfo |= fsaccess_TWL_NAND_DATA;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Boss") == 0)
			AccessInfo |= fsaccess_BOSS;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"DirectSdmc") == 0)
			AccessInfo |= fsaccess_DIRECT_SDMC;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Core") == 0)
			AccessInfo |= fsaccess_CORE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CtrNandRo") == 0)
			AccessInfo |= fsaccess_CTR_NAND_RO;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CtrNandRw") == 0)
			AccessInfo |= fsaccess_CTR_NAND_RW;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CtrNandRoWrite") == 0)
			AccessInfo |= fsaccess_CTR_NAND_RO_WRITE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategorySystemSettings") == 0)
			AccessInfo |= fsaccess_CATEGORY_SYSTEM_SETTINGS;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CardBoard") == 0)
			AccessInfo |= fsaccess_CARD_BOARD;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"ExportImportIvs") == 0)
			AccessInfo |= fsaccess_EXPORT_IMPORT_IVS;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"DirectSdmcWrite") == 0)
			AccessInfo |= fsaccess_DIRECT_SDMC_WRITE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"SwitchCleanup") == 0)
			AccessInfo |= fsaccess_SWITCH_CLEANUP;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"SaveDataMove") == 0)
			AccessInfo |= fsaccess_SAVE_DATA_MOVE;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Shop") == 0)
			AccessInfo |= fsaccess_SHOP;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"Shell") == 0)
			AccessInfo |= fsaccess_SHELL;
		else if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"CategoryHomeMenu") == 0)
			AccessInfo |= fsaccess_CATEGORY_HOME_MENU;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid FileSystemAccess Name: \"%s\"\n",rsf->AccessControlInfo.FileSystemAccess[i]);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	u32_to_u8(arm11->storageInfo.accessInfo,AccessInfo,LE);
	return 0;
}

int SetARM11StorageInfoSystemSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.SystemSaveDataId1){
		u32 SaveId = strtoul(rsf->AccessControlInfo.SystemSaveDataId1,NULL,0);
		u32_to_u8(arm11->storageInfo.systemSavedataId,SaveId,LE);
	}
	if(rsf->AccessControlInfo.SystemSaveDataId2){
		u32 SaveId = strtoul(rsf->AccessControlInfo.SystemSaveDataId2,NULL,0);
		u32_to_u8(&arm11->storageInfo.systemSavedataId[4],SaveId,LE);
	}
	return 0;
}

int SetARM11StorageInfoExtSaveDataId(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.ExtSaveDataId){
		if(!rsf->AccessControlInfo.UseExtSaveData){
			fprintf(stderr,"[EXHEADER ERROR] Failed to set ExtSaveDataId. UseExtSaveData must be true.\n");
			return EXHDR_BAD_YAML_OPT;
		}
		u64 ExtdataId = strtoull(rsf->AccessControlInfo.ExtSaveDataId,NULL,0);
		u64_to_u8(arm11->storageInfo.extSavedataId,ExtdataId,LE);
	}
	return 0;
}

int SetARM11StorageInfoOtherUserSaveData(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	u64 Value = 0; 
	if(rsf->AccessControlInfo.OtherUserSaveDataId1)
		Value = 0xffffff & strtoul(rsf->AccessControlInfo.OtherUserSaveDataId1,NULL,0);
	Value = Value << 20;
	if(rsf->AccessControlInfo.OtherUserSaveDataId2)
		Value |= 0xffffff & strtoul(rsf->AccessControlInfo.OtherUserSaveDataId2,NULL,0);
	Value = Value << 20;
	if(rsf->AccessControlInfo.OtherUserSaveDataId3)
		Value |= 0xffffff & strtoul(rsf->AccessControlInfo.OtherUserSaveDataId3,NULL,0);

	/* UseOtherVariationSaveData Flag */
	if(rsf->AccessControlInfo.UseOtherVariationSaveData)
		Value |= 0x1000000000000000;
	
	u64_to_u8(arm11->storageInfo.storageAccessableUniqueIds,Value,LE);
	return 0;
}

bool CheckCondiditionsForNewAccessibleSaveDataIds(rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.UseExtendedSaveDataAccessControl){
		if(rsf->AccessControlInfo.AccessibleSaveDataIds)
			fprintf(stderr,"[EXHEADER ERROR] AccessibleSaveDataIds is unavailable if UseExtendedSaveDataAccessControl is false.\n");
		return false;
	}

	/*
	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum == 0){
		fprintf(stderr,"[EXHEADER ERROR] AccessibleSaveDataIds must be specified if UseExtendedSaveDataAccessControl is true.\n");
		return false;
	}
	*/

	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum > 6){
		fprintf(stderr,"[EXHEADER ERROR] Too many UniqueId in \"AccessibleSaveDataIds\".\n");
		return false;
	}

	if(rsf->AccessControlInfo.UseExtSaveData){
		fprintf(stderr,"[EXHEADER ERROR] UseExtSaveData must be false if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (rsf->AccessControlInfo.ExtSaveDataId){
		fprintf(stderr,"[EXHEADER ERROR] ExtSaveDataId is unavailable if AccessibleSaveDataIds is specified.\n");
		return false;
	}
	if (rsf->AccessControlInfo.OtherUserSaveDataId1){
		if(strtoul(rsf->AccessControlInfo.OtherUserSaveDataId1,NULL,0) > 0){
			fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId1 must be 0 if AccessibleSaveDataIds is specified.\n");
			return false;
		}
	}
	if (rsf->AccessControlInfo.OtherUserSaveDataId2){
		if(strtoul(rsf->AccessControlInfo.OtherUserSaveDataId2,NULL,0) > 0){
			fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId2 must be 0 if AccessibleSaveDataIds is specified.\n");
			return false;
		}
	}
	if (rsf->AccessControlInfo.OtherUserSaveDataId3){
		if(strtoul(rsf->AccessControlInfo.OtherUserSaveDataId3,NULL,0) > 0){
			fprintf(stderr,"[EXHEADER ERROR] OtherUserSaveDataId3 must be 0 if AccessibleSaveDataIds is specified.\n");
			return false;
		}
	}
	return true;
}

int SetARM11StorageInfoAccessibleSaveDataIds(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	u64 RegionExtSaveDataId = 0;
	u64 RegionOtherUseSaveData = 0;

	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum > 0){
		u32 Max = rsf->AccessControlInfo.AccessibleSaveDataIdsNum < 3 ? rsf->AccessControlInfo.AccessibleSaveDataIdsNum : 3;
		for(int i = 0; i < Max; i++){
			u32 UniqueID = 0xffffff & strtoul(rsf->AccessControlInfo.AccessibleSaveDataIds[i],NULL,0);
			RegionOtherUseSaveData = RegionOtherUseSaveData << 20;
			RegionOtherUseSaveData |= UniqueID;
		}
	}
	if(rsf->AccessControlInfo.AccessibleSaveDataIdsNum > 3){
		for(int i = 3; i < rsf->AccessControlInfo.AccessibleSaveDataIdsNum; i++){
			u32 UniqueID = 0xffffff & strtoul(rsf->AccessControlInfo.AccessibleSaveDataIds[i],NULL,0);
			RegionExtSaveDataId = RegionExtSaveDataId << 20;
			RegionExtSaveDataId |= UniqueID;
		}
	}

	arm11->storageInfo.otherAttributes |= attribute_USE_EXTENDED_SAVEDATA_ACCESS_CONTROL;

	/* UseOtherVariationSaveData Flag */
	if(rsf->AccessControlInfo.UseOtherVariationSaveData)
		RegionOtherUseSaveData |= 0x1000000000000000;

	u64_to_u8(arm11->storageInfo.extSavedataId,RegionExtSaveDataId,LE);
	u64_to_u8(arm11->storageInfo.storageAccessableUniqueIds,RegionOtherUseSaveData,LE);
	return 0;
}

int SetARM11ServiceAccessControl(exhdr_ARM11SystemLocalCapabilities *arm11, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.ServiceAccessControl){
		if(rsf->AccessControlInfo.ServiceAccessControlNum > 32){
			fprintf(stderr,"[EXHEADER ERROR] Too Many Service Names, maximum is 32\n");
			return EXHDR_BAD_YAML_OPT;
		}
		for(int i = 0; i < rsf->AccessControlInfo.ServiceAccessControlNum; i++){
			int svc_handle_len = strlen(rsf->AccessControlInfo.ServiceAccessControl[i]);
			if(svc_handle_len > 8){
				fprintf(stderr,"[EXHEADER ERROR] Service Name: \"%s\" is too long\n",rsf->AccessControlInfo.ServiceAccessControl[i]);
				return EXHDR_BAD_YAML_OPT;
			}
			memcpy(arm11->serviceAccessControl[i],rsf->AccessControlInfo.ServiceAccessControl[i],svc_handle_len);
		}
	}
	else{
		ErrorParamNotFound("AccessControlInfo/ServiceAccessControl");
		return EXHDR_BAD_YAML_OPT;
	}
	return 0;
}

int get_ExHeaderARM11KernelInfo(exhdr_ARM11KernelCapabilities *arm11, rsf_settings *rsf)
{
	int result = 0;
	ARM11KernelCapabilityDescriptor desc[6];
	memset(&desc,0,sizeof(ARM11KernelCapabilityDescriptor)*6);

	/* Get Descriptors */
	result = SetARM11KernelDescSysCallControl(&desc[0],rsf);
	if(result) goto finish;
	result = SetARM11KernelDescInteruptNumList(&desc[1],rsf);
	if(result) goto finish;
	result = SetARM11KernelDescAddressMapping(&desc[2],rsf);
	if(result) goto finish;
	result = SetARM11KernelDescOtherCapabilities(&desc[3],rsf);
	if(result) goto finish;
	result = SetARM11KernelDescHandleTableSize(&desc[4],rsf);
	if(result) goto finish;
	result = SetARM11KernelDescReleaseKernelVersion(&desc[5],rsf);

	/* Write Descriptors To Exheader */
	u16 TotalDesc = 0;
	for(int i = 0; i < 6; i++){
		TotalDesc += desc[i].num;
	}
	if(TotalDesc >= 28){
		fprintf(stderr,"[EXHEADER ERROR] Too many Kernel Capabilities.\n");
		result = EXHDR_BAD_YAML_OPT;
		goto finish;
	}
	u16 DescIndex = 0;
	for(int i = 0; i < 6; i++){
		for(int j = 0; j < desc[i].num; j++){
			u32_to_u8(arm11->descriptors[DescIndex],desc[i].Data[j],LE);
			DescIndex++;
		}
	}

	/* Fill Remaining Descriptors with 0xffffffff */ 
	for(int i = DescIndex; i < 28; i++){
		u32_to_u8(arm11->descriptors[i],0xffffffff,LE);
	}

finish:
	for(int i = 0; i < 6; i++){
		free(desc[i].Data);
	}
	return result;
}

int SetARM11KernelDescSysCallControl(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	int ret = 0;

	// Create Temporary Descriptor
	ARM11KernelCapabilityDescriptor tmp;
	memset(&tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	AllocateARM11KernelDescMemory(&tmp,8);
	for(int i = 0; i < 8; i++)
		SetARM11KernelDescValue(&tmp,i,desc_SysCallControl | (i << 24));

	// Get SysCalls
	ret = GetARM11SysCalls(&tmp,rsf);
	if(ret) goto finish;

	// Count Active Syscall Descs
	u16 ActiveSysCallDesc = 0;
	for(int i = 0; i < 8; i++)
		if((tmp.Data[i] & 0x00ffffff) != 0) 
			ActiveSysCallDesc++;
	
	// Transfer Active Syscall Descs to out Descriptor
	AllocateARM11KernelDescMemory(desc,ActiveSysCallDesc);
	u16 SysCallDescPos = 0;
	for(int i = 0; i < 8; i++){
		if((tmp.Data[i] & 0x00ffffff) != 0) {
			SetARM11KernelDescValue(desc,SysCallDescPos,tmp.Data[i]);
			SysCallDescPos++;
		}
	}

finish:
	// Free data in Temporary Descriptor
	free(tmp.Data);
	return ret;
}

int GetARM11SysCalls(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.SystemCallAccess){
		ErrorParamNotFound("AccessControlInfo/SystemCallAccess");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < rsf->AccessControlInfo.SystemCallAccessNum; i++){
		int SysCall = strtoul(rsf->AccessControlInfo.SystemCallAccess[i],NULL,0);
		if(SysCall > 184){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected Syscall: 0x%02x. Expected Range: 0x00 - 0xB8\n",SysCall);
			return EXHDR_BAD_YAML_OPT;
		}
		EnableSystemCall(desc,SysCall);
	}

	return 0;
}

void EnableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall)
{
	int num = SysCall / 24;
	int num1 = SysCall % 24;
	desc->Data[num] |= 1 << (num1 & 31);
}

void DisableSystemCall(ARM11KernelCapabilityDescriptor *desc, int SysCall)
{
	int num = SysCall / 24;
	int num1 = SysCall % 24;
	desc->Data[num] = desc->Data[num] & ~(1 << (num1 & 31));
}

int SetARM11KernelDescInteruptNumList(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{	
	int ret = 0;

	// Create Temporary Descriptor
	ARM11KernelCapabilityDescriptor tmp;
	memset(&tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	AllocateARM11KernelDescMemory(&tmp,8);

	// Get Interupts
	ret = GetARM11Interupts(&tmp,rsf);
	if(ret) goto finish;

	// Count Active Interupt Descs
	u16 ActiveInteruptDesc = 0;
	for(int i = 0; i < 8; i++)
		if(tmp.Data[i]) 
			ActiveInteruptDesc++;
	
	// Transfer Active Interupt Descs to output Descriptor
	AllocateARM11KernelDescMemory(desc,ActiveInteruptDesc);
	u16 InteruptDescPos = 0;
	for(int i = 0; i < 8; i++){
		if(tmp.Data[i]) {
			SetARM11KernelDescValue(desc,InteruptDescPos,(tmp.Data[i] & 0x0fffffff) | desc_InteruptNumList);
			InteruptDescPos++;
		}
	}

finish:
	// Free data in Temporary Descriptor
	free(tmp.Data);
	return ret;
}

int GetARM11Interupts(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.InterruptNumbers){
		return 0;
	}
	if(rsf->AccessControlInfo.InterruptNumbersNum > 32){
		fprintf(stderr,"[EXHEADER ERROR] Too many Interupts. Maximum is 32\n");
		return EXHDR_BAD_YAML_OPT;
	}
	for(int i = 0; i < rsf->AccessControlInfo.InterruptNumbersNum; i++){
		int Interrupt = strtoul(rsf->AccessControlInfo.InterruptNumbers[i],NULL,0);
		if(Interrupt > 0x7f){
			fprintf(stderr,"[EXHEADER ERROR] Unexpected Interupt: 0x%02x. Expected Range: 0x00 - 0x7f\n",Interrupt);
			return EXHDR_BAD_YAML_OPT;
		}
		EnableInterupt(desc,Interrupt,i);
	}

	return 0;
}

void EnableInterupt(ARM11KernelCapabilityDescriptor *desc, int Interrupt, int i)
{
	int num = i / 4;
	if(num*4 == i) desc->Data[num] |= 0xffffffff;
	desc->Data[num] = desc->Data[num] << 7;
	desc->Data[num] |= Interrupt;
}

int SetARM11KernelDescAddressMapping(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	int ret = 0;
	// Create Temporary Descriptors
	ARM11KernelCapabilityDescriptor io_tmp;
	memset(&io_tmp,0,sizeof(ARM11KernelCapabilityDescriptor));
	ARM11KernelCapabilityDescriptor static_tmp;
	memset(&static_tmp,0,sizeof(ARM11KernelCapabilityDescriptor));

	// Getting IO Mapping
	ret = GetARM11IOMappings(&io_tmp,rsf);
	if(ret) goto finish;

	// Getting Static Mapping
	ret = GetARM11StaticMappings(&static_tmp,rsf);
	if(ret) goto finish;


	// Creating Output Descriptor and Combining the two MemMap Descriptors
	AllocateARM11KernelDescMemory(desc,io_tmp.num+static_tmp.num);
	u16 MemMapDescPos = 0;
	for(int i = 0; i < io_tmp.num; i++){
		SetARM11KernelDescValue(desc,MemMapDescPos,io_tmp.Data[i]);
		MemMapDescPos++;
	}
	for(int i = 0; i < static_tmp.num; i++){
		SetARM11KernelDescValue(desc,MemMapDescPos,static_tmp.Data[i]);
		MemMapDescPos++;
	}

finish:
	free(io_tmp.Data);
	free(static_tmp.Data);
	return ret;
}

int GetARM11IOMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.IORegisterMapping)
		return 0;

	AllocateARM11KernelDescMemory(desc,rsf->AccessControlInfo.IORegisterMappingNum*2);
	u16 DescUsed = 0;
	for(int i = 0; i < rsf->AccessControlInfo.IORegisterMappingNum; i++){
		if(strlen(rsf->AccessControlInfo.IORegisterMapping[i])){
			// Parse Address String
			char *AddressStartStr = rsf->AccessControlInfo.IORegisterMapping[i];
			char *AddressEndStr = strstr(AddressStartStr,"-");
			if(AddressEndStr){
				if(strlen(AddressEndStr) > 1) // if not just '-'
					AddressEndStr = (AddressEndStr+1); // Setting the str to the expected start of address string
				else 
					AddressEndStr = NULL;
			}


			u32 AddressStart = strtoul(AddressStartStr,NULL,16);
			if(!IsStartAddress(AddressStart)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x is not valid mapping start address.\n",AddressStart);
				return EXHDR_BAD_YAML_OPT;
			}
			if(!AddressEndStr){ // No End Addr Was Specified
				SetARM11KernelDescValue(desc,DescUsed,GetIOMappingDesc(AddressStart));
				DescUsed++;
				goto skip;
			}

			u32 AddressEnd = strtoul(AddressEndStr,NULL,16);
			if(!IsEndAddress(AddressEnd)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x is not valid mapping end address.\n",AddressEnd);
				return EXHDR_BAD_YAML_OPT;
			}

			u32 DescStartAddr = GetStaticMappingDesc(AddressStart,false);
			u32 DescEndAddr = GetStaticMappingDesc(AddressEnd+0x1000,false);
			if(DescStartAddr != DescEndAddr){
				SetARM11KernelDescValue(desc,DescUsed,DescStartAddr);
				SetARM11KernelDescValue(desc,DescUsed+1,DescEndAddr);
				DescUsed += 2;
				goto skip;
			}
			else{
				SetARM11KernelDescValue(desc,DescUsed,GetIOMappingDesc(AddressStart));
				DescUsed++;
				goto skip;
			}
		}

		skip: ;
	}
	desc->num = DescUsed;
	return 0;
}

int GetARM11StaticMappings(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(!rsf->AccessControlInfo.MemoryMapping)
		return 0;

	AllocateARM11KernelDescMemory(desc,rsf->AccessControlInfo.MemoryMappingNum*2);
	u16 DescUsed = 0;
	for(int i = 0; i < rsf->AccessControlInfo.MemoryMappingNum; i++){
		if(strlen(rsf->AccessControlInfo.MemoryMapping[i])){
			char *AddressStartStr = rsf->AccessControlInfo.MemoryMapping[i];
			char *AddressEndStr = strstr(AddressStartStr,"-");
			char *ROFlagStr = strstr(AddressStartStr,":");
			bool IsRO = false; 
			if(ROFlagStr)
				IsRO = strcasecmp(ROFlagStr,":r") == 0 ? true : false;

			if(AddressEndStr){
				if(strlen(AddressEndStr) > 1) {
					AddressEndStr = (AddressEndStr+1);
					if(AddressEndStr == ROFlagStr)
						AddressEndStr = NULL;
				}
				else 
					AddressEndStr = NULL;
			}
			u32 AddressStart = strtoul(AddressStartStr,NULL,16);
			if(!IsStartAddress(AddressStart)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x (%s) is not valid mapping start address.\n",AddressStart,AddressStartStr);
				return EXHDR_BAD_YAML_OPT;
			}
			if(!AddressEndStr){ // No End Addr Was Specified
				SetARM11KernelDescValue(desc,DescUsed,GetStaticMappingDesc(AddressStart,IsRO));
				SetARM11KernelDescValue(desc,DescUsed+1,GetStaticMappingDesc(AddressStart+0x1000, true));
				DescUsed += 2;
				goto skip;
			}

			u32 AddressEnd = strtoul(AddressEndStr,NULL,16);
			if(!IsEndAddress(AddressEnd)){
				fprintf(stderr,"[EXHEADER ERROR] Address 0x%x (%s) is not valid mapping end address.\n",AddressEnd,AddressEndStr);
				return EXHDR_BAD_YAML_OPT;
			}

			u32 DescStartAddr = GetStaticMappingDesc(AddressStart,IsRO);
			u32 DescEndAddr = GetStaticMappingDesc(AddressEnd+0x1000,true);
			if(DescStartAddr != DescEndAddr){
				SetARM11KernelDescValue(desc,DescUsed,DescStartAddr);
				SetARM11KernelDescValue(desc,DescUsed+1,DescEndAddr);
				DescUsed += 2;
				goto skip;
			}
			else{
				SetARM11KernelDescValue(desc,DescUsed,GetStaticMappingDesc(AddressStart,IsRO));
				SetARM11KernelDescValue(desc,DescUsed+1,GetStaticMappingDesc(AddressStart+0x1000, true));
				DescUsed += 2;
				goto skip;
			}
		}

		skip: ;
	}
	desc->num = DescUsed;
	return 0;
}

bool IsEndAddress(u32 Address)
{
	return (Address & 0x0fff) == 0x0fff;
}

bool IsStartAddress(u32 Address)
{
	return (Address & 0x0fff) == 0;
}

u32 GetIOMappingDesc(u32 Address)
{
	return GetMappingDesc(Address,0xFFE,0xC,false);
}

u32 GetStaticMappingDesc(u32 Address, bool IsReadOnly)
{
	return GetMappingDesc(Address,0x7FC,0xB,IsReadOnly);
}

u32 GetMappingDesc(u32 Address, u32 PrefixVal, s32 numPrefixBits, bool IsRO)
{
	u32 PrefixMask = GetDescPrefixMask(numPrefixBits);
	u32 PrefixBits = GetDescPrefixBits(numPrefixBits,PrefixVal);
	u32 Desc = (Address >> 12 & ~PrefixMask) | PrefixBits;
	if (IsRO)
		Desc |= 0x100000;
	return Desc;
}

int SetARM11KernelDescOtherCapabilities(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	u32 OtherCapabilities = 0;
	
	if(!rsf->AccessControlInfo.DisableDebug)
		OtherCapabilities |= othcap_PERMIT_DEBUG;
	if(rsf->AccessControlInfo.EnableForceDebug)
		OtherCapabilities |= othcap_FORCE_DEBUG;
	if(rsf->AccessControlInfo.CanUseNonAlphabetAndNumber)
		OtherCapabilities |= othcap_CAN_USE_NON_ALPHABET_AND_NUMBER;
	if(rsf->AccessControlInfo.CanWriteSharedPage)
		OtherCapabilities |= othcap_CAN_WRITE_SHARED_PAGE;
	if(rsf->AccessControlInfo.CanUsePrivilegedPriority)
		OtherCapabilities |= othcap_CAN_USE_PRIVILEGE_PRIORITY;
	if(rsf->AccessControlInfo.PermitMainFunctionArgument)
		OtherCapabilities |= othcap_PERMIT_MAIN_FUNCTION_ARGUMENT;
	if(rsf->AccessControlInfo.CanShareDeviceMemory)
		OtherCapabilities |= othcap_CAN_SHARE_DEVICE_MEMORY;
	if(rsf->AccessControlInfo.RunnableOnSleep)
		OtherCapabilities |= othcap_RUNNABLE_ON_SLEEP;
	if(rsf->AccessControlInfo.SpecialMemoryArrange)
		OtherCapabilities |= othcap_SPECIAL_MEMORY_ARRANGE;

	if(rsf->AccessControlInfo.MemoryType){
		u32 MemType = 0; 
		if(strcasecmp(rsf->AccessControlInfo.MemoryType,"application") == 0)
			MemType = memtype_APPLICATION;
		else if(strcasecmp(rsf->AccessControlInfo.MemoryType,"system") == 0)
			MemType = memtype_SYSTEM;
		else if(strcasecmp(rsf->AccessControlInfo.MemoryType,"base") == 0)
			MemType = memtype_BASE;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid memory type: \"%s\"\n",rsf->AccessControlInfo.MemoryType);
			return EXHDR_BAD_YAML_OPT;
		}
		OtherCapabilities = (OtherCapabilities & 0xffffff0f) | MemType << 8;
	}

	if(OtherCapabilities){
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_OtherCapabilities);
		SetARM11KernelDescValue(desc,0,OtherCapabilities);
	}
	return 0;
}

int SetARM11KernelDescHandleTableSize(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.HandleTableSize){
		u16 HandleTableSize = strtoul(rsf->AccessControlInfo.HandleTableSize,NULL,0);
		if(HandleTableSize > 1023){
			fprintf(stderr,"[EXHEADER ERROR] Too large handle table size\n");
			return EXHDR_BAD_YAML_OPT;
		}
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_HandleTableSize);
		SetARM11KernelDescValue(desc,0,HandleTableSize);
	}
	else{
		ErrorParamNotFound("AccessControlInfo/HandleTableSize");
		return EXHDR_BAD_YAML_OPT;
	}	
	return 0;
}

int SetARM11KernelDescReleaseKernelVersion(ARM11KernelCapabilityDescriptor *desc, rsf_settings *rsf)
{
	if(rsf->AccessControlInfo.ReleaseKernelMajor && rsf->AccessControlInfo.ReleaseKernelMinor){
		u32 releaseKernelMajor = strtoul(rsf->AccessControlInfo.ReleaseKernelMajor,NULL,0);
		u32 releaseKernelMinor = strtoul(rsf->AccessControlInfo.ReleaseKernelMinor,NULL,0);
		if (releaseKernelMajor > 255 || releaseKernelMinor > 255){
			fprintf(stderr,"[EXHEADER ERROR] Invalid release kernel Version");
		}
		AllocateARM11KernelDescMemory(desc,1);
		SetARM11KernelDescBitmask(desc,desc_KernelReleaseVersion);
		SetARM11KernelDescValue(desc,0,(releaseKernelMajor << 8 | releaseKernelMinor));
	}
	return 0;
}

void SetARM11KernelDescValue(ARM11KernelCapabilityDescriptor *desc, u16 Index, u32 Value)
{
	if(Index >= desc->num) return;
	desc->Data[Index] |= Value; 
}

void SetARM11KernelDescBitmask(ARM11KernelCapabilityDescriptor *desc, u32 Bitmask)
{
	for(int i = 0; i < desc->num; i++)
		SetARM11KernelDescValue(desc,i,Bitmask);
}

void AllocateARM11KernelDescMemory(ARM11KernelCapabilityDescriptor *desc, u16 Num)
{
	if(Num == 0) return;
	desc->num = Num;
	desc->Data = malloc(sizeof(u32)*Num);
	memset(desc->Data,0,sizeof(u32)*Num);
	return;
}

u32 GetDescPrefixMask(int numPrefixBits)
{
	return (u32)(~((1 << (32 - (numPrefixBits & 31))) - 1));
}

u32 GetDescPrefixBits(int numPrefixBits, u32 PrefixVal)
{
	return PrefixVal << (32 - (numPrefixBits & 31));
}

int get_ExHeaderARM9AccessControlInfo(exhdr_ARM9AccessControlInfo *arm9, rsf_settings *rsf)
{
	u32 Arm9AccessControl = 0;
	for(int i = 0; i < rsf->AccessControlInfo.IoAccessControlNum; i++){
		if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountNand") == 0)
			Arm9AccessControl |= arm9cap_FS_MOUNT_NAND;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountNandRoWrite") == 0)
			Arm9AccessControl |= arm9cap_FS_MOUNT_NAND_RO_WRITE;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountTwln") == 0)
			Arm9AccessControl |= arm9cap_FS_MOUNT_TWLN;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountWnand") == 0)
			Arm9AccessControl |= arm9cap_FS_MOUNT_WNAND;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"FsMountCardSpi") == 0)
			Arm9AccessControl |= arm9cap_FS_MOUNT_CARD_SPI;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"UseSdif3") == 0)
			Arm9AccessControl |= arm9cap_USE_SDIF3;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"CreateSeed") == 0)
			Arm9AccessControl |= arm9cap_CREATE_SEED;
		else if(strcmp(rsf->AccessControlInfo.IoAccessControl[i],"UseCardSpi") == 0)
			Arm9AccessControl |= arm9cap_USE_CARD_SPI;
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid IoAccessControl Name: \"%s\"\n",rsf->AccessControlInfo.IoAccessControl[i]);
			return EXHDR_BAD_YAML_OPT;
		}
	}
	
	for(int i = 0; i < rsf->AccessControlInfo.FileSystemAccessNum; i++){
		if(strcmp(rsf->AccessControlInfo.FileSystemAccess[i],"DirectSdmc") == 0)
			Arm9AccessControl |= arm9cap_USE_DIRECT_SDMC;
	}

	if(rsf->Option.UseOnSD)
		Arm9AccessControl |= arm9cap_SD_APPLICATION;

	u32_to_u8(arm9->descriptors,Arm9AccessControl,LE);

	if(rsf->AccessControlInfo.DescVersion){
		arm9->descriptors[15] = strtol(rsf->AccessControlInfo.DescVersion,NULL,0);
	}
	else{
		//ErrorParamNotFound("AccessControlInfo/DescVersion");
		//return EXHDR_BAD_YAML_OPT;
		arm9->descriptors[15] = 2; // Makerom generates a desc version 2 anyway, so if not specified, it will be set to 2
	}

	return 0;
}





/* Generic Exheader Errors */
void ErrorParamNotFound(char *string)
{
	fprintf(stderr,"[EXHEADER ERROR] Parameter Not Found: \"%s\"\n",string);
}

/* ExHeader Binary Print Functions */
void exhdr_Print_ServiceAccessControl(extended_hdr *hdr)
{
	printf("[+] Service Access Control\n");
	for(int i = 0; i < 32; i ++){
		char *SVC_Handle = (char*)hdr->arm11SystemLocalCapabilities.serviceAccessControl[i];
		if(SVC_Handle[0] == 0) break;
		printf("%.8s\n",hdr->arm11SystemLocalCapabilities.serviceAccessControl[i]);
	}
}

/* ExHeader Binary Read Functions */
u8* GetAcexRsaSig(access_descriptor *acexDesc)
{
	return acexDesc->signature ;
}

u8* GetAcexNcchPubKey(access_descriptor *acexDesc)
{
	return acexDesc->ncchRsaPubKey;
}

u16 GetRemasterVersion_frm_exhdr(extended_hdr *hdr)
{
	return u8_to_u16(hdr->codeSetInfo.remasterVersion,LE);
}

u64 GetSaveDataSize_frm_exhdr(extended_hdr *hdr)
{
	return u8_to_u64(hdr->systemInfo.savedataSize,LE);
}

void GetCoreVersion_frm_exhdr(u8 *Dest, extended_hdr *hdr)
{
	memcpy(Dest,hdr->arm11SystemLocalCapabilities.coreVersion,4);
}

int GetDependencyList_frm_exhdr(u8 *Dest, extended_hdr *hdr)
{
	if(!Dest) return -1;
	memcpy(Dest,hdr->dependencyList,0x30*8);
	
	return 0;
}

/* ExHeader Settings Read from RSF */
int GetSaveDataSizeFromString(u64 *out, char *string, char *moduleName)
{
	if(!string){
		*out = 0;
		return 0;
	}

	u64 SaveDataSize = strtoull(string,NULL,10);

	if(strstr(string,"K")){
		char *str = strstr(string,"K");
		if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
			SaveDataSize *= KB;
		}
	}
	else if(strstr(string,"M")){
		char *str = strstr(string,"M");
		if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
			SaveDataSize *= MB;
		}
	}
	else if(strstr(string,"G")){
		char *str = strstr(string,"G");
		if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
			SaveDataSize *= GB;
		}
	}
	else{
		if(moduleName)
			fprintf(stderr,"[%s ERROR] Invalid save data size format.\n",moduleName);
		else
			fprintf(stderr,"[ERROR] Invalid save data size format.\n");
		return EXHDR_BAD_YAML_OPT;
	}
	if((SaveDataSize & 65536) != 0){
		if(moduleName)
			fprintf(stderr,"[%s ERROR] Save data size must be aligned to 64K.\n",moduleName);
		else
			fprintf(stderr,"[ERROR] Save data size must be aligned to 64K.\n");
		return EXHDR_BAD_YAML_OPT;
	}
	*out = SaveDataSize;
	return 0;
}

int GetSaveDataSize_rsf(u64 *SaveDataSize, user_settings *usrset)
{	

	if(usrset->common.rsfSet.SystemControlInfo.SaveDataSize){
		*SaveDataSize = strtoull(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,NULL,10);
		if(strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"K")){
			char *str = strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"K");
			if(strcmp(str,"K") == 0 || strcmp(str,"KB") == 0 ){
				*SaveDataSize = *SaveDataSize*KB;
			}
		}
		else if(strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"M")){
			char *str = strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"M");
			if(strcmp(str,"M") == 0 || strcmp(str,"MB") == 0 ){
				*SaveDataSize = *SaveDataSize*MB;
			}
		}
		else if(strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"G")){
			char *str = strstr(usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"G");
			if(strcmp(str,"G") == 0 || strcmp(str,"GB") == 0 ){
				*SaveDataSize = *SaveDataSize*GB;
			}
		}
		else{
			fprintf(stderr,"[EXHEADER ERROR] Invalid save data size format.\n");
			return EXHDR_BAD_YAML_OPT;
		}
		if((*SaveDataSize & 65536) != 0){
			fprintf(stderr,"[EXHEADER ERROR] Save data size must be aligned to 64K.\n");
			return EXHDR_BAD_YAML_OPT;
		}
	}
	else{
		*SaveDataSize = 0;
	}
	return 0;
}

int GetRemasterVersion_rsf(u16 *RemasterVersion, user_settings *usrset)
{
	char *Str = usrset->common.rsfSet.SystemControlInfo.RemasterVersion;
	if(!Str){
		*RemasterVersion = 0;
		return 0;
	}
	*RemasterVersion = strtol(Str,NULL,0);
	return 0;
}
