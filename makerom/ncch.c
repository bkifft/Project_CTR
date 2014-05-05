#include "lib.h"
#include "dir.h"
#include "ncch.h"
#include "exheader.h"
#include "elf.h"
#include "exefs.h"
#include "romfs.h"
#include "titleid.h"

#include "logo_data.h" // Contains Logos

// Private Prototypes
int SignCFA(u8 *Signature, u8 *CFA_HDR, keys_struct *keys);
int CheckCFASignature(u8 *Signature, u8 *CFA_HDR, keys_struct *keys);
int SignCXI(u8 *Signature, u8 *CXI_HDR, keys_struct *keys);
int CheckCXISignature(u8 *Signature, u8 *CXI_HDR, u8 *PubK);

void init_NCCHSettings(ncch_settings *set);
void free_NCCHSettings(ncch_settings *set);
int get_NCCHSettings(ncch_settings *ncchset, user_settings *usrset);
int SetBasicOptions(ncch_settings *ncchset, user_settings *usrset);
int CreateInputFilePtrs(ncch_settings *ncchset, user_settings *usrset);
int ImportNonCodeExeFsSections(ncch_settings *ncchset);	
int ImportLogo(ncch_settings *ncchset);

int SetupNcch(ncch_settings *ncchset, romfs_buildctx *romfs);
int FinaliseNcch(ncch_settings *ncchset);
int SetCommonHeaderBasicData(ncch_settings *ncchset, ncch_hdr *hdr);
bool IsValidProductCode(char *ProductCode, bool FreeProductCode);

int BuildCommonHeader(ncch_settings *ncchset);
int EncryptNCCHSections(ncch_settings *ncchset);
int WriteNCCHSectionsToBuffer(ncch_settings *ncchset);

// Code

int SignCFA(u8 *Signature, u8 *CFA_HDR, keys_struct *keys)
{
	return ctr_sig(CFA_HDR,sizeof(ncch_hdr),Signature,keys->rsa.cciCfaPub,keys->rsa.cciCfaPvt,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCFASignature(u8 *Signature, u8 *CFA_HDR, keys_struct *keys)
{
	return ctr_sig(CFA_HDR,sizeof(ncch_hdr),Signature,keys->rsa.cciCfaPub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

int SignCXI(u8 *Signature, u8 *CXI_HDR, keys_struct *keys)
{
	return ctr_sig(CXI_HDR,sizeof(ncch_hdr),Signature,keys->rsa.cxiHdrPub,keys->rsa.cxiHdrPvt,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCXISignature(u8 *Signature, u8 *CXI_HDR, u8 *PubK)
{
	int result = ctr_sig(CXI_HDR,sizeof(ncch_hdr),Signature,PubK,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
	return result;
}

// NCCH Build Functions

int build_NCCH(user_settings *usrset)
{
	int result;

	// Init Settings\n");
	ncch_settings *ncchset = malloc(sizeof(ncch_settings));
	if(!ncchset) {
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}
	init_NCCHSettings(ncchset);

	// Get Settings\n");
	result = get_NCCHSettings(ncchset,usrset);
	if(result) goto finish;

	

	if(!ncchset->options.IsCfa){ // CXI Specfic Sections
		// Build ExeFs Code Section\n");
		result = BuildExeFsCode(ncchset);
		if(result) goto finish;
	
		// Build ExHeader\n");
		result = BuildExHeader(ncchset);
		if(result) goto finish;
	}	

	
	// Build ExeFs\n");
	result = BuildExeFs(ncchset);
	if(result) goto finish;

	
	// Prepare for RomFs\n");
	romfs_buildctx romfs_ctx;
	memset(&romfs_ctx,0,sizeof(romfs_buildctx));
	result = SetupRomFs(ncchset,&romfs_ctx);
	if(result) goto finish;

	
	// Setup NCCH including final memory allocation\n");
	result = SetupNcch(ncchset,&romfs_ctx);
	if(result) goto finish;

	// Build RomFs\n");
	result = BuildRomFs(&romfs_ctx);
	if(result) goto finish;
	
	// Finalise NCCH (Hashes/Signatures and crypto)\n");
	result = FinaliseNcch(ncchset);
	if(result) goto finish;

finish:
	if(result) 
		fprintf(stderr,"[NCCH ERROR] NCCH Build Process Failed\n");
	free_NCCHSettings(ncchset);
	return result;
}

void init_NCCHSettings(ncch_settings *set)
{
	memset(set,0,sizeof(ncch_settings));
}

void free_NCCHSettings(ncch_settings *set)
{
	if(set->componentFilePtrs.elf) fclose(set->componentFilePtrs.elf);
	if(set->componentFilePtrs.banner) fclose(set->componentFilePtrs.banner);
	if(set->componentFilePtrs.icon) fclose(set->componentFilePtrs.icon);
	if(set->componentFilePtrs.logo) fclose(set->componentFilePtrs.logo);
	if(set->componentFilePtrs.code) fclose(set->componentFilePtrs.code);
	if(set->componentFilePtrs.exhdr) fclose(set->componentFilePtrs.exhdr);
	if(set->componentFilePtrs.romfs) fclose(set->componentFilePtrs.romfs);
	if(set->componentFilePtrs.plainregion) fclose(set->componentFilePtrs.plainregion);

	if(set->exefsSections.code.size) free(set->exefsSections.code.buffer);
	if(set->exefsSections.banner.size) free(set->exefsSections.banner.buffer);
	if(set->exefsSections.icon.size) free(set->exefsSections.icon.buffer);

	if(set->sections.exhdr.size) free(set->sections.exhdr.buffer);
	if(set->sections.logo.size) free(set->sections.logo.buffer);
	if(set->sections.plainRegion.size) free(set->sections.plainRegion.buffer);
	if(set->sections.exeFs.size) free(set->sections.exeFs.buffer);

	memset(set,0,sizeof(ncch_settings));

	free(set);
}

int get_NCCHSettings(ncch_settings *ncchset, user_settings *usrset)
{
	int result = 0;
	ncchset->out = &usrset->common.workingFile;
	
	ncchset->rsfSet = &usrset->common.rsfSet;
	ncchset->keys = &usrset->common.keys;

	result = SetBasicOptions(ncchset,usrset);
	if(result) return result;
	result = CreateInputFilePtrs(ncchset,usrset);
	if(result) return result;
	result = ImportNonCodeExeFsSections(ncchset);
	if(result) return result;
	result = ImportLogo(ncchset);
	if(result) return result;
	

	return 0;
}

int SetBasicOptions(ncch_settings *ncchset, user_settings *usrset)
{
	int result = 0;

	/* Options */
	ncchset->options.mediaSize = 0x200;

	ncchset->options.IncludeExeFsLogo = usrset->ncch.includeExefsLogo;
	
	if(usrset->common.rsfSet.Option.EnableCompress != -1) ncchset->options.CompressCode = usrset->common.rsfSet.Option.EnableCompress;
	else ncchset->options.CompressCode = true;

	if(usrset->common.rsfSet.Option.UseOnSD != -1) ncchset->options.UseOnSD = usrset->common.rsfSet.Option.UseOnSD;
	else ncchset->options.UseOnSD = false;
	usrset->common.rsfSet.Option.UseOnSD = ncchset->options.UseOnSD;

	if(usrset->common.rsfSet.Option.EnableCrypt != -1) ncchset->options.Encrypt = usrset->common.rsfSet.Option.EnableCrypt;
	else ncchset->options.Encrypt = true;

	if(usrset->common.rsfSet.Option.FreeProductCode != -1) ncchset->options.FreeProductCode = usrset->common.rsfSet.Option.FreeProductCode;
	else ncchset->options.FreeProductCode = false;

	ncchset->options.IsCfa = (usrset->ncch.ncchType == CFA);
	
	ncchset->options.IsBuildingCodeSection = (usrset->ncch.elfPath != NULL);

	ncchset->options.UseRomFS = ((ncchset->rsfSet->Rom.HostRoot && strlen(ncchset->rsfSet->Rom.HostRoot) > 0) || usrset->ncch.romfsPath);
	
	if(ncchset->options.IsCfa && !ncchset->options.UseRomFS){
		fprintf(stderr,"[NCCH ERROR] \"Rom/HostRoot\" must be set\n");
		return NCCH_BAD_YAML_SET;
	}

	return result;
}

int CreateInputFilePtrs(ncch_settings *ncchset, user_settings *usrset)
{
	if(usrset->ncch.romfsPath){
		ncchset->componentFilePtrs.romfsSize = GetFileSize_u64(usrset->ncch.romfsPath);
		ncchset->componentFilePtrs.romfs = fopen(usrset->ncch.romfsPath,"rb");
		if(!ncchset->componentFilePtrs.romfs){
			fprintf(stderr,"[NCCH ERROR] Failed to open RomFs file '%s'\n",usrset->ncch.romfsPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.elfPath){
		ncchset->componentFilePtrs.elfSize = GetFileSize_u64(usrset->ncch.elfPath);
		ncchset->componentFilePtrs.elf = fopen(usrset->ncch.elfPath,"rb");
		if(!ncchset->componentFilePtrs.elf){
			fprintf(stderr,"[NCCH ERROR] Failed to open elf file '%s'\n",usrset->ncch.elfPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.bannerPath){
		ncchset->componentFilePtrs.bannerSize = GetFileSize_u64(usrset->ncch.bannerPath);
		ncchset->componentFilePtrs.banner = fopen(usrset->ncch.bannerPath,"rb");
		if(!ncchset->componentFilePtrs.banner){
			fprintf(stderr,"[NCCH ERROR] Failed to open banner file '%s'\n",usrset->ncch.bannerPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.iconPath){
		ncchset->componentFilePtrs.iconSize = GetFileSize_u64(usrset->ncch.iconPath);
		ncchset->componentFilePtrs.icon = fopen(usrset->ncch.iconPath,"rb");
		if(!ncchset->componentFilePtrs.icon){
			fprintf(stderr,"[NCCH ERROR] Failed to open icon file '%s'\n",usrset->ncch.iconPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.logoPath){
		ncchset->componentFilePtrs.logoSize = GetFileSize_u64(usrset->ncch.logoPath);
		ncchset->componentFilePtrs.logo = fopen(usrset->ncch.logoPath,"rb");
		if(!ncchset->componentFilePtrs.logo){
			fprintf(stderr,"[NCCH ERROR] Failed to open logo file '%s'\n",usrset->ncch.logoPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}

	if(usrset->ncch.codePath){
		ncchset->componentFilePtrs.codeSize = GetFileSize_u64(usrset->ncch.codePath);
		ncchset->componentFilePtrs.code = fopen(usrset->ncch.codePath,"rb");
		if(!ncchset->componentFilePtrs.code){
			fprintf(stderr,"[NCCH ERROR] Failed to open ExeFs Code file '%s'\n",usrset->ncch.codePath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.exheaderPath){
		ncchset->componentFilePtrs.exhdrSize = GetFileSize_u64(usrset->ncch.exheaderPath);
		ncchset->componentFilePtrs.exhdr = fopen(usrset->ncch.exheaderPath,"rb");
		if(!ncchset->componentFilePtrs.exhdr){
			fprintf(stderr,"[NCCH ERROR] Failed to open ExHeader file '%s'\n",usrset->ncch.exheaderPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	if(usrset->ncch.plainRegionPath){
		ncchset->componentFilePtrs.plainregionSize = GetFileSize_u64(usrset->ncch.plainRegionPath);
		ncchset->componentFilePtrs.plainregion = fopen(usrset->ncch.plainRegionPath,"rb");
		if(!ncchset->componentFilePtrs.plainregion){
			fprintf(stderr,"[NCCH ERROR] Failed to open PlainRegion file '%s'\n",usrset->ncch.plainRegionPath);
			return FAILED_TO_IMPORT_FILE;
		}
	}
	return 0;
}

int ImportNonCodeExeFsSections(ncch_settings *ncchset)
{
	if(ncchset->componentFilePtrs.banner){
		ncchset->exefsSections.banner.size = ncchset->componentFilePtrs.bannerSize;
		ncchset->exefsSections.banner.buffer = malloc(ncchset->exefsSections.banner.size);
		if(!ncchset->exefsSections.banner.buffer) {
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			return MEM_ERROR;
		}
		ReadFile_64(ncchset->exefsSections.banner.buffer,ncchset->exefsSections.banner.size,0,ncchset->componentFilePtrs.banner);
	}
	if(ncchset->componentFilePtrs.icon){
		ncchset->exefsSections.icon.size = ncchset->componentFilePtrs.iconSize;
		ncchset->exefsSections.icon.buffer = malloc(ncchset->exefsSections.icon.size);
		if(!ncchset->exefsSections.icon.buffer) {
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
			return MEM_ERROR;
		}
		ReadFile_64(ncchset->exefsSections.icon.buffer,ncchset->exefsSections.icon.size,0,ncchset->componentFilePtrs.icon);
	}
	return 0;
}

int ImportLogo(ncch_settings *ncchset)
{
	if(ncchset->componentFilePtrs.logo){
		ncchset->sections.logo.size = align(ncchset->componentFilePtrs.logoSize,ncchset->options.mediaSize);
		ncchset->sections.logo.buffer = malloc(ncchset->sections.logo.size);
		if(!ncchset->sections.logo.buffer) {
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
			return MEM_ERROR;
		}
		memset(ncchset->sections.logo.buffer,0,ncchset->sections.logo.size);
		ReadFile_64(ncchset->sections.logo.buffer,ncchset->componentFilePtrs.logoSize,0,ncchset->componentFilePtrs.logo);
	}
	else if(ncchset->rsfSet->BasicInfo.Logo){
		if(strcasecmp(ncchset->rsfSet->BasicInfo.Logo,"nintendo") == 0){
			ncchset->sections.logo.size = 0x2000;
			ncchset->sections.logo.buffer = malloc(ncchset->sections.logo.size);
			if(!ncchset->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(ncchset->sections.logo.buffer,Nintendo_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->rsfSet->BasicInfo.Logo,"licensed") == 0){
			ncchset->sections.logo.size = 0x2000;
			ncchset->sections.logo.buffer = malloc(ncchset->sections.logo.size);
			if(!ncchset->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
				return MEM_ERROR;
			}
			memcpy(ncchset->sections.logo.buffer,Nintendo_LicensedBy_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->rsfSet->BasicInfo.Logo,"distributed") == 0){
			ncchset->sections.logo.size = 0x2000;
			ncchset->sections.logo.buffer = malloc(ncchset->sections.logo.size);
			if(!ncchset->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(ncchset->sections.logo.buffer,Nintendo_DistributedBy_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->rsfSet->BasicInfo.Logo,"ique") == 0){
			ncchset->sections.logo.size = 0x2000;
			ncchset->sections.logo.buffer = malloc(ncchset->sections.logo.size);
			if(!ncchset->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
				return MEM_ERROR;
			}
			memcpy(ncchset->sections.logo.buffer,iQue_with_ISBN_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->rsfSet->BasicInfo.Logo,"iqueforsystem") == 0){
			ncchset->sections.logo.size = 0x2000;
			ncchset->sections.logo.buffer = malloc(ncchset->sections.logo.size);
			if(!ncchset->sections.logo.buffer) {
				fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
				return MEM_ERROR;
			}
			memcpy(ncchset->sections.logo.buffer,iQue_without_ISBN_LZ,0x2000);
		}
		else if(strcasecmp(ncchset->rsfSet->BasicInfo.Logo,"none") != 0){
			fprintf(stderr,"[NCCH ERROR] Invalid logo name\n");
			return NCCH_BAD_YAML_SET;
		}
	}
	return 0;
}

int SetupNcch(ncch_settings *ncchset, romfs_buildctx *romfs)
{
	u64 ncchSize = 0;
	u64 exhdrSize,logoSize,plnRgnSize,exefsSize,romfsSize;
	u64 exhdrOffset,logoOffset,plnRgnOffset,exefsOffset,romfsOffset;
	u32 exefsHashSize,romfsHashSize;

	ncchSize += 0x200; // Sig+Hdr

	// Sizes for NCCH hdr
	if(ncchset->sections.exhdr.size){
		exhdrSize = 0x400;
		exhdrOffset = ncchSize;
		ncchSize += ncchset->sections.exhdr.size;
	}
	else
		exhdrSize = 0;

	if(ncchset->sections.logo.size){
		logoSize = ncchset->sections.logo.size;
		logoOffset = align(ncchSize,ncchset->options.mediaSize);
		ncchSize = logoOffset + logoSize;
	}
	else
		logoSize = 0;

	if(ncchset->sections.plainRegion.size){
		plnRgnSize = align(ncchset->sections.plainRegion.size,ncchset->options.mediaSize);
		plnRgnOffset = align(ncchSize,ncchset->options.mediaSize);
		ncchSize = plnRgnOffset + plnRgnSize;
	}
	else
		plnRgnSize = 0;

	if(ncchset->sections.exeFs.size){
		exefsHashSize = align(sizeof(exefs_hdr),ncchset->options.mediaSize);
		exefsSize = align(ncchset->sections.exeFs.size,ncchset->options.mediaSize);
		exefsOffset = align(ncchSize,ncchset->options.mediaSize);
		ncchSize = exefsOffset + exefsSize;
	}
	else
		exefsSize = 0;

	if(romfs->romfsSize){
		romfsHashSize = align(romfs->romfsHeaderSize,ncchset->options.mediaSize);
		romfsSize = align(romfs->romfsSize,ncchset->options.mediaSize);
		//romfsOffset = align(ncchSize,0x200); // Old makerom method, SDK 2.x and prior
		romfsOffset = align(ncchSize,0x1000);
		ncchSize = romfsOffset + romfsSize;
	}
	else
		romfsSize = 0;



	// Aligning Total NCCH Size
	ncchSize = align(ncchSize,ncchset->options.mediaSize);
	u8 *ncch = calloc(1,ncchSize);
	if(!ncch){
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	// Setting up hdr\n");
	ncch_hdr *hdr = (ncch_hdr*)(ncch+0x100);
	int ret = SetCommonHeaderBasicData(ncchset,hdr);
	if(ret != 0){
		free(ncch);
		return ret;
	}
	u32_to_u8(hdr->ncchSize,ncchSize/ncchset->options.mediaSize,LE);


	// Copy already built sections to ncch\n");
	if(exhdrSize){
		memcpy((u8*)(ncch+exhdrOffset),ncchset->sections.exhdr.buffer,ncchset->sections.exhdr.size);
		free(ncchset->sections.exhdr.buffer);
		ncchset->sections.exhdr.buffer = NULL;
		u32_to_u8(hdr->exhdrSize,exhdrSize,LE);
	}

	if(logoSize){
		memcpy((u8*)(ncch+logoOffset),ncchset->sections.logo.buffer,ncchset->sections.logo.size);
		free(ncchset->sections.logo.buffer);
		ncchset->sections.logo.buffer = NULL;
		u32_to_u8(hdr->logoOffset,logoOffset/ncchset->options.mediaSize,LE);
		u32_to_u8(hdr->logoSize,logoSize/ncchset->options.mediaSize,LE);
	}

	if(plnRgnSize){		
		memcpy((u8*)(ncch+plnRgnOffset),ncchset->sections.plainRegion.buffer,ncchset->sections.plainRegion.size);
		free(ncchset->sections.plainRegion.buffer);
		ncchset->sections.plainRegion.buffer = NULL;
		u32_to_u8(hdr->plainRegionOffset,plnRgnOffset/ncchset->options.mediaSize,LE);
		u32_to_u8(hdr->plainRegionSize,plnRgnSize/ncchset->options.mediaSize,LE);
	}

	if(exefsSize){	
		memcpy((u8*)(ncch+exefsOffset),ncchset->sections.exeFs.buffer,ncchset->sections.exeFs.size);
		free(ncchset->sections.exeFs.buffer);
		
		ncchset->sections.exeFs.buffer = NULL;
		
		u32_to_u8(hdr->exefsOffset,exefsOffset/ncchset->options.mediaSize,LE);
		
		u32_to_u8(hdr->exefsSize,exefsSize/ncchset->options.mediaSize,LE);
		
		u32_to_u8(hdr->exefsHashSize,exefsHashSize/ncchset->options.mediaSize,LE);
		
	}

	// Point Romfs CTX to output buffer, if exists\n");
	if(romfsSize){
		romfs->output = ncch + romfsOffset;
		u32_to_u8(hdr->romfsOffset,romfsOffset/ncchset->options.mediaSize,LE);
		u32_to_u8(hdr->romfsSize,romfsSize/ncchset->options.mediaSize,LE);
		u32_to_u8(hdr->romfsHashSize,romfsHashSize/ncchset->options.mediaSize,LE);
	}
	
	ncchset->out->buffer = ncch;
	ncchset->out->size = ncchSize;

	GetNCCHStruct(&ncchset->cryptoDetails,hdr);

	return 0;
}

int FinaliseNcch(ncch_settings *ncchset)
{
	u8 *ncch = ncchset->out->buffer;

	ncch_hdr *hdr = (ncch_hdr*)(ncch + 0x100);
	u8 *exhdr = (u8*)(ncch + ncchset->cryptoDetails.exhdrOffset);
	u8 *logo = (u8*)(ncch + ncchset->cryptoDetails.logoOffset);
	u8 *exefs = (u8*)(ncch + ncchset->cryptoDetails.exefsOffset);
	u8 *romfs = (u8*)(ncch + ncchset->cryptoDetails.romfsOffset);

	// Taking Hashes\n");
	if(ncchset->cryptoDetails.exhdrSize)
		ctr_sha(exhdr,0x400,hdr->exhdrHash,CTR_SHA_256);
	if(ncchset->cryptoDetails.logoSize)
		ctr_sha(logo,ncchset->cryptoDetails.logoSize,hdr->logoHash,CTR_SHA_256);
	if(ncchset->cryptoDetails.exefsHashDataSize)
		ctr_sha(exefs,ncchset->cryptoDetails.exefsHashDataSize,hdr->exefsHash,CTR_SHA_256);
	if(ncchset->cryptoDetails.romfsHashDataSize)
		ctr_sha(romfs,ncchset->cryptoDetails.romfsHashDataSize,hdr->romfsHash,CTR_SHA_256);

	// Signing NCCH\n");
	int sig_result = Good;
	if(ncchset->options.IsCfa) sig_result = SignCFA(ncch,(u8*)hdr,ncchset->keys);
	else sig_result = SignCXI(ncch,(u8*)hdr,ncchset->keys);
	if(sig_result != Good){
		fprintf(stderr,"[NCCH ERROR] Failed to sign %s header\n",ncchset->options.IsCfa ? "CFA" : "CXI");
		return sig_result;
	}

	//memdump(stdout,"ncch: ",ncch,0x200);

	// Crypting NCCH\n");
	ncch_key_type keyType = GetNCCHKeyType(hdr);
	if(keyType != NoKey){
		SetNcchUnfixedKeys(ncchset->keys, ncch);

		// Getting AES Keys
		u8 *key0 = GetNCCHKey(keyType, ncchset->keys);
		u8 *key1 = GetNCCHKey(keyType, ncchset->keys);
		if(keyType == KeyIsUnFixed2)
			key0 = GetNCCHKey(KeyIsUnFixed, ncchset->keys);

		if(key0 == NULL || key1 == NULL){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			free(ncch);
			return -1;
		}

		/*
		memdump(stdout,"key0: ",key0,16);
		memdump(stdout,"key1: ",key1,16);
		*/

		// Crypting Exheader
		if(ncchset->cryptoDetails.exhdrSize)
			CryptNCCHSection(exhdr,ncchset->cryptoDetails.exhdrSize,0x0,&ncchset->cryptoDetails,key0,ncch_exhdr);

		// Crypting ExeFs Files
		if(ncchset->cryptoDetails.exefsSize){
			exefs_hdr *exefsHdr = (exefs_hdr*)exefs;
			for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
				u8 *key = NULL;
				if(strncmp(exefsHdr->fileHdr[i].name,"icon",8) == 0 || strncmp(exefsHdr->fileHdr[i].name,"banner",8) == 0)
					key = key0;
				else
					key = key1;

				u32 offset = u8_to_u32(exefsHdr->fileHdr[i].offset,LE) + 0x200;
				u32 size = u8_to_u32(exefsHdr->fileHdr[i].size,LE);

				if(size)
					CryptNCCHSection((exefs+offset),align(size,ncchset->options.mediaSize),offset,&ncchset->cryptoDetails,key,ncch_exefs);

			}
			// Crypting ExeFs Header
			CryptNCCHSection(exefs,0x200,0x0,&ncchset->cryptoDetails,key0,ncch_exefs);
		}

		// Crypting RomFs
		if(ncchset->cryptoDetails.romfsSize)
			CryptNCCHSection(romfs,ncchset->cryptoDetails.romfsSize,0x0,&ncchset->cryptoDetails,key1,ncch_romfs);
	}

	return 0;
}

int SetCommonHeaderBasicData(ncch_settings *ncchset, ncch_hdr *hdr)
{
	/* NCCH Magic */
	memcpy(hdr->magic,"NCCH",4);

	/* NCCH Format Version */
	if(!ncchset->options.IsCfa)
		u16_to_u8(hdr->formatVersion,0x2,LE);

	
	/* Setting ProgramId/TitleId */
	u64 ProgramId = 0;
	int result = GetProgramID(&ProgramId,ncchset->rsfSet,false); 
	if(result) return result;

	u64_to_u8(hdr->programId,ProgramId,LE);
	u64_to_u8(hdr->titleId,ProgramId,LE);

	/* Get Product Code and Maker Code */
	if(ncchset->rsfSet->BasicInfo.ProductCode){
		if(!IsValidProductCode((char*)ncchset->rsfSet->BasicInfo.ProductCode,ncchset->options.FreeProductCode)){
			fprintf(stderr,"[NCCH ERROR] Invalid Product Code\n");
			return NCCH_BAD_YAML_SET;
		}
		memcpy(hdr->productCode,ncchset->rsfSet->BasicInfo.ProductCode,strlen((char*)ncchset->rsfSet->BasicInfo.ProductCode));
	}
	else memcpy(hdr->productCode,"CTR-P-CTAP",10);

	if(ncchset->rsfSet->BasicInfo.CompanyCode){
		if(strlen((char*)ncchset->rsfSet->BasicInfo.CompanyCode) != 2){
			fprintf(stderr,"[NCCH ERROR] CompanyCode length must be 2\n");
			return NCCH_BAD_YAML_SET;
		}
		memcpy(hdr->makerCode,ncchset->rsfSet->BasicInfo.CompanyCode,2);
	}
	else memcpy(hdr->makerCode,"00",2);

	// Setting Encryption Settings
	if(!ncchset->options.Encrypt)
		hdr->flags[OtherFlag] = (NoCrypto|FixedCryptoKey);
	else if(ncchset->keys->aes.ncchKeyX0){
		hdr->flags[OtherFlag] = UnFixedCryptoKey;
		if(ncchset->keys->aes.ncchKeyX1)
			hdr->flags[SecureCrypto2] = 1;
	}
	else{
		hdr->flags[OtherFlag] = FixedCryptoKey;	
		u8 *key = GetNCCHKey(GetNCCHKeyType(hdr),ncchset->keys);
		if(!key){ // for detecting absense of fixed aes keys
			hdr->flags[OtherFlag] = (NoCrypto|FixedCryptoKey);
			fprintf(stderr,"[NCCH WARNING] NCCH AES Key could not be loaded, NCCH will not be encrypted\n");
		}
	}

	

	/* Set ContentUnitSize */
	hdr->flags[ContentUnitSize] = 0; // 0x200

	/* Setting ContentPlatform */
	hdr->flags[ContentPlatform] = 1; // CTR

	/* Setting OtherFlag */
	if(!ncchset->options.UseRomFS) 
		hdr->flags[OtherFlag] |= NoMountRomFs;


	/* Setting ContentType */
	hdr->flags[ContentType] = 0;
	if(ncchset->options.UseRomFS) hdr->flags[ContentType] |= content_Data;
	if(!ncchset->options.IsCfa) hdr->flags[ContentType] |= content_Executable;
	if(ncchset->rsfSet->BasicInfo.ContentType){
		if(strcmp(ncchset->rsfSet->BasicInfo.ContentType,"Application") == 0) hdr->flags[ContentType] |= 0;
		else if(strcmp(ncchset->rsfSet->BasicInfo.ContentType,"SystemUpdate") == 0) hdr->flags[ContentType] |= content_SystemUpdate;
		else if(strcmp(ncchset->rsfSet->BasicInfo.ContentType,"Manual") == 0) hdr->flags[ContentType] |= content_Manual;
		else if(strcmp(ncchset->rsfSet->BasicInfo.ContentType,"Child") == 0) hdr->flags[ContentType] |= content_Child;
		else if(strcmp(ncchset->rsfSet->BasicInfo.ContentType,"Trial") == 0) hdr->flags[ContentType] |= content_Trial;
		else{
			fprintf(stderr,"[NCCH ERROR] Invalid ContentType '%s'\n",ncchset->rsfSet->BasicInfo.ContentType);
			return NCCH_BAD_YAML_SET;
		}
	}

	return 0;
}

bool IsValidProductCode(char *ProductCode, bool FreeProductCode)
{
	if(strlen(ProductCode) > 16) return false;

	if(FreeProductCode)
		return true;

	if(strlen(ProductCode) < 10) return false;
	if(strncmp(ProductCode,"CTR-",4) != 0) return false;
	if(ProductCode[5] != '-') return false;
	if(!isdigit(ProductCode[4]) && !isupper(ProductCode[4])) return false;
	for(int i = 6; i < 10; i++){
		if(!isdigit(ProductCode[i]) && !isupper(ProductCode[i])) return false;
	}

	return true;
}

// NCCH Read Functions

int VerifyNCCH(u8 *ncch, keys_struct *keys, bool CheckHash, bool SuppressOutput)
{
	// Setup
	u8 Hash[0x20];
	u8 *hdr_sig = ncch;
	ncch_hdr* hdr = GetNCCH_CommonHDR(NULL,NULL,ncch);

	ncch_struct *ncch_ctx = calloc(1,sizeof(ncch_struct));
	if(!ncch_ctx){ 
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	GetNCCHStruct(ncch_ctx,hdr);

	ncch_key_type keyType = GetNCCHKeyType(hdr);
	u8 *key0 = NULL;
	u8 *key1 = NULL;
	if(keyType != NoKey){
		//memdump(stdout,"ncch: ",ncch,0x200);
		SetNcchUnfixedKeys(keys,ncch);
		if(GetNCCHKey(keyType,keys) == NULL){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key.\n");
			return UNABLE_TO_LOAD_NCCH_KEY;
		}
		key0 = GetNCCHKey(keyType,keys);
		key1 = GetNCCHKey(keyType,keys);
		if(keyType == KeyIsUnFixed2)
			key0 = GetNCCHKey(KeyIsUnFixed,keys);
	}

	//memdump(stdout,"key0: ",key0,16);
	//memdump(stdout,"key1: ",key1,16);

	if(IsCfa(hdr)){
		if(CheckCFASignature(hdr_sig,(u8*)hdr,keys) != Good && !keys->rsa.isFalseSign){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CFA Sigcheck Failed\n");
			free(ncch_ctx);
			return NCCH_HDR_SIG_BAD;
		}
		if(!ncch_ctx->romfsSize){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CFA is corrupt\n");
			free(ncch_ctx);
			return NO_ROMFS_IN_CFA;
		}
	}
	else{ // IsCxi
		// Checking for necessary sections
		if(!ncch_ctx->exhdrSize){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncch_ctx);
			return NO_EXHEADER_IN_CXI;
		}
		if(!ncch_ctx->exefsSize){
			if(!SuppressOutput) 
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			free(ncch_ctx);
			return NO_EXEFS_IN_CXI;
		}
		// Get ExHeader
		extended_hdr *ExHeader = malloc(ncch_ctx->exhdrSize);
		if(!ExHeader){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncch_ctx);
			return MEM_ERROR; 
		}
		memcpy(ExHeader,ncch+ncch_ctx->exhdrOffset,ncch_ctx->exhdrSize);
		if(key0 != NULL)
			CryptNCCHSection((u8*)ExHeader,ncch_ctx->exhdrSize,0,ncch_ctx,key0,ncch_exhdr);

		// Checking Exheader Hash to see if decryption was sucessful
		ctr_sha(ExHeader,0x400,Hash,CTR_SHA_256);
		if(memcmp(Hash,hdr->exhdrHash,0x20) != 0){
			//memdump(stdout,"Expected Hash: ",hdr->extended_header_sha_256_hash,0x20);
			//memdump(stdout,"Actual Hash:   ",Hash,0x20);
			//memdump(stdout,"Exheader:      ",(u8*)ExHeader,0x400);
			if(!SuppressOutput) {
				fprintf(stderr,"[NCCH ERROR] ExHeader Hashcheck Failed\n");
				fprintf(stderr,"[NCCH ERROR] CXI is corrupt\n");
			}
			free(ncch_ctx);
			free(ExHeader);
			return ExHeader_Hashfail;
		}

		// Checking RSA Sigs
		u8 *hdr_pubk = GetNcchHdrPubKey_frm_exhdr(ExHeader);

		if(CheckaccessDescSignature(ExHeader,keys) != 0 && !keys->rsa.isFalseSign){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] AccessDesc Sigcheck Failed\n");
			free(ncch_ctx);
			free(ExHeader);
			return ACCESSDESC_SIG_BAD;
		}
		if(CheckCXISignature(hdr_sig,(u8*)hdr,hdr_pubk) != 0 /* && !keys->rsa.isFalseSign*/){ // This should always be correct
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] CXI Header Sigcheck Failed\n");
			free(ncch_ctx);
			free(ExHeader);
			return NCCH_HDR_SIG_BAD;
		}
		free(ExHeader);
	}

	if(!CheckHash)
		return 0;

	/* Checking ExeFs Hash, if present */
	if(ncch_ctx->exefsSize)
	{
		u8 *ExeFs = malloc(ncch_ctx->exefsHashDataSize);
		if(!ExeFs){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncch_ctx);
			return MEM_ERROR; 
		}
		memcpy(ExeFs,ncch+ncch_ctx->exefsOffset,ncch_ctx->exefsHashDataSize);
		if(key0 != NULL)
			CryptNCCHSection(ExeFs,ncch_ctx->exefsHashDataSize,0,ncch_ctx,key0,ncch_exefs);
		ctr_sha(ExeFs,ncch_ctx->exefsHashDataSize,Hash,CTR_SHA_256);
		free(ExeFs);
		if(memcmp(Hash,hdr->exefsHash,0x20) != 0){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] ExeFs Hashcheck Failed\n");
			free(ncch_ctx);
			return ExeFs_Hashfail;
		}
	}

	/* Checking RomFs hash, if present */
	if(ncch_ctx->romfsSize){
		u8 *RomFs = malloc(ncch_ctx->romfsHashDataSize);
		if(!RomFs){ 
			fprintf(stderr,"[NCCH ERROR] Not enough memory\n"); 
			free(ncch_ctx);
			return MEM_ERROR; 
		}
		memcpy(RomFs,ncch+ncch_ctx->romfsOffset,ncch_ctx->romfsHashDataSize);
		if(key1 != NULL)
			CryptNCCHSection(RomFs,ncch_ctx->romfsHashDataSize,0,ncch_ctx,key1,ncch_romfs);
		ctr_sha(RomFs,ncch_ctx->romfsHashDataSize,Hash,CTR_SHA_256);
		free(RomFs);
		if(memcmp(Hash,hdr->romfsHash,0x20) != 0){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] RomFs Hashcheck Failed\n");
			free(ncch_ctx);
			return ExeFs_Hashfail;
		}
	}

	/* Checking the Logo Hash, if present */
	if(ncch_ctx->logoSize){
		u8 *logo = (ncch+ncch_ctx->logoOffset);
		ctr_sha(logo,ncch_ctx->logoSize,Hash,CTR_SHA_256);
		if(memcmp(Hash,hdr->logoHash,0x20) != 0){
			if(!SuppressOutput) fprintf(stderr,"[NCCH ERROR] Logo Hashcheck Failed\n");
			free(ncch_ctx);
			return Logo_Hashfail;
		}
	} 
	
	
	free(ncch_ctx);
	return 0;
}


u8* RetargetNCCH(FILE *fp, u64 size, u8 *TitleId, u8 *ProgramId, keys_struct *keys)
{
	u8 *ncch = calloc(1,size);
	if(!ncch){
		fprintf(stderr,"[NCCH ERROR] Not enough memory\n");
		return NULL;
	}
	ReadFile_64(ncch,size,0,fp); // Importing
	
	if(ModifyNcchIds(ncch,TitleId, ProgramId, keys) != 0){
		free(ncch);
		return NULL;
	}

	return ncch;
}

int ModifyNcchIds(u8 *ncch, u8 *titleId, u8 *programId, keys_struct *keys)
{
	if(!IsNCCH(NULL,ncch)){
		//free(ncch);
		return -1;
	}
		
	ncch_hdr *hdr = NULL;
	hdr = GetNCCH_CommonHDR(NULL,NULL,ncch);
	
	if(/*keys->rsa.requiresPresignedDesc && */!IsCfa(hdr)){
		fprintf(stderr,"[NCCH ERROR] CXI's ID cannot be modified without the ability to resign the AccessDesc\n"); // Not yet yet, requires AccessDesc Privk, may implement anyway later
		//free(ncch);
		return -1;
	}
	
	bool titleIdMatches = titleId == NULL? true : memcmp(titleId,hdr->titleId,8) == 0;
	bool programIdMatches = programId == NULL? true : memcmp(programId,hdr->programId,8) == 0;

	if(titleIdMatches && programIdMatches) 
		return 0;// if no modification is required don't do anything

	if(titleIdMatches){ // If TitleID Same, no crypto required, just resign.
		memcpy(hdr->programId,programId,8);
		SignCFA(ncch,(u8*)hdr,keys);
		return 0;
	}

	ncch_key_type keytype = GetNCCHKeyType(hdr);
	ncch_struct ncch_struct;
	u8 *key = NULL;
	u8 *romfs = NULL;
	
	//Decrypting if necessary
	if(keytype != NoKey){
		GetNCCHStruct(&ncch_struct,hdr);
		romfs = (ncch+ncch_struct.romfsOffset);
		SetNcchUnfixedKeys(keys, ncch); // For Secure Crypto
		key = GetNCCHKey(keytype,keys);
		if(key == NULL){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			//free(ncch);
			return -1;
		}
		CryptNCCHSection(romfs,ncch_struct.romfsSize,0,&ncch_struct,key,ncch_romfs);
	}
	
	// Editing data and resigning
	if(titleId)
		memcpy(hdr->titleId,titleId,8);
	if(programId)
		memcpy(hdr->programId,programId,8);
	SignCFA(ncch,(u8*)hdr,keys);

	//Checking New Key Type
	keytype = GetNCCHKeyType(hdr);
	
	// Re-encrypting if necessary
	if(keytype != NoKey){
		GetNCCHStruct(&ncch_struct,hdr);
		romfs = (ncch+ncch_struct.romfsOffset);
		SetNcchUnfixedKeys(keys, ncch); // For Secure Crypto
		key = GetNCCHKey(keytype,keys);
		if(key == NULL){
			fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key\n");
			//free(ncch);
			return -1;
		}
		CryptNCCHSection(romfs,ncch_struct.romfsSize,0,&ncch_struct,key,ncch_romfs);
	}

	return 0;
}


ncch_hdr* GetNCCH_CommonHDR(void *out, FILE *fp, u8 *buf)
{
	if(!fp && !buf) return NULL;
	if(fp){
		if(!out) return NULL;
		ReadFile_64(out,0x100,0x100,fp);
		return (ncch_hdr*)out;
	}
	else{
		return (ncch_hdr*)(buf+0x100);
	}
}


bool IsNCCH(FILE *fp, u8 *buf)
{
	if(!fp && !buf) return false;
	ncch_hdr *ncchHDR = NULL;
	bool result;
	if(fp) {
		ncchHDR = malloc(sizeof(ncch_hdr));
		GetNCCH_CommonHDR(ncchHDR,fp,NULL);
		result = (memcmp(ncchHDR->magic,"NCCH",4) == 0);
		free(ncchHDR);
	}
	else {
		ncchHDR = GetNCCH_CommonHDR(ncchHDR,NULL,buf);
		result = (memcmp(ncchHDR->magic,"NCCH",4) == 0);
	}
	return result;
}

bool IsCfa(ncch_hdr* hdr)
{
	return (((hdr->flags[ContentType] & content_Data) == content_Data) && ((hdr->flags[ContentType] & content_Executable) != content_Executable));
}

u32 GetNCCH_MediaUnitSize(ncch_hdr* hdr)
{
	u16 formatVersion = u8_to_u16(hdr->formatVersion,LE);
	u32 ret = 0;
	if (formatVersion == 1)
		ret = 1;
	else if (formatVersion == 2 || formatVersion == 0)
		ret = 1 << (hdr->flags[ContentUnitSize] + 9);
	return ret;
	//return 0x200*pow(2,hdr->flags[ContentUnitSize]);
}

u32 GetNCCH_MediaSize(ncch_hdr* hdr)
{
	return u8_to_u32(hdr->ncchSize,LE);
}

ncch_key_type GetNCCHKeyType(ncch_hdr* hdr)
{	
	// Non-Secure Key Options
	if((hdr->flags[OtherFlag] & NoCrypto) == NoCrypto) 
		return NoKey;
	if((hdr->flags[OtherFlag] & FixedCryptoKey) == FixedCryptoKey){
		if((hdr->programId[4] & 0x10) == 0x10) 
			return KeyIsSystemFixed;
		else 
			return KeyIsNormalFixed;
	}

	// Secure Key Options
	if(hdr->flags[SecureCrypto2]) 
		return KeyIsUnFixed2;
	return KeyIsUnFixed;
}

u8* GetNCCHKey(ncch_key_type keytype, keys_struct *keys)
{
	switch(keytype){
		case NoKey: return NULL;
		case KeyIsNormalFixed:
			return keys->aes.normalKey;
		case KeyIsSystemFixed:
			return keys->aes.systemFixedKey;
		case KeyIsUnFixed:
			if(keys->aes.ncchKeyX0)
				return keys->aes.unFixedKey0;
			else
				return NULL;
		case KeyIsUnFixed2:
			if(keys->aes.ncchKeyX1)
				return keys->aes.unFixedKey1;
			else
				return NULL;
	}
	return NULL;
}

int GetNCCHSection(u8 *dest, u64 dest_max_size, u64 src_pos, u8 *ncch, ncch_struct *ncch_ctx, keys_struct *keys, ncch_section section)
{
	if(!ncch) return MEM_ERROR;
	u8 *key = NULL;
	ncch_hdr* hdr = GetNCCH_CommonHDR(NULL,NULL,ncch);
	ncch_key_type keytype = GetNCCHKeyType(hdr);

	if(keytype != NoKey && (section == ncch_exhdr || section == ncch_exefs || section == ncch_romfs)){
		key = GetNCCHKey(keytype,keys);
		if(key == NULL){
			//fprintf(stderr,"[NCCH ERROR] Failed to load ncch aes key.\n");
			return UNABLE_TO_LOAD_NCCH_KEY;
		}
	}
	//printf("detecting section type\n");
	u64 offset = 0;
	u64 size = 0;
	switch(section){
		case ncch_exhdr:
			offset = ncch_ctx->exhdrOffset;
			size = ncch_ctx->exhdrSize;
			break;
		case ncch_Logo:
			offset = ncch_ctx->logoOffset;
			size = ncch_ctx->logoSize;
			break;
		case ncch_PlainRegion:
			offset = ncch_ctx->plainRegionOffset;
			size = ncch_ctx->plainRegionSize;
			break;
		case ncch_exefs:
			offset = ncch_ctx->exefsOffset;
			size = ncch_ctx->exefsSize;
			break;
		case ncch_romfs:
			offset = ncch_ctx->romfsOffset;
			size = ncch_ctx->romfsSize;
			break;
	}
	if(!offset || !size) return NCCH_SECTION_NOT_EXIST; 

	if(src_pos > size) return DATA_POS_DNE;

	size = min_u64(size-src_pos,dest_max_size);

	//printf("Copying data\n");
	u8 *section_pos = (ncch + offset + src_pos);
	memcpy(dest,section_pos,size);

	//printf("decrypting if needed\n");
	if(keytype != NoKey && (section == ncch_exhdr || section == ncch_exefs || section == ncch_romfs)){ // Decrypt
		//memdump(stdout,"Key: ",key,16);
		CryptNCCHSection(dest,size,src_pos,ncch_ctx,key,section);
		//printf("no cigar\n");
	}
	//printf("Got thing okay\n");
	return 0;
}

int GetNCCHStruct(ncch_struct *ctx, ncch_hdr *header)
{
	memcpy(ctx->titleId,header->titleId,8);
	memcpy(ctx->programId,header->programId,8);

	
	u32 media_unit = GetNCCH_MediaUnitSize(header);
	
	ctx->formatVersion = u8_to_u16(header->formatVersion,LE);
	if(!IsCfa(header)){
		ctx->exhdrOffset = 0x200;
		ctx->exhdrSize = u8_to_u32(header->exhdrSize,LE) + 0x400;
		ctx->plainRegionOffset = (u64)(u8_to_u32(header->plainRegionOffset,LE)*media_unit);
		ctx->plainRegionSize = (u64)(u8_to_u32(header->plainRegionSize,LE)*media_unit);
	}

	ctx->logoOffset = (u64)(u8_to_u32(header->logoOffset,LE)*media_unit);
	ctx->logoSize = (u64)(u8_to_u32(header->logoSize,LE)*media_unit);
	ctx->exefsOffset = (u64)(u8_to_u32(header->exefsOffset,LE)*media_unit);
	ctx->exefsSize = (u64)(u8_to_u32(header->exefsSize,LE)*media_unit);
	ctx->exefsHashDataSize = (u64)(u8_to_u32(header->exefsHashSize,LE)*media_unit);
	ctx->romfsOffset = (u64) (u8_to_u32(header->romfsOffset,LE)*media_unit);
	ctx->romfsSize = (u64) (u8_to_u32(header->romfsSize,LE)*media_unit);
	ctx->romfsHashDataSize = (u64)(u8_to_u32(header->romfsHashSize,LE)*media_unit);
	return 0;
}

void CryptNCCHSection(u8 *buffer, u64 size, u64 src_pos, ncch_struct *ctx, u8 key[16], u8 type)
{
	if(type < 1 || type > 3)
		return;
	u8 counter[0x10];
	ncch_get_counter(ctx,counter,type);	
	ctr_aes_context aes_ctx;
	memset(&aes_ctx,0x0,sizeof(ctr_aes_context));
	ctr_init_counter(&aes_ctx, key, counter);
	if(src_pos > 0){
		u32 carry = 0;
		carry = align(src_pos,0x10);
		carry /= 0x10;
		ctr_add_counter(&aes_ctx,carry);
	}

	
	ctr_crypt_counter(&aes_ctx, buffer, buffer, size);
	return;
}

void ncch_get_counter(ncch_struct *ctx, u8 counter[16], u8 type)
{
	u8 *titleId = ctx->titleId;
	u32 i;
	u32 x = 0;

	memset(counter, 0, 16);

	if (ctx->formatVersion == 2 || ctx->formatVersion == 0)
	{
		for(i=0; i<8; i++)
			counter[i] = titleId[7-i];
		counter[8] = type;
	}
	else if (ctx->formatVersion == 1)
	{
		switch(type){
			case ncch_exhdr : x = ctx->exhdrOffset; break;
			case ncch_exefs : x = ctx->exefsOffset; break;
			case ncch_romfs : x = ctx->romfsOffset; break;
		}
		for(i=0; i<8; i++)
			counter[i] = titleId[i];
		for(i=0; i<4; i++)
			counter[12+i] = x>>((3-i)*8);
	}
	
	//memdump(stdout,"CTR: ",counter,16);
}