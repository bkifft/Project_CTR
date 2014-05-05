#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "exefs.h"
#include "certs.h"
#include "cia.h"
#include "tik.h"
#include "tmd.h"
#include "titleid.h"
#include "srl.h"
#include "ncsd.h"

// Private Prototypes
/* cia_settings tools */
void init_CIASettings(cia_settings *set);
void free_CIASettings(cia_settings *set);
int get_CIASettings(cia_settings *ciaset, user_settings *usrset);

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset);
int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset);
int GetCIADataFromNcch(cia_settings *ciaset, u8 *ncch, ncch_struct *ncch_ctx, u8 *key);
int GetMetaRegion(cia_settings *ciaset, u8 *ncch, ncch_struct *ncch_ctx, u8 *key);
int GetContentFilePtrs(cia_settings *ciaset, user_settings *usrset);
int ImportNcchContent(cia_settings *ciaset);
int GetSettingsFromSrl(cia_settings *ciaset);
int GetSettingsFromCci(cia_settings *ciaset);

u16 SetupVersion(u16 Major, u16 Minor, u16 Micro);

void GetContentHashes(cia_settings *ciaset);
void EncryptContent(cia_settings *ciaset);

int BuildCIA_CertChain(cia_settings *ciaset);
int BuildCIA_Header(cia_settings *ciaset);

int WriteCIAtoFile(cia_settings *ciaset);

int CryptContent(u8 *EncBuffer,u8 *DecBuffer,u64 size,u8 *title_key, u16 index, u8 mode);


int build_CIA(user_settings *usrset)
{
	int result = 0;

	// Init Settings
	cia_settings *ciaset = calloc(1,sizeof(cia_settings));
	if(!ciaset) {
		fprintf(stderr,"[CIA ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	// Get Settings
	init_CIASettings(ciaset);
	result = get_CIASettings(ciaset,usrset);
	if(result) goto finish;

	// Create Output File
	ciaset->out = fopen(usrset->common.outFileName,"wb");
	if(!ciaset->out){
		fprintf(stderr,"[CIA ERROR] Failed to create \"%s\"\n",usrset->common.outFileName);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}

	// Create CIA Sections

	/* Certificate Chain */
	result = BuildCIA_CertChain(ciaset);
	if(result) goto finish;

	/* Ticket */
	result = BuildTicket(ciaset);
	if(result) goto finish;

	/* Title Metadata */
	result = BuildTMD(ciaset);
	if(result) goto finish;

	/* CIA Header */
	result = BuildCIA_Header(ciaset);
	if(result) goto finish;
	
	/* Write To File */
	result = WriteCIAtoFile(ciaset);
	if(result) goto finish;

finish:
	if(result != FAILED_TO_CREATE_OUTFILE && ciaset->out) 
		fclose(ciaset->out);

	free_CIASettings(ciaset);

	return result;
}

void init_CIASettings(cia_settings *set)
{
	memset(set,0,sizeof(cia_settings));
}

void free_CIASettings(cia_settings *set)
{
	if(set->content.filePtrs){
		for(u32 i = 1; i < set->content.count; i++){
			fclose(set->content.filePtrs[i]);
		}
		free(set->content.filePtrs);
	}
	free(set->ciaSections.certChain.buffer);
	free(set->ciaSections.tik.buffer);
	free(set->ciaSections.tmd.buffer);
	free(set->ciaSections.meta.buffer);
	free(set->ciaSections.content.buffer);

	memset(set,0,sizeof(cia_settings));

	free(set);
}

int get_CIASettings(cia_settings *ciaset, user_settings *usrset)
{
	int result = 0;

	// Transfering data from usrset
	result = GetSettingsFromUsrset(ciaset,usrset);

	if(usrset->common.workingFileType == infile_ncch){
		result = GetSettingsFromNcch0(ciaset,0);
		if(result) 
			return result;
		result = GetContentFilePtrs(ciaset,usrset);
		if(result) 
			return result;
		result = ImportNcchContent(ciaset);
		if(result) 
			return result;
	}

	else if(usrset->common.workingFileType == infile_srl){
		result = GetSettingsFromSrl(ciaset);
		if(result) 
			return result;
	}

	else if(usrset->common.workingFileType == infile_ncsd){
		result = GetSettingsFromCci(ciaset);
		if(result)
			return result;
	}
	
	GetContentHashes(ciaset);

	if(ciaset->content.encryptCia)
		EncryptContent(ciaset);

	return 0;
}

int GetSettingsFromUsrset(cia_settings *ciaset, user_settings *usrset)
{
	// General Stuff
	ciaset->keys = &usrset->common.keys;
	ciaset->ciaSections.content.buffer = usrset->common.workingFile.buffer;
	ciaset->ciaSections.content.size = usrset->common.workingFile.size;
	usrset->common.workingFile.buffer = NULL;
	ciaset->ciaSections.content.size = 0;

	u32_to_u8(ciaset->tmd.titleType,TYPE_CTR,BE);
	ciaset->content.encryptCia = usrset->common.rsfSet.Option.EnableCrypt;
	ciaset->content.IsDlc = usrset->cia.DlcContent;
	if(ciaset->keys->aes.commonKey[ciaset->keys->aes.currentCommonKey] == NULL && ciaset->content.encryptCia){
		fprintf(stderr,"[CIA WARNING] Common Key could not be loaded, CIA will not be encrypted\n");
		ciaset->content.encryptCia = false;
	}
	
	ciaset->cert.caCrlVersion = 0;
	ciaset->cert.signerCrlVersion = 0;

	for(int i = 0; i < 3; i++){
		ciaset->common.titleVersion[i] = usrset->cia.titleVersion[i];
	}

	ciaset->content.overrideSaveDataSize = usrset->cia.overideSaveDataSize;

	// Ticket Data
	u64_to_u8(ciaset->tik.ticketId,u64GetRand(),BE);
	if(usrset->cia.randomTitleKey)
	{
		u64_to_u8(ciaset->common.titleKey,u64GetRand(),BE);
		u64_to_u8((ciaset->common.titleKey+8),u64GetRand(),BE);
	}
	else
		memset(ciaset->common.titleKey,0,16);

	ciaset->tik.formatVersion = 1;

	int result = GenCertChildIssuer(ciaset->tik.issuer,ciaset->keys->certs.xsCert);
	if(result) return result;
	
	// Tmd Stuff
	if(usrset->cia.contentId[0] > 0xffffffff)
		ciaset->content.id[0] = u32GetRand();
	else 
		ciaset->content.id[0] = usrset->cia.contentId[0];

	ciaset->tmd.formatVersion = 1;
	result = GenCertChildIssuer(ciaset->tmd.issuer,ciaset->keys->certs.cpCert);
	return 0;
}

int GetSettingsFromNcch0(cia_settings *ciaset, u32 ncch0_offset)
{
	/* Sanity Checks */
	if(!ciaset->ciaSections.content.buffer) 
		return CIA_NO_NCCH0;

	u8 *ncch0 = (u8*)(ciaset->ciaSections.content.buffer+ncch0_offset);

	if(!IsNCCH(NULL,ncch0)){
		fprintf(stderr,"[CIA ERROR] Content0 is not NCCH\n");
		return CIA_INVALID_NCCH0;
	}

	/* Get Ncch0 Header */
	ncch_hdr *hdr = NULL;
	hdr = GetNCCH_CommonHDR(hdr,NULL,ncch0);
	if(IsCfa(hdr)){
		ciaset->content.IsCfa = true;
	}

	ciaset->content.offset[0] = 0;
	ciaset->content.size[0] = align(GetNCCH_MediaSize(hdr)*GetNCCH_MediaUnitSize(hdr),0x10);
	ciaset->content.totalSize = ciaset->content.size[0];

	/* Get Ncch0 Import Context */
	ncch_struct *ncch_ctx = malloc(sizeof(ncch_struct));
	if(!ncch_ctx){ 
		fprintf(stderr,"[CIA ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	memset(ncch_ctx,0x0,sizeof(ncch_struct));
	GetNCCHStruct(ncch_ctx,hdr);

	/* Verify Ncch0 (Sig&Hash Checks) */
	int result = VerifyNCCH(ncch0,ciaset->keys,false,true);
	if(result == UNABLE_TO_LOAD_NCCH_KEY){
		ciaset->content.keyNotFound = true;
		if(!ciaset->content.IsCfa){
			fprintf(stderr,"[CIA WARNING] CXI AES Key could not be loaded\n");
			fprintf(stderr,"      Meta Region, SaveDataSize, Remaster Version cannot be obtained\n");
		}
	}
	else if(result != 0){
		fprintf(stderr,"[CIA ERROR] Content 0 Is Corrupt (res = %d)\n",result);
		return CIA_INVALID_NCCH0;
	}

	/* Gen Settings From Ncch0 */
	endian_memcpy(ciaset->common.titleId,hdr->titleId,8,LE);


	/* Getting ncch key */
	ncch_key_type keyType = GetNCCHKeyType(hdr);
	u8 *ncchkey = NULL;
	if(!ciaset->content.keyNotFound){
		SetNcchUnfixedKeys(ciaset->keys,ncch0);
		ncchkey = GetNCCHKey(keyType,ciaset->keys);
		if(keyType == KeyIsUnFixed2)
			ncchkey = GetNCCHKey(KeyIsUnFixed,ciaset->keys);
	}

	/* Get TMD Data from ncch */
	result = GetCIADataFromNcch(ciaset,ncch0,ncch_ctx,ncchkey); // Data For TMD
	if(result) goto finish;
	/* Get META Region from ncch */
	result = GetMetaRegion(ciaset,ncch0,ncch_ctx,ncchkey); // Meta Region
	/* Finish */
finish:
	/* Return */
	free(ncch_ctx);
	return result;	
}

int GetCIADataFromNcch(cia_settings *ciaset, u8 *ncch, ncch_struct *ncch_ctx, u8 *key)
{
	extended_hdr *exhdr = malloc(0x400);
	memcpy(exhdr,ncch+ncch_ctx->exhdrOffset,0x400);
	if(key != NULL)
		CryptNCCHSection((u8*)exhdr,0x400,0,ncch_ctx,key,ncch_exhdr);

	u16 Category = u8_to_u16((ciaset->common.titleId+2),BE);
	if(IsPatch(Category)||ciaset->content.IsCfa||ciaset->content.keyNotFound) u32_to_u8(ciaset->tmd.savedataSize,0,LE);
	else u32_to_u8(ciaset->tmd.savedataSize,(u32)GetSaveDataSize_frm_exhdr(exhdr),LE);
	if(ciaset->content.overrideSaveDataSize){
		u64 size = 0;
		GetSaveDataSizeFromString(&size,ciaset->content.overrideSaveDataSize,"CIA");
		u32_to_u8(ciaset->tmd.savedataSize,(u32)size,LE);
	}
	
	if(ciaset->content.IsCfa||ciaset->content.keyNotFound){
		if(ciaset->common.titleVersion[0] == 0xffff){ // '-major' wasn't set
			if(ciaset->content.IsCfa){ // Is a CFA and can be decrypted
				fprintf(stderr,"[CIA ERROR] Invalid major version. Use \"-major\" option.\n");
				return CIA_BAD_VERSION;
			}
			else // CXI which cannot be decrypted
				ciaset->common.titleVersion[0] = 0;
		}
	}
	else{ // Is a CXI and can be decrypted
		if(ciaset->common.titleVersion[0] != 0xffff){ // '-major' was set
			fprintf(stderr,"[CIA ERROR] Option \"-major\" cannot be applied for cxi.\n");
			return CIA_BAD_VERSION;
		}
		// Setting remaster ver
		ciaset->common.titleVersion[0] = GetRemasterVersion_frm_exhdr(exhdr);
	}

	u16 version = SetupVersion(ciaset->common.titleVersion[0],ciaset->common.titleVersion[1],ciaset->common.titleVersion[2]);
	ciaset->tik.version = version;
	ciaset->tmd.version = version;

	free(exhdr);
	return 0;
}

int GetMetaRegion(cia_settings *ciaset, u8 *ncch, ncch_struct *ncch_ctx, u8 *key)
{
	if(ciaset->content.IsCfa || ciaset->content.keyNotFound) 
		return 0;

	extended_hdr *exhdr = malloc(0x400);
	memcpy(exhdr,ncch+ncch_ctx->exhdrOffset,0x400);
	if(key != NULL)
		CryptNCCHSection((u8*)exhdr,0x400,0,ncch_ctx,key,ncch_exhdr);

	exefs_hdr *exefsHdr = malloc(sizeof(exefs_hdr));
	memcpy(exefsHdr,ncch+ncch_ctx->exefsOffset,sizeof(exefs_hdr));
	if(key != NULL)
		CryptNCCHSection((u8*)exefsHdr,sizeof(exefs_hdr),0,ncch_ctx,key,ncch_exefs);

	u32 icon_size = 0;
	u32 icon_offset = 0;
	for(int i = 0; i < MAX_EXEFS_SECTIONS; i++){
		if(strncmp(exefsHdr->fileHdr[i].name,"icon",8) == 0){
			icon_size = u8_to_u32(exefsHdr->fileHdr[i].size,LE);
			icon_offset = u8_to_u32(exefsHdr->fileHdr[i].offset,LE) + 0x200;
		}
	}

	ciaset->ciaSections.meta.size = sizeof(cia_metadata) + icon_size;
	ciaset->ciaSections.meta.buffer = malloc(ciaset->ciaSections.meta.size);
	if(!ciaset->ciaSections.meta.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR; 
	}
	cia_metadata *hdr = (cia_metadata*)ciaset->ciaSections.meta.buffer;
	memset(hdr,0,sizeof(cia_metadata));
	GetDependencyList_frm_exhdr(hdr->dependencyList,exhdr);
	GetCoreVersion_frm_exhdr(hdr->coreVersion,exhdr);
	if(icon_size > 0){
		u8 *IconDestPos = (ciaset->ciaSections.meta.buffer + sizeof(cia_metadata));
		memcpy(IconDestPos,ncch+ncch_ctx->exefsOffset+icon_offset,icon_size);
		if(key != NULL)
			CryptNCCHSection(IconDestPos,icon_size,icon_offset,ncch_ctx,key,ncch_exefs);
		//memdump(stdout,"Icon: ",IconDestPos,0x10);
	}

	free(exefsHdr);
	free(exhdr);
	return 0;
}

int GetContentFilePtrs(cia_settings *ciaset, user_settings *usrset)
{
	ciaset->content.filePtrs = malloc(sizeof(FILE*)*CIA_MAX_CONTENT);
	if(!ciaset->content.filePtrs){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	memset(ciaset->content.filePtrs,0,sizeof(FILE*)*CIA_MAX_CONTENT);
	int j = 1;
	ncch_hdr *hdr = malloc(sizeof(ncch_hdr));
	for(int i = 1; i < CIA_MAX_CONTENT; i++){
		if(usrset->common.contentPath[i]){
			if(!AssertFile(usrset->common.contentPath[i])){ 
				fprintf(stderr,"[CIA ERROR] Failed to open \"%s\"\n",usrset->common.contentPath[i]); 
				return FAILED_TO_OPEN_FILE; 
			}
			ciaset->content.fileSize[j] = GetFileSize_u64(usrset->common.contentPath[i]);
			ciaset->content.filePtrs[j] = fopen(usrset->common.contentPath[i],"rb");
			
			if(usrset->cia.contentId[i] == 0x100000000)
				ciaset->content.id[j] = u32GetRand(); 
			else 
				ciaset->content.id[j] = (u32)usrset->cia.contentId[i];

			ciaset->content.index[j] = (u16)i;

			// Get Data from ncch HDR
			GetNCCH_CommonHDR(hdr,ciaset->content.filePtrs[j],NULL);
			
			// Get Size
			u64 calcSize = (u64)GetNCCH_MediaSize(hdr) * (u64)GetNCCH_MediaUnitSize(hdr);
			if(calcSize != ciaset->content.fileSize[j]){
				fprintf(stderr,"[CIA ERROR] \"%s\" is corrupt\n",usrset->common.contentPath[i]); 
				return FAILED_TO_OPEN_FILE; 
			}

			ciaset->content.size[j] = align(calcSize,0x10);
			ciaset->content.offset[j] = ciaset->content.totalSize;
			
			ciaset->content.totalSize += ciaset->content.size[j];
			

			// Finish get next content
			j++;
		}
	}
	free(hdr);
	ciaset->content.count = j;

	// Check Conflicting IDs
	for(int i = 0; i < ciaset->content.count; i++){
		for(j = i+1; j < ciaset->content.count; j++){
			if(ciaset->content.id[j] == ciaset->content.id[i]){
				fprintf(stderr,"[CIA ERROR] CIA Content %d and %d, have conflicting IDs\n",ciaset->content.index[j],ciaset->content.index[i]);
				return CIA_CONFILCTING_CONTENT_IDS;
			}
		}
	}
	return 0;
}

int ImportNcchContent(cia_settings *ciaset)
{
	ciaset->ciaSections.content.buffer = realloc(ciaset->ciaSections.content.buffer,ciaset->content.totalSize);
	if(!ciaset->ciaSections.content.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	ncch_hdr *ncch0hdr = (ncch_hdr*)(ciaset->ciaSections.content.buffer+0x100);
	for(int i = 1; i < ciaset->content.count; i++){
		// Import
		u8 *ncchpos = (u8*)(ciaset->ciaSections.content.buffer+ciaset->content.offset[i]);

		ReadFile_64(ncchpos, ciaset->content.fileSize[i], 0, ciaset->content.filePtrs[i]);
		if(ModifyNcchIds(ncchpos, NULL, ncch0hdr->programId, ciaset->keys) != 0)
			return -1;
		
		// Set Additional Flags
		if(ciaset->content.IsDlc)
			ciaset->content.flags[i] |= content_Optional;

		//if(unknown condition)
		//	ciaset->content.flags[i] |= content_Shared;
	}

	ciaset->ciaSections.content.size = ciaset->content.totalSize;
	return 0;
}

int GetSettingsFromSrl(cia_settings *ciaset)
{
	srl_hdr *hdr = (srl_hdr*)ciaset->ciaSections.content.buffer;
	if(!hdr || ciaset->ciaSections.content.size < sizeof(srl_hdr)) {
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	// Check if TWL SRL File
	if(u8_to_u16(&hdr->title_id[6],LE) != 0x0003){
		fprintf(stderr,"[CIA ERROR] Invalid TWL SRL File\n");
		return FAILED_TO_IMPORT_FILE;
	}

	// Generate and store Converted TitleID
	u64_to_u8(ciaset->common.titleId,ConvertTwlIdToCtrId(u8_to_u64(hdr->title_id,LE)),BE);
	//memdump(stdout,"SRL TID: ",ciaset->TitleID,8);

	// Get TWL Flag
	ciaset->tmd.twlFlag = ((hdr->reserved_flags[3] & 6) >> 1);

	// Get Remaster Version
	u16 version = SetupVersion(hdr->romVersion,ciaset->common.titleVersion[1],0);
	ciaset->tik.version = version;
	ciaset->tmd.version = version;

	// Get SaveDataSize (Public and Private)
	memcpy(ciaset->tmd.savedataSize,hdr->pubSaveDataSize,4);
	memcpy(ciaset->tmd.privSavedataSize,hdr->privSaveDataSize,4);

	// Setting CIA Content Settings
	ciaset->content.count = 1;
	ciaset->content.offset[0] = 0;
	ciaset->content.size[0] = ciaset->ciaSections.content.size;
	ciaset->content.totalSize = ciaset->ciaSections.content.size;

	return 0;
}

int GetSettingsFromCci(cia_settings *ciaset)
{
	int result = 0;

	if(!IsCci(ciaset->ciaSections.content.buffer)){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file\n");
		return FAILED_TO_IMPORT_FILE;
	}
	
	u32 ncch0_offset = GetPartitionOffset(ciaset->ciaSections.content.buffer,0);
	if(!ncch0_offset){
		fprintf(stderr,"[CIA ERROR] Invalid CCI file (invalid ncch0)\n");
		return FAILED_TO_IMPORT_FILE;
	}

	result = GetSettingsFromNcch0(ciaset, ncch0_offset);
	if(result){
		fprintf(stderr,"Import of Ncch 0 failed(%d)\n",result);	
		return result;
	}
	int j = 1;
	
	u64 cciContentOffsets[CCI_MAX_CONTENT];
	cciContentOffsets[0] = ncch0_offset;
	ncch_hdr *hdr;
	for(int i = 1; i < 8; i++){
		if(GetPartitionSize(ciaset->ciaSections.content.buffer,i)){
			cciContentOffsets[j] = GetPartitionOffset(ciaset->ciaSections.content.buffer,i);

			// Get Data from ncch HDR
			GetNCCH_CommonHDR(hdr,NULL,GetPartition(ciaset->ciaSections.content.buffer,i));
			hdr = (ncch_hdr*)(ciaset->ciaSections.content.buffer + cciContentOffsets[j] + 0x100);
			
			// Get Size
			ciaset->content.size[j] =  GetPartitionSize(ciaset->ciaSections.content.buffer,i);
			ciaset->content.offset[j] = ciaset->content.totalSize;
			
			ciaset->content.totalSize += ciaset->content.size[j];
			
			// Get ID
			u8 hash[0x20];
			ctr_sha((u8*)hdr,0x200,hash,CTR_SHA_256);
			ciaset->content.id[j] = u8_to_u32(hash,BE);

			// Get Index
			ciaset->content.index[j] = i;

			// Increment Content Count
			j++;
		}
	}
	ciaset->content.count = j;

	for(int i = 0; i < ciaset->content.count; i++){ // Re-organising content positions in memory
		u8 *cci_pos = (ciaset->ciaSections.content.buffer + cciContentOffsets[i]);
		u8 *cia_pos = (ciaset->ciaSections.content.buffer + ciaset->content.offset[i]);
		memcpy(cia_pos,cci_pos,ciaset->content.size[i]);
	}
	ciaset->ciaSections.content.size = ciaset->content.totalSize;
	return 0;
}

u16 SetupVersion(u16 Major, u16 Minor, u16 Micro)
{
	return (((Major << 10) & 0xFC00) | ((Minor << 4) & 0x3F0) | (Micro & 0xf));
}

void GetContentHashes(cia_settings *ciaset)
{
	for(int i = 0; i < ciaset->content.count; i++)
		ctr_sha(ciaset->ciaSections.content.buffer+ciaset->content.offset[i],ciaset->content.size[i],ciaset->content.hash[i],CTR_SHA_256);
}

void EncryptContent(cia_settings *ciaset)
{
	for(int i = 0; i < ciaset->content.count; i++){
		ciaset->content.flags[i] |= content_Encrypted;
		u8 *content = ciaset->ciaSections.content.buffer+ciaset->content.offset[i];
		CryptContent(content, content, ciaset->content.size[i], ciaset->common.titleKey, i, ENC);
	}
}

int BuildCIA_CertChain(cia_settings *ciaset)
{
	ciaset->ciaSections.certChain.size = GetCertSize(ciaset->keys->certs.caCert) + GetCertSize(ciaset->keys->certs.xsCert) + GetCertSize(ciaset->keys->certs.cpCert);
	ciaset->ciaSections.certChain.buffer = malloc(ciaset->ciaSections.certChain.size);
	if(!ciaset->ciaSections.certChain.buffer) {
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR; 
	}
	memcpy(ciaset->ciaSections.certChain.buffer,ciaset->keys->certs.caCert,GetCertSize(ciaset->keys->certs.caCert));
	memcpy((ciaset->ciaSections.certChain.buffer+GetCertSize(ciaset->keys->certs.caCert)),ciaset->keys->certs.xsCert,GetCertSize(ciaset->keys->certs.xsCert));
	memcpy((ciaset->ciaSections.certChain.buffer+GetCertSize(ciaset->keys->certs.caCert)+GetCertSize(ciaset->keys->certs.xsCert)),ciaset->keys->certs.cpCert,GetCertSize(ciaset->keys->certs.cpCert));
	return 0;
}

int BuildCIA_Header(cia_settings *ciaset)
{
	// Allocating memory for header
	ciaset->ciaSections.ciaHdr.size = sizeof(cia_hdr);
	ciaset->ciaSections.ciaHdr.buffer = malloc(ciaset->ciaSections.ciaHdr.size);
	if(!ciaset->ciaSections.ciaHdr.buffer){
		fprintf(stderr,"[CIA ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	cia_hdr *hdr = (cia_hdr*)ciaset->ciaSections.ciaHdr.buffer;

	// Clearing 
	memset(hdr,0,sizeof(cia_hdr));

	// Setting Data
	u32_to_u8(hdr->hdrSize,sizeof(cia_hdr),LE);
	u16_to_u8(hdr->type,0x0,LE);
	u16_to_u8(hdr->version,0x0,LE);
	u32_to_u8(hdr->certChainSize,ciaset->ciaSections.certChain.size,LE);
	u32_to_u8(hdr->tikSize,ciaset->ciaSections.tik.size,LE);
	u32_to_u8(hdr->tmdSize,ciaset->ciaSections.tmd.size,LE);
	u32_to_u8(hdr->metaSize,ciaset->ciaSections.meta.size,LE);
	u64_to_u8(hdr->contentSize,ciaset->content.totalSize,LE);

	// Recording Offsets
	ciaset->ciaSections.certChainOffset = align(sizeof(cia_hdr),0x40);
	ciaset->ciaSections.tikOffset = align(ciaset->ciaSections.certChainOffset+ciaset->ciaSections.certChain.size,0x40);
	ciaset->ciaSections.tmdOffset = align(ciaset->ciaSections.tikOffset+ciaset->ciaSections.tik.size,0x40);
	ciaset->ciaSections.contentOffset = align(ciaset->ciaSections.tmdOffset+ciaset->ciaSections.tmd.size,0x40);
	ciaset->ciaSections.metaOffset = align(ciaset->ciaSections.contentOffset+ciaset->content.totalSize,0x40);
	
	for(int i = 0; i < ciaset->content.count; i++){
		// This works by treating the 0x2000 byte index array as an array of 2048 u32 values
		
		// Used for determining which u32 chunk to write the value to
		u16 section = ciaset->content.index[i]/32;
		
		// Calculating the value added to the u32
		u32 value = 1 << (0x1F-ciaset->content.index[i]);

		// Retrieving current u32 block
		u32 cur_content_index_section = u8_to_u32(hdr->contentIndex+(sizeof(u32)*section),BE);
		
		// Adding value to block
		cur_content_index_section += value;
		
		// Returning block
		u32_to_u8(hdr->contentIndex+(sizeof(u32)*section),cur_content_index_section,BE);
	}
	return 0;
}

int WriteCIAtoFile(cia_settings *ciaset)
{
	WriteBuffer(ciaset->ciaSections.ciaHdr.buffer,ciaset->ciaSections.ciaHdr.size,0,ciaset->out);
	WriteBuffer(ciaset->ciaSections.certChain.buffer,ciaset->ciaSections.certChain.size,ciaset->ciaSections.certChainOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.tik.buffer,ciaset->ciaSections.tik.size,ciaset->ciaSections.tikOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.tmd.buffer,ciaset->ciaSections.tmd.size,ciaset->ciaSections.tmdOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.content.buffer,ciaset->ciaSections.content.size,ciaset->ciaSections.contentOffset,ciaset->out);
	WriteBuffer(ciaset->ciaSections.meta.buffer,ciaset->ciaSections.meta.size,ciaset->ciaSections.metaOffset,ciaset->out);
	return 0;
}


int CryptContent(u8 *EncBuffer,u8 *DecBuffer,u64 size,u8 *title_key, u16 index, u8 mode)
{
	//generating IV
	u8 iv[16];
	memset(&iv,0x0,16);
	iv[0] = (index >> 8) & 0xff;
	iv[1] = index & 0xff;
	//Crypting content
	ctr_aes_context ctx;
	memset(&ctx,0x0,sizeof(ctr_aes_context));
	ctr_init_aes_cbc(&ctx,title_key,iv,mode);
	if(mode == ENC) ctr_aes_cbc(&ctx,DecBuffer,EncBuffer,size,ENC);
	else ctr_aes_cbc(&ctx,EncBuffer,DecBuffer,size,DEC);
	return 0;
}