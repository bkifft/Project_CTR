#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "ncsd.h"
#include "cia.h"
#include "tmd.h"

// Private Prototypes

/* RSA Crypto */
int SignCCI(u8 *Signature, u8 *NCSD_HDR, keys_struct *keys);
int CheckCCISignature(u8 *Signature, u8 *NCSD_HDR, keys_struct *keys);

/* cci_settings tools */
void init_CCISettings(cci_settings *set);
int get_CCISettings(cci_settings *cciset, user_settings *usrset);
void free_CCISettings(cci_settings *set);

/* CCI Data Gen/Write */
int BuildCCIHeader(cci_settings *cciset, user_settings *usrset);
int BuildCardInfoHeader(cci_settings *cciset, user_settings *usrset);
int WriteHeaderToFile(cci_settings *cciset);
int WriteContentToFile(cci_settings *cciset,user_settings *usrset);
int WriteDummyBytes(cci_settings *cciset);

/* Get Data from Content Files */
int CheckContent0(cci_settings *cciset, user_settings *usrset);
int GetDataFromContent0(cci_settings *cciset, user_settings *usrset);
int GetContentFP(cci_settings *cciset, user_settings *usrset);
int ImportNcchPartitions(cci_settings *cciset);
int ImportCverDetails(cci_settings *cciset, user_settings *usrset);

/* Get Data from YAML Settings */
int GetNCSDFlags(cci_settings *cciset, rsf_settings *yaml);
int GetMediaSize(cci_settings *cciset, user_settings *usrset);
u64 GetUnusedSize(u64 MediaSize, u8 CardType);
int GetWriteableAddress(cci_settings *cciset, user_settings *usrset);
int GetCardInfoBitmask(cci_settings *cciset, user_settings *usrset);

int CheckMediaSize(cci_settings *cciset);

static InternalCCI_Context ctx;
const int NCCH0_OFFSET = 0x4000;

// Code
int build_CCI(user_settings *usrset)
{
	int result = 0;

	// Init Settings
	cci_settings *cciset = calloc(1,sizeof(cci_settings));
	if(!cciset) {
		fprintf(stderr,"[CCI ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}
	init_CCISettings(cciset);
	
	// Get Settings
	result = get_CCISettings(cciset,usrset);
	if(result) goto finish;

	// Import Content
	result = ImportNcchPartitions(cciset);
	if(result) goto finish;

	// Create Output File
	cciset->out = fopen(usrset->common.outFileName,"wb");
	if(!cciset->out){
		fprintf(stderr,"[CCI ERROR] Failed to create '%s'\n",usrset->common.outFileName);
		result = FAILED_TO_CREATE_OUTFILE;
		goto finish;
	}

	// Generate NCSD Header and Additional Header
	result = BuildCCIHeader(cciset,usrset);
	if(result) goto finish;
	BuildCardInfoHeader(cciset,usrset);
	
	// Write to File
	WriteHeaderToFile(cciset);
	result = WriteContentToFile(cciset,usrset);
	if(result) 
		goto finish;
	
	// Fill out file if necessary 
	if(cciset->option.fillOutCci) 
		WriteDummyBytes(cciset);
	
	// Close output file
finish:
	if(result != FAILED_TO_CREATE_OUTFILE && cciset->out) fclose(cciset->out);
	free_CCISettings(cciset);
	return result;
}


int SignCCI(u8 *Signature, u8 *NCSD_HDR, keys_struct *keys)
{
	return ctr_sig(NCSD_HDR,sizeof(cci_hdr),Signature,keys->rsa.cciCfaPub,keys->rsa.cciCfaPvt,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int CheckCCISignature(u8 *Signature, u8 *NCSD_HDR, keys_struct *keys)
{
	return ctr_sig(NCSD_HDR,sizeof(cci_hdr),Signature,keys->rsa.cciCfaPub,NULL,RSA_2048_SHA256,CTR_RSA_VERIFY);
}

void init_CCISettings(cci_settings *set)
{
	memset(set,0,sizeof(cci_settings));
	memset(&ctx,0,sizeof(InternalCCI_Context));
}

int get_CCISettings(cci_settings *cciset, user_settings *usrset)
{
	cciset->keys = &usrset->common.keys;
	int result = 0;

	/* Importing Data from Content */
	result = CheckContent0(cciset,usrset);
	if(result) return result;

	result = GetDataFromContent0(cciset,usrset);
	if(result) return result;

	result = GetContentFP(cciset,usrset);
	if(result) return result;
	

	/* Getting Data from YAML */
	result = GetNCSDFlags(cciset,&usrset->common.rsfSet);
	if(result) return result;

	result = GetMediaSize(cciset,usrset);
	if(result) return result;

	result = CheckMediaSize(cciset);
	if(result) return result;

	/** Card Info Header Data **/
	result = GetWriteableAddress(cciset,usrset);
	if(result) return result;

	result = GetCardInfoBitmask(cciset,usrset);
	if(result) return result;
	
	result = ImportCverDetails(cciset,usrset);
	if(result) return result;

	/* All Done */
	return 0;
}

void free_CCISettings(cci_settings *set)
{
	if(set->content.filePtrs){
		for(int i = 1; i < 8; i++) {
			if(set->content.filePtrs[i]) fclose(set->content.filePtrs[i]);
		}
		free(set->content.filePtrs);
	}
	free(set);
}

int BuildCCIHeader(cci_settings *cciset, user_settings *usrset)
{
	memcpy((u8*)ctx.cciHdr.magic,"NCSD",4);
	u32_to_u8((u8*)ctx.cciHdr.mediaSize,(cciset->header.mediaSize/cciset->option.mediaUnit),LE); 
	memcpy((u8*)ctx.cciHdr.titleId,cciset->header.mediaId,8);
	memcpy((u8*)ctx.cciHdr.flags,cciset->header.flags,8);

	// Content
	for(int i = 0; i < 8; i++){
		u32_to_u8((u8*)ctx.cciHdr.offset_sizeTable[i].offset,(cciset->content.offset[i]/cciset->option.mediaUnit),LE);
		u32_to_u8((u8*)ctx.cciHdr.offset_sizeTable[i].size,(cciset->content.size[i]/cciset->option.mediaUnit),LE);
		memcpy((u8*)ctx.cciHdr.contentIdTable[i],cciset->content.titleId[i],8);
		ctx.cciHdr.contentFsType[i] = cciset->content.fsType[i];
		ctx.cciHdr.contentCryptoType[i] = cciset->content.cryptoType[i];
	}
	
	// Signature
	if(SignCCI(ctx.signature,(u8*)&ctx.cciHdr,cciset->keys) != Good){
		fprintf(stderr,"[CCI ERROR] Failed to sign CCI\n");
		return CCI_SIG_FAIL;
	}
	return 0;
}

int BuildCardInfoHeader(cci_settings *cciset, user_settings *usrset)
{
	u32_to_u8((u8*)ctx.cardinfo.writableAddress,(cciset->cardinfo.writableAddress/cciset->option.mediaUnit),LE); 
	u32_to_u8((u8*)ctx.cardinfo.cardInfoBitmask,cciset->cardinfo.cardInfoBitmask,BE);
	u32_to_u8((u8*)ctx.cardinfo.mediaSizeUsed,cciset->cardinfo.cciTotalSize,LE);
	memcpy(ctx.cardinfo.cverTitleId,cciset->cardinfo.cverTitleId,8);
	memcpy(ctx.cardinfo.cverTitleVersion,cciset->cardinfo.cverTitleVersion,2);
	memcpy((u8*)ctx.cardinfo.ncch0TitleId,cciset->content.titleId[0],8);
	memcpy((u8*)ctx.cardinfo.initialData,cciset->cardinfo.initialData,0x30);
	memcpy((u8*)ctx.cardinfo.ncch0Hdr,&cciset->cardinfo.ncchHdr,0x100);
	memcpy((u8*)ctx.devcardinfo.titleKey,cciset->cardinfo.titleKey,0x10);

	return 0;
}

int ImportNcchPartitions(cci_settings *cciset)
{
	cciset->content.data->buffer = realloc(cciset->content.data->buffer,cciset->content.data->size);
	if(!cciset->content.data->buffer){
		fprintf(stderr,"[CCI ERROR] Not enough memory\n");
		return MEM_ERROR;
	}

	ncch_hdr *ncch0hdr = (ncch_hdr*)(cciset->content.data->buffer+0x100);
	for(int i = 1; i < CCI_MAX_CONTENT; i++){
		if(!cciset->content.size[i])
			continue;

		u8 *ncchpos = (u8*)(cciset->content.data->buffer+cciset->content.offset[i]-cciset->content.offset[0]);

		ReadFile_64(ncchpos, cciset->content.fileSize[i], 0, cciset->content.filePtrs[i]);
		if(ModifyNcchIds(ncchpos, cciset->content.titleId[i], ncch0hdr->programId, cciset->keys) != 0)
			return -1;
	}
	return 0;
}

int WriteHeaderToFile(cci_settings *cciset)
{
	WriteBuffer(ctx.signature,0x100,0,cciset->out);
	WriteBuffer((u8*)&ctx.cciHdr,sizeof(cci_hdr),0x100,cciset->out);
	WriteBuffer((u8*)&ctx.cardinfo,sizeof(cardinfo_hdr),0x200,cciset->out);
	if(!cciset->option.useDevCardInfo){
		// Creating Buffer of Dummy Bytes
		u64 len = NCCH0_OFFSET - 0x1200;
		u8 *dummy_bytes = malloc(len);
		memset(dummy_bytes,0xff,len);
		WriteBuffer(dummy_bytes,len,0x1200,cciset->out);
	}
	else
		WriteBuffer((u8*)&ctx.devcardinfo,sizeof(devcardinfo_hdr),0x1200,cciset->out);
	return 0;
}

int WriteContentToFile(cci_settings *cciset,user_settings *usrset)
{
	// Write Content 0
	WriteBuffer(cciset->content.data->buffer,cciset->content.data->size,NCCH0_OFFSET,cciset->out);
	free(cciset->content.data->buffer);
	cciset->content.data->buffer = NULL;
	cciset->content.data->size = 0;
	return 0;
}

int WriteDummyBytes(cci_settings *cciset)
{
	// Seeking end of CCI Data
	fseek_64(cciset->out,cciset->cardinfo.cciTotalSize);

	// Determining Size of Dummy Bytes
	u64 len = cciset->header.mediaSize - cciset->cardinfo.cciTotalSize;
	
	// Creating Buffer of Dummy Bytes
	u8 *dummy_bytes = malloc(cciset->option.mediaUnit);
	memset(dummy_bytes,0xff,cciset->option.mediaUnit);
	
	// Writing Dummy Bytes to file
	for(u64 i = 0; i < len; i += cciset->option.mediaUnit)
		fwrite(dummy_bytes,cciset->option.mediaUnit,1,cciset->out);
	
	return 0;
}

int GetContentFP(cci_settings *cciset, user_settings *usrset)
{
	cciset->content.filePtrs = calloc(8,sizeof(FILE*));
	if(!cciset->content.filePtrs){
		fprintf(stderr,"[CCI ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	
	for(int i = 1; i < 8; i++){
		if(usrset->common.contentPath[i]){
			if(!AssertFile(usrset->common.contentPath[i])){ // Checking if file could be opened
				fprintf(stderr,"[CCI ERROR] Failed to open '%s'\n",usrset->common.contentPath[i]);
				return FAILED_TO_OPEN_FILE;
			}

			cciset->content.fileSize[i] = GetFileSize_u64(usrset->common.contentPath[i]);
			cciset->content.filePtrs[i] = fopen(usrset->common.contentPath[i],"rb");
			/*
			if(!cciset->content.filePtrs[i]){ // Checking if file could be opened
				fprintf(stderr,"[CCI ERROR] Failed to open '%s'\n",usrset->common.contentPath[i]);
				return FAILED_TO_OPEN_FILE;
			}
			*/
			if(!IsNCCH(cciset->content.filePtrs[i],NULL)){ // Checking if NCCH
				fprintf(stderr,"[CCI ERROR] Content '%s' is invalid\n",usrset->common.contentPath[i]);
				return NCSD_INVALID_NCCH;
			}
			
			// Getting NCCH Header
			ncch_hdr *hdr = malloc(sizeof(ncch_hdr));
			GetNCCH_CommonHDR(hdr,cciset->content.filePtrs[i],NULL);
			
			if(usrset->cci.dontModifyNcchTitleID)
				memcpy(&cciset->content.titleId[i], hdr->titleId, 8);
			else{
				memcpy(&cciset->content.titleId[i], cciset->header.mediaId, 8); // Set TitleID			
				u16_to_u8(&cciset->content.titleId[i][6], (i+4), LE);
			}

			u64 contentSize = (u64)GetNCCH_MediaSize(hdr)* (u64)GetNCCH_MediaUnitSize(hdr);
			if(contentSize != cciset->content.fileSize[i]){
				fprintf(stderr,"[CCI ERROR] Content '%s' is corrupt\n",usrset->common.contentPath[i]);
				return NCSD_INVALID_NCCH;
			}

			cciset->content.size[i] =  align(contentSize,cciset->option.mediaUnit);
			cciset->content.offset[i] = cciset->cardinfo.cciTotalSize;
			
			cciset->content.data->size += cciset->content.size[i];
			cciset->cardinfo.cciTotalSize += cciset->content.size[i];
			
			free(hdr);
		}
	}
	return 0;
}

int CheckContent0(cci_settings *cciset, user_settings *usrset)
{
	if(!usrset->common.workingFile.buffer || !usrset->common.workingFile.size) 
		return NCSD_NO_NCCH0;
	cciset->content.data = &usrset->common.workingFile;
	
	if(!IsNCCH(NULL,cciset->content.data->buffer)) 
		return NCSD_INVALID_NCCH0;
	
	return 0;
}

int GetDataFromContent0(cci_settings *cciset, user_settings *usrset)
{	
	cciset->cardinfo.cciTotalSize = NCCH0_OFFSET; 
	ncch_hdr *hdr;
	
	hdr = GetNCCH_CommonHDR(NULL,NULL,cciset->content.data->buffer);
	
	memcpy(&cciset->cardinfo.ncchHdr,hdr,sizeof(ncch_hdr));
	
	u16 ncch_format_ver = u8_to_u16(hdr->formatVersion,LE);
	if(ncch_format_ver > 2){
		fprintf(stderr,"[CCI ERROR] NCCH type %d not supported\n",ncch_format_ver);
		return FAILED_TO_IMPORT_FILE;
	}

	//memdump(stdout,"ncch0 head: ",(cciset->ncch0+0x100),0x100);
	//memdump(stdout,"ncch0 head: ",(u8*)(hdr),0x100);
	
	memcpy(cciset->header.mediaId,hdr->titleId,8);
	memcpy(&cciset->content.titleId[0],hdr->titleId,8);
#ifndef PUBLIC_BUILD
	if(usrset->cci.useSDKStockData){
		memcpy(cciset->cardinfo.initialData,stock_initial_data,0x30);
		memcpy(cciset->cardinfo.titleKey,stock_title_key,0x10);
		cciset->option.useDevCardInfo = true;
	}
	else{
		for(int i = 0; i < 0x2c/sizeof(u32); i++)
		{
			u32 val = u32GetRand();
			memcpy((cciset->cardinfo.initialData+i*sizeof(u32)),&val,4);
		}
		/*
		for(int i = 0; i < 2; i++)
		{
			u64 val = u64GetRand();
			memcpy((cciset->cardinfo.titleKey+i*8),&val,8);
		}
		cciset->option.useDevCardInfo = true;
		*/
	}
#else
	for(int i = 0; i < 0x2c/sizeof(u32); i++)
	{
		u32 val = u32GetRand();
		memcpy((cciset->cardinfo.initialData+i*sizeof(u32)),&val,4);
	}
#endif
	
	cciset->header.flags[MediaUnitSize] = hdr->flags[ContentUnitSize];
	cciset->option.mediaUnit = GetNCCH_MediaUnitSize(hdr);
	
	cciset->content.size[0] = (u64)(GetNCCH_MediaSize(hdr) * cciset->option.mediaUnit);
	cciset->content.offset[0] = cciset->cardinfo.cciTotalSize;
	
	cciset->content.data->size = cciset->content.size[0];
	cciset->cardinfo.cciTotalSize += cciset->content.size[0];
	return 0;
}

int GetMediaSize(cci_settings *cciset, user_settings *usrset)
{
	char *mediaSizeStr = usrset->common.rsfSet.CardInfo.MediaSize;
	if(!mediaSizeStr) cciset->header.mediaSize = (u64)GB*2;
	else{
		if(strcasecmp(mediaSizeStr,"128MB") == 0) cciset->header.mediaSize = (u64)MB*128;
		else if(strcasecmp(mediaSizeStr,"256MB") == 0) cciset->header.mediaSize = (u64)MB*256;
		else if(strcasecmp(mediaSizeStr,"512MB") == 0) cciset->header.mediaSize = (u64)MB*512;
		else if(strcasecmp(mediaSizeStr,"1GB") == 0) cciset->header.mediaSize = (u64)GB*1;
		else if(strcasecmp(mediaSizeStr,"2GB") == 0) cciset->header.mediaSize = (u64)GB*2;
		else if(strcasecmp(mediaSizeStr,"4GB") == 0) cciset->header.mediaSize = (u64)GB*4;
		else if(strcasecmp(mediaSizeStr,"8GB") == 0) cciset->header.mediaSize = (u64)GB*8;
		else if(strcasecmp(mediaSizeStr,"16GB") == 0) cciset->header.mediaSize = (u64)GB*16;
		else if(strcasecmp(mediaSizeStr,"32GB") == 0) cciset->header.mediaSize = (u64)GB*32;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaSize: %s\n",mediaSizeStr);
			return INVALID_YAML_OPT;
		}
	}
	
	cciset->option.fillOutCci = usrset->common.rsfSet.Option.MediaFootPadding;
	
	return 0;
}

u64 GetUnusedSize(u64 MediaSize, u8 CardType)
{
	if(CardType == CARD1){
		switch(MediaSize){
			case (u64)MB*128: return (u64)2621440;
			case (u64)MB*256: return (u64)5242880;
			case (u64)MB*512: return (u64)10485760;
			case (u64)GB*1: return (u64)73924608;
			case (u64)GB*2: return (u64)147324928;
			case (u64)GB*4: return (u64)294649856;
			case (u64)GB*8: return (u64)587202560;
			default: return (u64)((MediaSize/MB)*0x11800); // Aprox
		}
	}
	else if(CardType == CARD2){
		switch(MediaSize){
			case (u64)MB*512: return (u64)37224448;
			case (u64)GB*1: return (u64)73924608;
			case (u64)GB*2: return (u64)147324928;
			case (u64)GB*4: return (u64)294649856;
			case (u64)GB*8: return (u64)587202560;
			default: return (u64)((MediaSize/MB)*0x11800); // Aprox
		}
	}
	return 0;
}

int GetNCSDFlags(cci_settings *cciset, rsf_settings *yaml)
{
	/* BackupWriteWaitTime */
	cciset->header.flags[FW6x_BackupWriteWaitTime] = 0;
	if(yaml->CardInfo.BackupWriteWaitTime){
		u32 WaitTime = strtoul(yaml->CardInfo.BackupWriteWaitTime,NULL,0);
		if(WaitTime > 255){
			fprintf(stderr,"[CCI ERROR] Invalid Card BackupWriteWaitTime (%d) : must 0-255\n",WaitTime);
			return EXHDR_BAD_YAML_OPT;
		}
		cciset->header.flags[FW6x_BackupWriteWaitTime] = (u8)WaitTime;
	}

	/* MediaType */
	if(!yaml->CardInfo.MediaType) cciset->header.flags[MediaTypeIndex] = CARD1;
	else{
		if(strcasecmp(yaml->CardInfo.MediaType,"Card1") == 0) cciset->header.flags[MediaTypeIndex] = CARD1;
		else if(strcasecmp(yaml->CardInfo.MediaType,"Card2") == 0) cciset->header.flags[MediaTypeIndex] = CARD2;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid MediaType: %s\n",yaml->CardInfo.MediaType);
			return INVALID_YAML_OPT;
		}
	}

	/* Platform */
	cciset->header.flags[MediaPlatformIndex] = CTR;

	u8 saveCrypto;

	if(!yaml->CardInfo.SaveCrypto) saveCrypto = 3;
	else{
		if(strcasecmp(yaml->CardInfo.SaveCrypto,"fw1") == 0 || strcasecmp(yaml->CardInfo.SaveCrypto,"ctr fail") == 0 ) saveCrypto = 1;
		else if(strcasecmp(yaml->CardInfo.SaveCrypto,"fw2") == 0) saveCrypto = 2;
		else if(strcasecmp(yaml->CardInfo.SaveCrypto,"fw3") == 0) saveCrypto = 3;
		else if(strcasecmp(yaml->CardInfo.SaveCrypto,"fw6") == 0) saveCrypto = 6;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid SaveCrypto: %s\n",yaml->CardInfo.SaveCrypto);
			return INVALID_YAML_OPT;
		}
	}
	

	/* FW6x SaveCrypto */
	cciset->header.flags[FW6x_SaveCryptoFlag] = saveCrypto == 6;

	/* CardDevice */
	if(saveCrypto > 1){
		u8 flag = CardDeviceFlag;
		if(saveCrypto == 2) flag = OldCardDeviceFlag;
		if(!yaml->CardInfo.CardDevice) cciset->header.flags[flag] = CARD_DEVICE_NONE;
		else{
			if(strcmp(yaml->CardInfo.CardDevice,"NorFlash") == 0) {
				cciset->header.flags[flag] = CARD_DEVICE_NOR_FLASH;
				if(cciset->header.flags[MediaTypeIndex] == CARD2){
					fprintf(stderr,"[CCI WARNING] 'CardDevice: NorFlash' is invalid on Card2\n");
					cciset->header.flags[flag] = CARD_DEVICE_NONE;
				}
			}
			else if(strcmp(yaml->CardInfo.CardDevice,"None") == 0) cciset->header.flags[flag] = CARD_DEVICE_NONE;
			else if(strcmp(yaml->CardInfo.CardDevice,"BT") == 0) cciset->header.flags[flag] = CARD_DEVICE_BT;
			else {
				fprintf(stderr,"[CCI ERROR] Invalid CardDevice: %s\n",yaml->CardInfo.CardDevice);
				return INVALID_YAML_OPT;
			}
		}
	}
	return 0;
}

int GetWriteableAddress(cci_settings *cciset, user_settings *usrset)
{
	int result = GetSaveDataSizeFromString(&cciset->option.savedataSize,usrset->common.rsfSet.SystemControlInfo.SaveDataSize,"NCSD");
	if(result) return result;

	char *WriteableAddressStr = usrset->common.rsfSet.CardInfo.WritableAddress;;
	
	cciset->cardinfo.writableAddress = -1;
	if(cciset->header.flags[MediaTypeIndex] != CARD2) return 0; // Can only be set for Card2 Media
	
	if(WriteableAddressStr){
		if(strncmp(WriteableAddressStr,"0x",2) != 0){
			fprintf(stderr,"[CCI ERROR] WritableAddress requires a Hexadecimal value\n");
			return INVALID_YAML_OPT;
		}	
		cciset->cardinfo.writableAddress = strtoull((WriteableAddressStr+2),NULL,16);
	}
	if(cciset->cardinfo.writableAddress == -1){ // If not set manually or is max size
		if ((cciset->header.mediaSize / 2) < cciset->option.savedataSize){ // If SaveData size is greater than half the MediaSize
			u64 SavedataSize = cciset->option.savedataSize / KB;
			fprintf(stderr,"[CCI ERROR] Too large SavedataSize %lldK\n",SavedataSize);
			return SAVE_DATA_TOO_LARGE;
		}
		if (cciset->option.savedataSize > (u64)(2047*MB)){ // Limit set by Nintendo
			u64 SavedataSize = cciset->option.savedataSize / KB;
			fprintf(stderr,"[CCI ERROR] Too large SavedataSize %lldK\n",SavedataSize);
			return SAVE_DATA_TOO_LARGE;
		}
		if(usrset->cci.closeAlignWritableRegion)
			cciset->cardinfo.writableAddress = align(cciset->cardinfo.cciTotalSize, cciset->option.mediaUnit);
		else{
			u64 UnusedSize = GetUnusedSize(cciset->header.mediaSize,cciset->header.flags[MediaTypeIndex]); // Need to look into this
			cciset->cardinfo.writableAddress = cciset->header.mediaSize - UnusedSize - cciset->option.savedataSize;
		}
	}
	return 0;
}

int GetCardInfoBitmask(cci_settings *cciset, user_settings *usrset)
{
	char *str = usrset->common.rsfSet.CardInfo.CardType;
	if(!str) cciset->cardinfo.cardInfoBitmask |= 0;
	else{
		if(strcasecmp(str,"s1") == 0) cciset->cardinfo.cardInfoBitmask |= 0;
		else if(strcasecmp(str,"s2") == 0) cciset->cardinfo.cardInfoBitmask |= 0x20;
		else {
			fprintf(stderr,"[CCI ERROR] Invalid CardType: %s\n",str);
			return INVALID_YAML_OPT;
		}
	}
	
	str = usrset->common.rsfSet.CardInfo.CryptoType;
	if(!str) cciset->cardinfo.cardInfoBitmask |= 0;//(3*0x40);
	else{
		int Value = strtol(str,NULL,10);
		if(Value < 0 || Value > 3) {
			fprintf(stderr,"[CCI ERROR] Invalid CryptoType: %s\n",str);
			return INVALID_YAML_OPT;
		}
		if(Value != 3){
			fprintf(stderr,"[CCI WARNING] Card crypto type = '%d'\n",Value);
		}
		cciset->cardinfo.cardInfoBitmask |= (Value*0x40);
	}
	
	return 0;
}

int ImportCverDetails(cci_settings *cciset, user_settings *usrset)
{
	if(!usrset->cci.cverCiaPath){
		memset(cciset->cardinfo.cverTitleId,0,8);
		memset(cciset->cardinfo.cverTitleVersion,0,2);
		return 0;
	}
	if(!cciset->content.size[7]){
		fprintf(stderr,"[CCI WARNING] Update Partition (content 7) is not specified, cver details will not be set\n");
		memset(cciset->cardinfo.cverTitleId,0,8);
		memset(cciset->cardinfo.cverTitleVersion,0,2);
		return 0;
	}
	
	if(!AssertFile(usrset->cci.cverCiaPath)){
		fprintf(stderr,"[CCI ERROR] Failed to open \"%s\"\n",usrset->cci.cverCiaPath);
		return FAILED_TO_IMPORT_FILE;
	}
	FILE *cia = fopen(usrset->cci.cverCiaPath,"rb");
	cia_hdr *ciaHdr = calloc(1,sizeof(cia_hdr));
	ReadFile_64(ciaHdr,sizeof(cia_hdr),0,cia);
	
	u64 tmdSize = GetTmdSize(ciaHdr);
	u64 tmdOffset = GetTmdOffset(ciaHdr);
	u8 *tmd = calloc(1,tmdSize);
	ReadFile_64(tmd,tmdSize,tmdOffset,cia);
	tmd_hdr *tmdHdr = GetTmdHdr(tmd);
	//memdump(stdout,"tmd: ",(u8*)tmdHdr,sizeof(tmd_hdr));


	endian_memcpy(cciset->cardinfo.cverTitleId,tmdHdr->titleID,8,LE);
	endian_memcpy(cciset->cardinfo.cverTitleVersion,tmdHdr->titleVersion,2,LE);

	if(!usrset->cci.dontModifyNcchTitleID)
		endian_memcpy(&cciset->content.titleId[7][6],tmdHdr->titleVersion,2,LE);
	
	fclose(cia);
	free(ciaHdr);
	free(tmd);

	return 0;
}

int CheckMediaSize(cci_settings *cciset)
{
	if(cciset->cardinfo.cciTotalSize > cciset->header.mediaSize){
		char *MediaSizeStr = NULL;
		switch(cciset->header.mediaSize){
			case (u64)128*MB: MediaSizeStr = " '128MB'"; break;
			case (u64)256*MB: MediaSizeStr = " '256MB'"; break;
			case (u64)512*MB: MediaSizeStr = " '512MB'"; break;
			case (u64)1*GB: MediaSizeStr = " '1GB'"; break;
			case (u64)2*GB: MediaSizeStr = " '2GB'"; break;
			case (u64)4*GB: MediaSizeStr = " '4GB'"; break;
			case (u64)8*GB: MediaSizeStr = " '8GB'"; break;
			case (u64)16*GB: MediaSizeStr = " '16GB'"; break;
			case (u64)32*GB: MediaSizeStr = " '32GB'"; break;
			default:  MediaSizeStr = ""; break;
		}
		fprintf(stderr,"[CCI ERROR] MediaSize%s is too Small\n",MediaSizeStr);
		return INVALID_YAML_OPT;
	}
	return 0;
}

bool IsCci(u8 *ncsd)
{
	cci_hdr *hdr = (cci_hdr*)(ncsd+0x100);
	if(!hdr) return false;
	if(memcmp(hdr->magic,"NCSD",4)!=0) return false;
	if(hdr->flags[MediaPlatformIndex] != CTR) return false;
	if(hdr->flags[MediaTypeIndex] != CARD1 && hdr->flags[MediaTypeIndex] != CARD2) return false;

	return true;
}

u8* GetPartition(u8 *ncsd, u8 index)
{
	return (u8*)(ncsd+GetPartitionOffset(ncsd,index));
}


u64 GetPartitionOffset(u8 *ncsd, u8 index)
{
	cci_hdr *hdr = (cci_hdr*)(ncsd+0x100);
	u32 media_size = 0x200*pow(2,hdr->flags[MediaUnitSize]);
	u32 offset = u8_to_u64(hdr->offset_sizeTable[index].offset,LE);
	return offset*media_size;
}

u64 GetPartitionSize(u8 *ncsd, u8 index)
{
	cci_hdr *hdr = (cci_hdr*)(ncsd+0x100);
	u32 media_size = 0x200*pow(2,hdr->flags[MediaUnitSize]);
	u32 size = u8_to_u64(hdr->offset_sizeTable[index].size,LE);
	return size*media_size;
}
