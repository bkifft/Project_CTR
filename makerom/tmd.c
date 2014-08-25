#include "lib.h"
#include "cia_build.h"
#include "tmd_build.h"

// Private Prototypes
int SetupTMDBuffer(buffer_struct *tik);
int SetupTMDHeader(tmd_hdr *hdr, tmd_content_info_record *info_record, cia_settings *ciaset);
int SignTMDHeader(tmd_hdr *hdr, tmd_signature *sig, keys_struct *keys);
int SetupTMDInfoRecord(tmd_content_info_record *info_record, u8 *content_record, u16 ContentCount);
int SetupTMDContentRecord(u8 *content_record, cia_settings *ciaset);

u32 PredictTMDSize(u16 ContentCount)
{
	return sizeof(tmd_signature) + sizeof(tmd_hdr) + sizeof(tmd_content_info_record)*64 + sizeof(tmd_content_chunk)*ContentCount;
}

int BuildTMD(cia_settings *ciaset)
{
	int result = 0;
	ciaset->ciaSections.tmd.size = PredictTMDSize(ciaset->content.count);
	result = SetupTMDBuffer(&ciaset->ciaSections.tmd);
	if(result) return result;

	// Setting TMD Struct Ptrs
	tmd_signature *sig = (tmd_signature*)ciaset->ciaSections.tmd.buffer;
	tmd_hdr *hdr = (tmd_hdr*)(ciaset->ciaSections.tmd.buffer+sizeof(tmd_signature));
	tmd_content_info_record *info_record = (tmd_content_info_record*)(ciaset->ciaSections.tmd.buffer+sizeof(tmd_signature)+sizeof(tmd_hdr));
	u8 *content_record = (u8*)(ciaset->ciaSections.tmd.buffer+sizeof(tmd_signature)+sizeof(tmd_hdr)+sizeof(tmd_content_info_record)*64);


	SetupTMDContentRecord(content_record,ciaset);
	SetupTMDInfoRecord(info_record,content_record,ciaset->content.count);
	result = SetupTMDHeader(hdr,info_record,ciaset);
	if(result) return result;
	result = SignTMDHeader(hdr,sig,ciaset->keys);
	return 0;
}

int SetupTMDBuffer(buffer_struct *tmd)
{
	tmd->buffer = calloc(1,tmd->size); 
	if(!tmd->buffer) { 
		fprintf(stderr,"[TMD ERROR] Not enough memory\n"); 
		return MEM_ERROR; 
	}
	return 0;
}

int SetupTMDHeader(tmd_hdr *hdr, tmd_content_info_record *info_record, cia_settings *ciaset)
{
	clrmem(hdr,sizeof(tmd_hdr));

	memcpy(hdr->issuer,ciaset->tmd.issuer,0x40);
	hdr->formatVersion = ciaset->tmd.formatVersion;
	hdr->caCrlVersion = ciaset->cert.caCrlVersion;
	hdr->signerCrlVersion = ciaset->cert.signerCrlVersion;
	memcpy(hdr->titleID,ciaset->common.titleId,8);
	memcpy(hdr->titleType,ciaset->tmd.titleType,4);
	memcpy(hdr->savedataSize,ciaset->tmd.savedataSize,4);
	memcpy(hdr->privSavedataSize,ciaset->tmd.privSavedataSize,4);
	hdr->twlFlag = ciaset->tmd.twlFlag;
	u16_to_u8(hdr->titleVersion,ciaset->tmd.version,BE);
	u16_to_u8(hdr->contentCount,ciaset->content.count,BE);
	ctr_sha(info_record,sizeof(tmd_content_info_record)*64,hdr->infoRecordHash,CTR_SHA_256);
	return 0;
}

int SignTMDHeader(tmd_hdr *hdr, tmd_signature *sig, keys_struct *keys)
{
	clrmem(sig,sizeof(tmd_signature));
	u32_to_u8(sig->sigType,RSA_2048_SHA256,BE);
	return ctr_sig((u8*)hdr,sizeof(tmd_hdr),sig->data,keys->rsa.cpPub,keys->rsa.cpPvt,RSA_2048_SHA256,CTR_RSA_SIGN);
}

int SetupTMDInfoRecord(tmd_content_info_record *info_record, u8 *content_record, u16 ContentCount)
{
	clrmem(info_record,sizeof(tmd_content_info_record)*0x40);
	u16_to_u8(info_record->contentIndexOffset,0x0,BE);
	u16_to_u8(info_record->contentCommandCount,ContentCount,BE);
	ctr_sha(content_record,sizeof(tmd_content_chunk)*ContentCount,info_record->contentChunkHash,CTR_SHA_256);
	return 0;
}

int SetupTMDContentRecord(u8 *content_record, cia_settings *ciaset)
{
	for(int i = 0; i < ciaset->content.count; i++){
		tmd_content_chunk *ptr = (tmd_content_chunk*)(content_record+sizeof(tmd_content_chunk)*i);
		u32_to_u8(ptr->id,ciaset->content.id[i],BE);
		u16_to_u8(ptr->index,ciaset->content.index[i],BE);
		u16_to_u8(ptr->flags,ciaset->content.flags[i],BE);
		u64_to_u8(ptr->size,ciaset->content.size[i],BE);
		memcpy(ptr->hash,ciaset->content.hash[i],0x20);
	}
	return 0;
}

tmd_hdr *GetTmdHdr(u8 *tmd)
{
	u32 sigType = u8_to_u32(tmd,BE);

	switch(sigType){
		case(RSA_4096_SHA1):
		case(RSA_4096_SHA256):
			return (tmd_hdr*)(tmd+0x240);
		case(RSA_2048_SHA1):
		case(RSA_2048_SHA256):
			return (tmd_hdr*)(tmd+0x140);
		case(ECC_SHA1):
		case(ECC_SHA256):
			return (tmd_hdr*)(tmd+0x7C);
	}

	return NULL;
}

tmd_content_chunk* GetTmdContentInfo(u8 *tmd)
{
	tmd_hdr *hdr = GetTmdHdr(tmd);
	if(!hdr)
		return NULL;
		
	return (tmd_content_chunk*)((u8*)hdr + sizeof(tmd_hdr) + (sizeof(tmd_content_info_record)*64));
}

u64 GetTmdTitleId(tmd_hdr *hdr)
{
	return u8_to_u64(hdr->titleID,BE);
}

u32 GetTmdSaveSize(tmd_hdr *hdr)
{
	return u8_to_u32(hdr->savedataSize,BE);
}

u16 GetTmdContentCount(tmd_hdr *hdr)
{
	return u8_to_u16(hdr->contentCount,BE);
}

u16 GetTmdVersion(tmd_hdr *hdr)
{
	return u8_to_u16(hdr->titleVersion,BE);
}

u32 GetTmdContentId(tmd_content_chunk info)
{
	return u8_to_u32(info.id,BE);
}

u16 GetTmdContentIndex(tmd_content_chunk info)
{
	return u8_to_u16(info.index,BE);
}

u16 GetTmdContentFlags(tmd_content_chunk info)
{
	return u8_to_u16(info.flags,BE);
}

u64 GetTmdContentSize(tmd_content_chunk info)
{
	return u8_to_u64(info.size,BE);
}

u8* GetTmdContentHash(tmd_content_chunk *info)
{
	return (u8*)info->hash;
}

bool IsTmdContentEncrypted(tmd_content_chunk info)
{
	return  (GetTmdContentFlags(info) & content_Encrypted) == content_Encrypted;
}

bool ValidateTmdContent(u8 *data, tmd_content_chunk info)
{
	u8 hash[32];
	ctr_sha(data,GetTmdContentSize(info),hash,CTR_SHA_256);
	return memcmp(hash,GetTmdContentHash(&info),32) == 0;
}