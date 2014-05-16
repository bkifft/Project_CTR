#include "lib.h"
#include "ncch.h"
#include "exheader.h"
#include "accessdesc.h"

#include "polarssl/base64.h"

#include "desc_presets.h"
#ifndef PUBLIC_BUILD
#include "desc_dev_sigdata.h"
#include "desc_prod_sigdata.h"
#endif

const int RSF_RSA_DATA_LEN = 344;
const int RSF_DESC_DATA_LEN = 684;


int accessdesc_SignWithKey(exheader_settings *exhdrset, ncch_settings *ncchset);
int accessdesc_GetSignFromRsf(exheader_settings *exhdrset, ncch_settings *ncchset);
int accessdesc_GetSignFromPreset(exheader_settings *exhdrset, ncch_settings *ncchset);
void accessdesc_GetPresetData(u8 **desc, u8 **accessDesc, u8 **depList, ncch_settings *ncchset);
#ifndef PUBLIC_BUILD
void accessdesc_GetPresetSigData(u8 **accessDescSig, u8 **cxiPubk, u8 **cxiPvtk, ncch_settings *ncchset);
#endif

bool IsValidB64Char(char chr);
u32 b64_strlen(char *str);
void b64_strcpy(char *dst, char *src);

int set_AccessDesc(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	if(exhdrset->useAccessDescPreset)
		return accessdesc_GetSignFromPreset(exhdrset,ncchset);
	else if(ncchset->rsfSet->CommonHeaderKey.Found) // Keydata exists in RSF
		return accessdesc_GetSignFromRsf(exhdrset,ncchset);
	else if(!ncchset->keys->rsa.requiresPresignedDesc) // Else if The AccessDesc can be signed with key
		return accessdesc_SignWithKey(exhdrset,ncchset);
	else{ // No way the access desc signature can be 'obtained'
		fprintf(stderr,"[EXHEADER ERROR] Current keyset cannot sign AccessDesc, please appropriatly setup RSF, or specify a preset with -accessdesc\n");
		return CANNOT_SIGN_ACCESSDESC;
	}
}

int accessdesc_SignWithKey(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Set RSA Keys */
	memcpy(exhdrset->keys->rsa.cxiHdrPvt,exhdrset->keys->rsa.cciCfaPvt,0x100);
	memcpy(exhdrset->keys->rsa.cxiHdrPub,exhdrset->keys->rsa.cciCfaPub,0x100);
	memcpy(&exhdrset->exHdr->accessDescriptor.ncchRsaPubKey,exhdrset->keys->rsa.cxiHdrPub,0x100);

	/* Copy Data From ExHeader */
	memcpy(&exhdrset->exHdr->accessDescriptor.arm11SystemLocalCapabilities,&exhdrset->exHdr->arm11SystemLocalCapabilities,sizeof(exhdr_ARM11SystemLocalCapabilities));
	memcpy(&exhdrset->exHdr->accessDescriptor.arm11KernelCapabilities,&exhdrset->exHdr->arm11KernelCapabilities,sizeof(exhdr_ARM11KernelCapabilities));
	memcpy(&exhdrset->exHdr->accessDescriptor.arm9AccessControlInfo,&exhdrset->exHdr->arm9AccessControlInfo,sizeof(exhdr_ARM9AccessControlInfo));
	
	/* Adjust Data */
	u8 *flag = &exhdrset->exHdr->accessDescriptor.arm11SystemLocalCapabilities.flag;
	u8 SystemMode = (*flag>>4)&0xF;
	u8 AffinityMask = (*flag>>2)&0x3;
	u8 IdealProcessor = 1<<((*flag>>0)&0x3);
	*flag = (u8)(SystemMode << 4 | AffinityMask << 2 | IdealProcessor);
	exhdrset->exHdr->accessDescriptor.arm11SystemLocalCapabilities.priority /= 2;

	/* Sign AccessDesc */
	return SignAccessDesc(exhdrset->exHdr,exhdrset->keys);
}

int accessdesc_GetSignFromRsf(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	/* Yaml Option Sanity Checks */
	if(!exhdrset->rsf->CommonHeaderKey.Found){
		fprintf(stderr,"[EXHEADER ERROR] RSF Section \"CommonHeaderKey\" not found\n");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.D){
		ErrorParamNotFound("CommonHeaderKey/D");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.D) != RSF_RSA_DATA_LEN){
		fprintf(stderr,"[EXHEADER ERROR] \"CommonHeaderKey/D\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.D));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.Modulus){
		ErrorParamNotFound("CommonHeaderKey/Modulus");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.Modulus) != RSF_RSA_DATA_LEN){
		fprintf(stderr,"[EXHEADER ERROR] \"CommonHeaderKey/Modulus\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.Modulus));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.AccCtlDescSign){
		ErrorParamNotFound("CommonHeaderKey/Signature");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescSign) != RSF_RSA_DATA_LEN){
		fprintf(stderr,"[EXHEADER ERROR] \"CommonHeaderKey/Signature\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescSign));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.AccCtlDescBin){
		ErrorParamNotFound("CommonHeaderKey/Descriptor");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescBin) != RSF_DESC_DATA_LEN){
		fprintf(stderr,"[EXHEADER ERROR] \"CommonHeaderKey/Descriptor\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescBin));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	/* Set RSA Keys */
	int result = 0;
	u32 out;

	out = 0x100;
	result = base64_decode(exhdrset->keys->rsa.cxiHdrPub,(size_t *)&out,(const u8*)exhdrset->rsf->CommonHeaderKey.Modulus,strlen(exhdrset->rsf->CommonHeaderKey.Modulus));
	if(out != 0x100)
		result = POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL;
	if(result) goto finish;

	out = 0x100;
	result = base64_decode(exhdrset->keys->rsa.cxiHdrPvt,(size_t *)&out,(const u8*)exhdrset->rsf->CommonHeaderKey.D,strlen(exhdrset->rsf->CommonHeaderKey.D));
	if(out != 0x100)
		result = POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL;
	if(result) goto finish;

	/* Set AccessDesc */
	out = 0x100;
	result = base64_decode(exhdrset->exHdr->accessDescriptor.signature,(size_t *)&out,(const u8*)exhdrset->rsf->CommonHeaderKey.AccCtlDescSign, strlen( exhdrset->rsf->CommonHeaderKey.AccCtlDescSign));
	if(out != 0x100)
		result = POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL;
	if(result) goto finish;
	memcpy(exhdrset->exHdr->accessDescriptor.ncchRsaPubKey,exhdrset->keys->rsa.cxiHdrPub,0x100);

	out = 0x200;
	result = base64_decode((u8*)&exhdrset->exHdr->accessDescriptor.arm11SystemLocalCapabilities,(size_t *)&out,(const u8*)exhdrset->rsf->CommonHeaderKey.AccCtlDescBin,strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescBin));
	if(out != 0x200)
		result = POLARSSL_ERR_BASE64_BUFFER_TOO_SMALL;
	if(result) goto finish;
finish:
	return result;	
}

int accessdesc_GetSignFromPreset(exheader_settings *exhdrset, ncch_settings *ncchset)
{
	u8 *desc = NULL;
	u8 *accessDesc = NULL;
	u8 *depList = NULL;

	u8 *accessDescSig = NULL;
	u8 *cxiPubk = NULL;
	u8 *cxiPvtk = NULL;

	accessdesc_GetPresetData(&desc,&accessDesc,&depList,ncchset);
#ifndef PUBLIC_BUILD
	accessdesc_GetPresetSigData(&accessDescSig,&cxiPubk,&cxiPvtk,ncchset);
#endif

	// Error Checking
	if(!desc || !depList){
		fprintf(stderr,"[EXHEADER ERROR] AccessDesc preset is unavailable, please configure RSF file\n");
		return CANNOT_SIGN_ACCESSDESC;
	}

	if((!cxiPubk || !cxiPvtk || !accessDesc || !accessDescSig) && ncchset->keys->rsa.requiresPresignedDesc){
		fprintf(stderr,"[EXHEADER ERROR] This AccessDesc preset needs to be signed, the current keyset is incapable of doing so. Please configure RSF file with the appropriate signature data.\n");
		return CANNOT_SIGN_ACCESSDESC;
	}
	
	// Setting data in Exheader
	// Dependency List
	memcpy(exhdrset->exHdr->dependencyList,depList,0x180);

	// Backing Up Non Preset Data
	u8 ProgramID[8];
	exhdr_StorageInfo StorageInfoBackup;
	exhdr_ARM9AccessControlInfo Arm9Desc;
	memcpy(ProgramID,exhdrset->exHdr->arm11SystemLocalCapabilities.programId,8);
	memcpy(&StorageInfoBackup,&exhdrset->exHdr->arm11SystemLocalCapabilities.storageInfo,sizeof(exhdr_StorageInfo));
	memcpy(&Arm9Desc,&exhdrset->exHdr->arm9AccessControlInfo,sizeof(exhdr_ARM9AccessControlInfo));
	
	// Setting Preset Data
	memcpy(&exhdrset->exHdr->arm11SystemLocalCapabilities,desc,0x200);

	// Restoring Non Preset Data
	memcpy(exhdrset->exHdr->arm11SystemLocalCapabilities.programId,ProgramID,8);
	memcpy(&exhdrset->exHdr->arm11SystemLocalCapabilities.storageInfo,&StorageInfoBackup,sizeof(exhdr_StorageInfo));
	memcpy(&exhdrset->exHdr->arm9AccessControlInfo,&Arm9Desc,sizeof(exhdr_ARM9AccessControlInfo));


	// Setting AccessDesc Area
	// Signing normally if possible
	if(!ncchset->keys->rsa.requiresPresignedDesc) 
		return accessdesc_SignWithKey(exhdrset,ncchset);

	// Otherwise set static data & ncch hdr sig info
	memcpy(exhdrset->keys->rsa.cxiHdrPub,cxiPubk,0x100);
	memcpy(exhdrset->keys->rsa.cxiHdrPvt,cxiPvtk,0x100);
	memcpy(&exhdrset->exHdr->accessDescriptor.signature,accessDescSig,0x100);
	memcpy(&exhdrset->exHdr->accessDescriptor.ncchRsaPubKey,cxiPubk,0x100);
	memcpy(&exhdrset->exHdr->accessDescriptor.arm11SystemLocalCapabilities,accessDesc,0x200);

	return 0;
}

void accessdesc_GetPresetData(u8 **desc, u8 **accessDesc, u8 **depList, ncch_settings *ncchset)
{
	if(ncchset->keys->accessDescSign.presetType == desc_preset_APP){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x1B:
			case 0x1C:
				*desc = (u8*)app_fw1B_desc_data;
				*accessDesc = (u8*)app_fw1B_acex_data;
				*depList = (u8*)fw1B_dep_list;
				break;
			case 0x1D:
				*desc = (u8*)app_fw1D_desc_data;
				*accessDesc = (u8*)app_fw1D_acex_data;
				*depList = (u8*)fw1D_dep_list;
				break;
			case 0x1E:
				*desc = (u8*)app_fw1E_desc_data;
				*accessDesc = (u8*)app_fw1E_acex_data;
				*depList = (u8*)fw1D_dep_list;
				break;
			case 0x20:
				*desc = (u8*)app_fw20_desc_data;
				*accessDesc = (u8*)app_fw20_acex_data;
				*depList = (u8*)fw20_dep_list;
				break;
			case 0x21:
				*desc = (u8*)app_fw21_desc_data;
				*accessDesc = (u8*)app_fw21_acex_data;
				*depList = (u8*)fw21_dep_list;
				break;
			case 0x23:
				*desc = (u8*)app_fw23_desc_data;
				*accessDesc = (u8*)app_fw23_acex_data;
				*depList = (u8*)fw23_dep_list;
				break;
			case 0x27:
				*desc = (u8*)app_fw27_desc_data;
				*accessDesc = (u8*)app_fw27_acex_data;
				*depList = (u8*)fw27_dep_list;
				break;
			
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_EC_APP){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x20:
				*desc = (u8*)ecapp_fw20_desc_data;
				*accessDesc = (u8*)ecapp_fw20_acex_data;
				*depList = (u8*)fw20_dep_list;
				break;
			case 0x23:
				*desc = (u8*)ecapp_fw23_desc_data;
				*accessDesc = (u8*)ecapp_fw23_acex_data;
				*depList = (u8*)fw23_dep_list;
				break;
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_DLP){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x1B:
			case 0x1C:
				*desc = (u8*)dlp_fw1B_desc_data;
				*accessDesc = (u8*)dlp_fw1B_acex_data;
				*depList = (u8*)fw1B_dep_list;
				break;
			case 0x1D:
				*desc = (u8*)dlp_fw1D_desc_data;
				*accessDesc = (u8*)dlp_fw1D_acex_data;
				*depList = (u8*)fw1D_dep_list;
				break;
			case 0x21:
				*desc = (u8*)dlp_fw21_desc_data;
				*accessDesc = (u8*)dlp_fw21_acex_data;
				*depList = (u8*)fw21_dep_list;
				break;
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_DEMO){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x1E:
				*desc = (u8*)demo_fw1E_desc_data;
				*accessDesc = (u8*)demo_fw1E_acex_data;
				*depList = (u8*)fw1D_dep_list;
				break;
			case 0x21:
				*desc = (u8*)demo_fw21_desc_data;
				*accessDesc = (u8*)demo_fw21_acex_data;
				*depList = (u8*)fw21_dep_list;
				break;
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_FIRM){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			default:
				*desc = (u8*)firm_fw26_desc_data;
				*accessDesc = (u8*)firm_fw26_acex_data;
				*depList = (u8*)firm_fwXX_dep_list;
				break;
		}
	}
}

#ifndef PUBLIC_BUILD
void accessdesc_GetPresetSigData(u8 **accessDescSig, u8 **cxiPubk, u8 **cxiPvtk, ncch_settings *ncchset)
{
	if(ncchset->keys->accessDescSign.presetType == desc_preset_APP){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x1B:
			case 0x1C:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw1B_dev_acexsig;
					*cxiPubk = (u8*)app_fw1B_dev_hdrpub;
					*cxiPvtk = (u8*)app_fw1B_dev_hdrpvt;
				}
				break;
			case 0x1D:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw1D_dev_acexsig;
					*cxiPubk = (u8*)app_fw1D_dev_hdrpub;
					*cxiPvtk = (u8*)app_fw1D_dev_hdrpvt;
				}
				if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw1D_prod_acexsig;
					*cxiPubk = (u8*)app_fw1D_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x1E:
				if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw1E_prod_acexsig;
					*cxiPubk = (u8*)app_fw1E_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x20:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw20_dev_acexsig;
					*cxiPubk = (u8*)app_fw20_dev_hdrpub;
					*cxiPvtk = NULL;
				}
				else if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw20_prod_acexsig;
					*cxiPubk = (u8*)app_fw20_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x21:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw21_dev_acexsig;
					*cxiPubk = (u8*)app_fw21_dev_hdrpub;
					*cxiPvtk = (u8*)app_fw21_dev_hdrpvt;
				}
				else if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw21_prod_acexsig;
					*cxiPubk = (u8*)app_fw21_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x23:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw23_dev_acexsig;
					*cxiPubk = (u8*)app_fw23_dev_hdrpub;
					*cxiPvtk = NULL;
				}
				else if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw23_prod_acexsig;
					*cxiPubk = (u8*)app_fw23_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x27:
				if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw27_prod_acexsig;
					*cxiPubk = (u8*)app_fw27_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_EC_APP){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x20:
				if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)ecapp_fw20_prod_acexsig;
					*cxiPubk = (u8*)ecapp_fw20_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x23:
				if(ncchset->keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)ecapp_fw23_prod_acexsig;
					*cxiPubk = (u8*)ecapp_fw23_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_DLP){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x1B:
			case 0x1C:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)dlp_fw1B_dev_acexsig;
					*cxiPubk = (u8*)dlp_fw1B_dev_hdrpub;
					*cxiPvtk = (u8*)dlp_fw1B_dev_hdrpvt;
				}
				break;
			case 0x1D:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)dlp_fw1D_dev_acexsig;
					*cxiPubk = (u8*)dlp_fw1D_dev_hdrpub;
					*cxiPvtk = (u8*)dlp_fw1D_dev_hdrpvt;
				}
				break;
			case 0x21:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)dlp_fw21_dev_acexsig;
					*cxiPubk = (u8*)dlp_fw21_dev_hdrpub;
					*cxiPvtk = (u8*)dlp_fw21_dev_hdrpvt;
				}
				break;
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_DEMO){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x1E:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)demo_fw1E_dev_acexsig;
					*cxiPubk = (u8*)demo_fw1E_dev_hdrpub;
					*cxiPvtk = NULL;
				}
 				break;
			case 0x21:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)demo_fw21_dev_acexsig;
					*cxiPubk = (u8*)demo_fw21_dev_hdrpub;
					*cxiPvtk = (u8*)demo_fw21_dev_hdrpvt;
				}
 				break;
		}
	}
	else if(ncchset->keys->accessDescSign.presetType == desc_preset_FIRM){
		switch(ncchset->keys->accessDescSign.targetFirmware){
			case 0x26:
				if(ncchset->keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)firm_fw26_dev_acexsig;
					*cxiPubk = (u8*)firm_fw26_dev_hdrpub;
					*cxiPvtk = NULL;
				}
 				break;
		}
	}
}
#endif

bool IsValidB64Char(char chr)
{
	return (isalnum(chr) || chr == '+' || chr == '/' || chr == '=');
}

u32 b64_strlen(char *str)
{
	u32 count = 0;
	u32 i = 0;
	while(str[i] != 0x0){
		if(IsValidB64Char(str[i])) {
			//printf("Is Valid: %c\n",str[i]);
			count++;
		}
		i++;
	}

	return count;
}

void b64_strcpy(char *dst, char *src)
{
	u32 src_len = strlen(src);
	u32 j = 0;
	for(u32 i = 0; i < src_len; i++){
		if(IsValidB64Char(src[i])){
			dst[j] = src[i];
			j++;
		}
	}
	dst[j] = 0;

	memdump(stdout,"src: ",(u8*)src,src_len+1);
	memdump(stdout,"dst: ",(u8*)dst,j+1);
}
