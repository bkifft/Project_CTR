#include "lib.h"
#include "ncch_build.h"
#include "exheader_build.h"
#include "accessdesc.h"

#include "desc/presets.h"
#include "desc/dev_sigdata.h"
#include "desc/prod_sigdata.h"

const int RSF_RSA_DATA_LEN = 344;
const int RSF_DESC_DATA_LEN = 684;


int accessdesc_SignWithKey(exheader_settings *exhdrset);
int accessdesc_GetSignFromRsf(exheader_settings *exhdrset);
int accessdesc_GetSignFromPreset(exheader_settings *exhdrset);
void accessdesc_GetPresetData(u8 **desc, u8 **accessDesc, u8 **depList, keys_struct *keys);
void accessdesc_GetPresetSigData(u8 **accessDescSig, u8 **cxiPubk, u8 **cxiPvtk, keys_struct *keys);

int set_AccessDesc(exheader_settings *exhdrset)
{
	if(exhdrset->useAccessDescPreset) // Use AccessDesc Template
		return accessdesc_GetSignFromPreset(exhdrset);
	else if(exhdrset->rsf->CommonHeaderKey.Found) // Keydata exists in RSF
		return accessdesc_GetSignFromRsf(exhdrset);
	else if(!exhdrset->keys->rsa.requiresPresignedDesc) // Else if The AccessDesc can be signed with key
		return accessdesc_SignWithKey(exhdrset);
	else{ // No way the access desc signature can be 'obtained'
		fprintf(stderr,"[ACEXDESC ERROR] Current keyset cannot sign AccessDesc, please appropriately set-up RSF, or specify a preset with \"-desc\"\n");
		return CANNOT_SIGN_ACCESSDESC;
	}
}

int accessdesc_SignWithKey(exheader_settings *exhdrset)
{
	/* Set RSA Keys */
	memcpy(exhdrset->keys->rsa.cxiHdrPvt,exhdrset->keys->rsa.cciCfaPvt,0x100);
	memcpy(exhdrset->keys->rsa.cxiHdrPub,exhdrset->keys->rsa.cciCfaPub,0x100);
	memcpy(&exhdrset->acexDesc->ncchRsaPubKey,exhdrset->keys->rsa.cxiHdrPub,0x100);

	/* Copy Data From ExHeader */
	memcpy(&exhdrset->acexDesc->arm11SystemLocalCapabilities,&exhdrset->exHdr->arm11SystemLocalCapabilities,sizeof(exhdr_ARM11SystemLocalCapabilities));
	memcpy(&exhdrset->acexDesc->arm11KernelCapabilities,&exhdrset->exHdr->arm11KernelCapabilities,sizeof(exhdr_ARM11KernelCapabilities));
	memcpy(&exhdrset->acexDesc->arm9AccessControlInfo,&exhdrset->exHdr->arm9AccessControlInfo,sizeof(exhdr_ARM9AccessControlInfo));
	
	/* Adjust Data */
	u8 *flag = &exhdrset->acexDesc->arm11SystemLocalCapabilities.flag[2];
	u8 SystemMode = (*flag>>4)&0xF;
	u8 AffinityMask = (*flag>>2)&0x3;
	u8 IdealProcessor = 1<<((*flag>>0)&0x3);
	*flag = (u8)(SystemMode << 4 | AffinityMask << 2 | IdealProcessor);
	exhdrset->acexDesc->arm11SystemLocalCapabilities.flag[3] /= 2;

	/* Sign AccessDesc */
	return SignAccessDesc(exhdrset->acexDesc,exhdrset->keys);
}

int accessdesc_GetSignFromRsf(exheader_settings *exhdrset)
{
	/* Yaml Option Sanity Checks */
	if(!exhdrset->rsf->CommonHeaderKey.Found){
		fprintf(stderr,"[ACEXDESC ERROR] RSF Section \"CommonHeaderKey\" not found\n");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.D){
		ErrorParamNotFound("CommonHeaderKey/D");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.D) != RSF_RSA_DATA_LEN){
		fprintf(stderr,"[ACEXDESC ERROR] \"CommonHeaderKey/D\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.D));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.Modulus){
		ErrorParamNotFound("CommonHeaderKey/Modulus");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.Modulus) != RSF_RSA_DATA_LEN){
		fprintf(stderr,"[ACEXDESC ERROR] \"CommonHeaderKey/Modulus\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.Modulus));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.AccCtlDescSign){
		ErrorParamNotFound("CommonHeaderKey/Signature");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescSign) != RSF_RSA_DATA_LEN){
		fprintf(stderr,"[ACEXDESC ERROR] \"CommonHeaderKey/Signature\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescSign));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	if(!exhdrset->rsf->CommonHeaderKey.AccCtlDescBin){
		ErrorParamNotFound("CommonHeaderKey/Descriptor");
		return COMMON_HEADER_KEY_NOT_FOUND;
	}
	if(b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescBin) != RSF_DESC_DATA_LEN){
		fprintf(stderr,"[ACEXDESC ERROR] \"CommonHeaderKey/Descriptor\" has invalid length (%d)\n",b64_strlen(exhdrset->rsf->CommonHeaderKey.AccCtlDescBin));
		return COMMON_HEADER_KEY_NOT_FOUND;
	}

	/* Set RSA Keys */
	int result = 0;
	// NCCH Header pubk
	result = b64_decode(exhdrset->keys->rsa.cxiHdrPub,exhdrset->rsf->CommonHeaderKey.Modulus,0x100);
	if(result) return result;
	// NCCH Header privk
	result = b64_decode(exhdrset->keys->rsa.cxiHdrPvt,exhdrset->rsf->CommonHeaderKey.D,0x100);
	if(result) return result;

	/* Set AccessDesc */
	// Signature
	result = b64_decode(exhdrset->acexDesc->signature,exhdrset->rsf->CommonHeaderKey.AccCtlDescSign,0x100);
	if(result) return result;
	// NCCH Header pubk
	memcpy(exhdrset->acexDesc->ncchRsaPubKey,exhdrset->keys->rsa.cxiHdrPub,0x100);
	// Access Control
	result = b64_decode((u8*)&exhdrset->acexDesc->arm11SystemLocalCapabilities,exhdrset->rsf->CommonHeaderKey.AccCtlDescBin,0x200);
	if(result) return result;
	
	return 0;	
}

int accessdesc_GetSignFromPreset(exheader_settings *exhdrset)
{
	u8 *desc = NULL;
	u8 *accessDesc = NULL;
	u8 *depList = NULL;

	u8 *accessDescSig = NULL;
	u8 *cxiPubk = NULL;
	u8 *cxiPvtk = NULL;

	accessdesc_GetPresetData(&desc,&accessDesc,&depList,exhdrset->keys);
	accessdesc_GetPresetSigData(&accessDescSig,&cxiPubk,&cxiPvtk,exhdrset->keys);

	// Error Checking
	if(!desc || !depList){
		fprintf(stderr,"[ACEXDESC ERROR] AccessDesc template is unavailable, please configure RSF file\n");
		return CANNOT_SIGN_ACCESSDESC;
	}

	if((!cxiPubk || !cxiPvtk || !accessDesc || !accessDescSig) && exhdrset->keys->rsa.requiresPresignedDesc){
		fprintf(stderr,"[ACEXDESC ERROR] This AccessDesc template needs to be signed, the current keyset is incapable of doing so. Please configure RSF file with the appropriate signature data.\n");
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
	if(!exhdrset->keys->rsa.requiresPresignedDesc) 
		return accessdesc_SignWithKey(exhdrset);

	// Otherwise set static data & ncch hdr sig info
	memcpy(exhdrset->keys->rsa.cxiHdrPub,cxiPubk,0x100);
	memcpy(exhdrset->keys->rsa.cxiHdrPvt,cxiPvtk,0x100);
	memcpy(&exhdrset->acexDesc->signature,accessDescSig,0x100);
	memcpy(&exhdrset->acexDesc->ncchRsaPubKey,cxiPubk,0x100);
	memcpy(&exhdrset->acexDesc->arm11SystemLocalCapabilities,accessDesc,0x200);

	return 0;
}

void accessdesc_GetPresetData(u8 **desc, u8 **accessDesc, u8 **depList, keys_struct *keys)
{
	if(keys->accessDescSign.presetType == desc_preset_APP){
		switch(keys->accessDescSign.targetFirmware){
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
	else if(keys->accessDescSign.presetType == desc_preset_EC_APP){
		switch(keys->accessDescSign.targetFirmware){
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
	else if(keys->accessDescSign.presetType == desc_preset_DLP){
		switch(keys->accessDescSign.targetFirmware){
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
	else if(keys->accessDescSign.presetType == desc_preset_DEMO){
		switch(keys->accessDescSign.targetFirmware){
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
	else if(keys->accessDescSign.presetType == desc_preset_FIRM){
		switch(keys->accessDescSign.targetFirmware){
			default:
				*desc = (u8*)firm_fw26_desc_data;
				*accessDesc = (u8*)firm_fw26_acex_data;
				*depList = (u8*)firm_fwXX_dep_list;
				break;
		}
	}
}

void accessdesc_GetPresetSigData(u8 **accessDescSig, u8 **cxiPubk, u8 **cxiPvtk, keys_struct *keys)
{
	if(keys->accessDescSign.presetType == desc_preset_APP){
		switch(keys->accessDescSign.targetFirmware){
			case 0x1B:
			case 0x1C:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw1B_dev_acexsig;
					*cxiPubk = (u8*)app_fw1B_dev_hdrpub;
					*cxiPvtk = (u8*)app_fw1B_dev_hdrpvt;
				}
				break;
			case 0x1D:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw1D_dev_acexsig;
					*cxiPubk = (u8*)app_fw1D_dev_hdrpub;
					*cxiPvtk = (u8*)app_fw1D_dev_hdrpvt;
				}
				if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw1D_prod_acexsig;
					*cxiPubk = (u8*)app_fw1D_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x1E:
				if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw1E_prod_acexsig;
					*cxiPubk = (u8*)app_fw1E_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x20:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw20_dev_acexsig;
					*cxiPubk = (u8*)app_fw20_dev_hdrpub;
					*cxiPvtk = NULL;
				}
				if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw20_prod_acexsig;
					*cxiPubk = (u8*)app_fw20_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x21:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw21_dev_acexsig;
					*cxiPubk = (u8*)app_fw21_dev_hdrpub;
					*cxiPvtk = (u8*)app_fw21_dev_hdrpvt;
				}
				else if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw21_prod_acexsig;
					*cxiPubk = (u8*)app_fw21_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x23:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)app_fw23_dev_acexsig;
					*cxiPubk = (u8*)app_fw23_dev_hdrpub;
					*cxiPvtk = NULL;
				}
				else if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw23_prod_acexsig;
					*cxiPubk = (u8*)app_fw23_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x27:
				if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)app_fw27_prod_acexsig;
					*cxiPubk = (u8*)app_fw27_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			
		}
	}
	else if(keys->accessDescSign.presetType == desc_preset_EC_APP){
		switch(keys->accessDescSign.targetFirmware){
			case 0x20:
				if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)ecapp_fw20_prod_acexsig;
					*cxiPubk = (u8*)ecapp_fw20_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
			case 0x23:
				if(keys->keyset == pki_PRODUCTION){
					*accessDescSig = (u8*)ecapp_fw23_prod_acexsig;
					*cxiPubk = (u8*)ecapp_fw23_prod_hdrpub;
					*cxiPvtk = NULL;
				}
				break;
		}
	}
	else if(keys->accessDescSign.presetType == desc_preset_DLP){
		switch(keys->accessDescSign.targetFirmware){
			case 0x1B:
			case 0x1C:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)dlp_fw1B_dev_acexsig;
					*cxiPubk = (u8*)dlp_fw1B_dev_hdrpub;
					*cxiPvtk = (u8*)dlp_fw1B_dev_hdrpvt;
				}
				break;
			case 0x1D:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)dlp_fw1D_dev_acexsig;
					*cxiPubk = (u8*)dlp_fw1D_dev_hdrpub;
					*cxiPvtk = (u8*)dlp_fw1D_dev_hdrpvt;
				}
				break;
			case 0x21:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)dlp_fw21_dev_acexsig;
					*cxiPubk = (u8*)dlp_fw21_dev_hdrpub;
					*cxiPvtk = (u8*)dlp_fw21_dev_hdrpvt;
				}
				break;
		}
	}
	else if(keys->accessDescSign.presetType == desc_preset_DEMO){
		switch(keys->accessDescSign.targetFirmware){
			case 0x1E:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)demo_fw1E_dev_acexsig;
					*cxiPubk = (u8*)demo_fw1E_dev_hdrpub;
					*cxiPvtk = NULL;
				}
 				break;
			case 0x21:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)demo_fw21_dev_acexsig;
					*cxiPubk = (u8*)demo_fw21_dev_hdrpub;
					*cxiPvtk = (u8*)demo_fw21_dev_hdrpvt;
				}
 				break;
		}
	}
	else if(keys->accessDescSign.presetType == desc_preset_FIRM){
		switch(keys->accessDescSign.targetFirmware){
			case 0x26:
				if(keys->keyset == pki_DEVELOPMENT){
					*accessDescSig = (u8*)firm_fw26_dev_acexsig;
					*cxiPubk = (u8*)firm_fw26_dev_hdrpub;
					*cxiPvtk = NULL;
				}
 				break;
		}
	}
}