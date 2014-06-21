#include "lib.h"

// KeyData
#include "tpki.h" // Test PKI
#ifndef PUBLIC_BUILD
#include "ppki.h" // Production PKI
#include "dpki.h" // Development PKI
#endif

// Private Prototypes
int SetRsaKeySet(u8 **PrivDest, u8 *PrivSource, u8 **PubDest, u8 *PubSource);
int SetunFixedKey(keys_struct *keys, u8 *unFixedKey);
void InitcommonKeySlots(keys_struct *keys);

FILE* keyset_OpenFile(char *dir, char *name, bool FileRequired);
void keysetOpenError(char *file);

int SetTIK_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetTMD_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int Set_CCI_CFA_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetAccessDesc_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);
int SetCXI_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod);

int SetCaCert(keys_struct *keys, u8 *Cert);
int SetTikCert(keys_struct *keys, u8 *Cert);
int SetTmdCert(keys_struct *keys, u8 *Cert);

int LoadKeysFromResources(keys_struct *keys);
void SetDummyRsaData(keys_struct *keys);
int LoadKeysFromKeyfile(keys_struct *keys);
void CheckAccessDescKey(keys_struct *keys);
void DumpKeyset(keys_struct *keys);

// Code
void InitKeys(keys_struct *keys)
{
	memset(keys,0,sizeof(keys_struct));
	InitcommonKeySlots(keys);
	keys->rsa.cxiHdrPub = malloc(RSA_2048_KEY_SIZE);
	keys->rsa.cxiHdrPvt = malloc(RSA_2048_KEY_SIZE);
	keys->aes.unFixedKey0 = malloc(16);
	keys->aes.unFixedKey1 = malloc(16);
}

void PrintBadKeySize(char *path, u32 size)
{
	fprintf(stderr,"[KEYSET ERROR] %s has invalid size (0x%x)\n",path,size);
}

int SetKeys(keys_struct *keys)
{	
	int result = 0;
	result = LoadKeysFromResources(keys);
	if(result) return KEYSET_ERROR;

	if(!keys->keysetLoaded){
		result = LoadKeysFromKeyfile(keys);
		if(result) return KEYSET_ERROR;
	}
	
	if(keys->rsa.isFalseSign)
		SetDummyRsaData(keys);

	CheckAccessDescKey(keys);
	
	if(keys->dumpkeys)
		DumpKeyset(keys);

	return 0;
}

int LoadKeysFromResources(keys_struct *keys)
{
	if(keys->keyset == pki_TEST){
		keys->keysetLoaded = true;
		/* AES Keys */
		// CIA
		//SetCommonKey(keys,(u8*)zeros_aesKey,1);
		if(keys->aes.currentCommonKey > 0xff)
			SetCurrentCommonKey(keys,0);
	
		// NCCH
		keys->aes.normalKey = NULL;
		keys->aes.systemFixedKey = NULL;
		//SetNormalKey(keys,zeros_aesKey);
		//SetSystemFixedKey(keys,(u8*)zeros_aesKey);

		/* RSA Keys */
		keys->rsa.isFalseSign = true;		
	}
	#ifndef PUBLIC_BUILD
	else if(keys->keyset == pki_DEVELOPMENT){
		keys->keysetLoaded = true;
		/* AES Keys */
		// CIA
		for(int i = 0; i < 2; i++){
			SetCommonKey(keys,(u8*)ctr_common_etd_key_dpki[i],i);
		}
		if(keys->aes.currentCommonKey > 0xff)
			SetCurrentCommonKey(keys,0);
	
		// NCCH
		SetNormalKey(keys,(u8*)dev_fixed_ncch_key[0]);
		SetSystemFixedKey(keys,(u8*)dev_fixed_ncch_key[1]);
		
		/*
		keys->aes.ncchKeyX0 = (u8*)dev_unfixed_ncch_keyX[0];
		keys->aes.ncchKeyX1 = (u8*)dev_unfixed_ncch_keyX[1];
		*/

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys,(u8*)xs9_dpki_rsa_priv,(u8*)xs9_dpki_rsa_pub);
		SetTMD_RsaKey(keys,(u8*)cpA_dpki_rsa_priv,(u8*)cpA_dpki_rsa_pub);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys,(u8*)dev_ncsd_cfa_priv,(u8*)dev_ncsd_cfa_pub);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)dev_acex_priv,(u8*)dev_acex_pub);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca4_dpki_cert);
		SetTikCert(keys,(u8*)xs9_dpki_cert);
		SetTmdCert(keys,(u8*)cpA_dpki_cert);
	}
	else if(keys->keyset == pki_PRODUCTION){
		keys->keysetLoaded = true;
		/* AES Keys */
		// CIA
		for(int i = 0; i < 6; i++){
			keys->aes.commonKey[i] = malloc(16);
			AesKeyScrambler(keys->aes.commonKey[i],(u8*)ctr_common_etd_keyX_ppki,(u8*)ctr_common_etd_keyY_ppki[i]);
		}
		SetCurrentCommonKey(keys,1);
	
		// NCCH
		keys->aes.normalKey = NULL;
		keys->aes.systemFixedKey = NULL;
		/*
		keys->aes.ncchKeyX0 = (u8*)prod_unfixed_ncch_keyX[0];
		keys->aes.ncchKeyX1 = (u8*)prod_unfixed_ncch_keyX[1];
		*/

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys,(u8*)xsC_ppki_rsa_priv,(u8*)xsC_ppki_rsa_pub);
		SetTMD_RsaKey(keys,(u8*)cpB_ppki_rsa_priv,(u8*)cpB_ppki_rsa_pub);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys,(u8*)prod_ncsd_cfa_priv,(u8*)prod_ncsd_cfa_pub);
		// CXI
		SetAccessDesc_RsaKey(keys,(u8*)prod_acex_priv,(u8*)prod_acex_pub);
	
		/* Certs */
		SetCaCert(keys,(u8*)ca3_ppki_cert);
		SetTikCert(keys,(u8*)xsC_ppki_cert);
		SetTmdCert(keys,(u8*)cpB_ppki_cert);
	}
#endif
	return 0;
}

void SetDummyRsaData(keys_struct *keys)
{
	if(!keys->rsa.xsPvt || !keys->rsa.xsPub)
		SetTIK_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
	if(!keys->rsa.cpPvt || !keys->rsa.cpPub)
		SetTMD_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
		
	if(!keys->rsa.cciCfaPvt || !keys->rsa.cciCfaPub)
		Set_CCI_CFA_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);
	
	if(!keys->rsa.acexPvt || !keys->rsa.acexPub)
		SetAccessDesc_RsaKey(keys,(u8*)tpki_rsa_privExp,(u8*)tpki_rsa_pubMod);

	/* Certs */
	if(!keys->certs.caCert)
		SetCaCert(keys,(u8*)ca3_tpki_cert);
	if(!keys->certs.xsCert)
		SetTikCert(keys,(u8*)xsC_tpki_cert);
	if(!keys->certs.cpCert)
		SetTmdCert(keys,(u8*)cpB_tpki_cert);
}

int LoadKeysFromKeyfile(keys_struct *keys)
{
	printf("[KEYSET ERROR] Custom keys not supported\n");
	return -1;
}

void CheckAccessDescKey(keys_struct *keys)
{
	// Checking if AccessDesc can be signed
	u8 *tmp = calloc(1,RSA_2048_KEY_SIZE);
	if(memcmp(tmp,keys->rsa.acexPvt,RSA_2048_KEY_SIZE) == 0)
		keys->rsa.requiresPresignedDesc = true;
	else 
		keys->rsa.requiresPresignedDesc = false;

	free(tmp);
}

void DumpKeyset(keys_struct *keys)
{
	bool showNcchFixedKeys = (keys->aes.normalKey || keys->aes.systemFixedKey);
	bool showCommonKeys = false;
	for(int i = 0; i < 256; i++){
		if(keys->aes.commonKey[i]){
			showCommonKeys = true;
			break;
		}
	}

	printf("[*] Keyset\n");
		
	if(showCommonKeys){
		printf(" > eTicket Common Keys\n");
		for(int i = 0; i < 256; i++){
			if(keys->aes.commonKey[i]){
				printf(" [0x%02x]     ",i);
				memdump(stdout,"",keys->aes.commonKey[i],16);
			}
		}
	}
	if(showNcchFixedKeys){
		printf(" > Fixed NCCH Keys\n");
		if(keys->aes.normalKey)
			memdump(stdout," [Normal]   ",keys->aes.normalKey,16);
		if(keys->aes.systemFixedKey)
			memdump(stdout," [System]   ",keys->aes.systemFixedKey,16);
	}

	printf(" > TIK RSA Keys\n");
	memdump(stdout," [PUB]      ",keys->rsa.xsPub,0x100);
	memdump(stdout," [PVT]      ",keys->rsa.xsPvt,0x100);
	printf(" > TMD RSA Keys\n");
	memdump(stdout," [PUB]      ",keys->rsa.cpPub,0x100);
	memdump(stdout," [PVT]      ",keys->rsa.cpPvt,0x100);
	printf(" > AcexDesc RSA Keys\n");
	memdump(stdout," [PUB]      ",keys->rsa.acexPub,0x100);
	memdump(stdout," [PVT]      ",keys->rsa.acexPvt,0x100);
	printf(" > NcsdCfa RSA Keys\n");
	memdump(stdout," [PUB]      ",keys->rsa.cciCfaPub,0x100);
	memdump(stdout," [PVT]      ",keys->rsa.cciCfaPvt,0x100);
}

FILE* keyset_OpenFile(char *dir, char *name, bool FileRequired)
{
	int file_path_len = sizeof(char)*(strlen(dir)+strlen(name)+1);
	char *file_path = malloc(file_path_len);
	memset(file_path,0,file_path_len);

	sprintf(file_path,"%s%s",dir,name);

	FILE *fp = fopen(file_path,"rb");
	
	if(!fp && FileRequired)
		fprintf(stderr,"[KEYSET ERROR] Failed to open: %s\n",file_path);

	free(file_path);
	return fp;
}

void keysetOpenError(char *file)
{
	fprintf(stderr,"[KEYSET ERROR] Failed to open: %s\n",file);
}

void FreeKeys(keys_struct *keys)
{
	// AES
	if(keys->aes.commonKey){
		for(int i = 0; i < 256; i++){
			free(keys->aes.commonKey[i]);
		}
	}
	free(keys->aes.commonKey);
	free(keys->aes.normalKey);
	free(keys->aes.systemFixedKey);
	free(keys->aes.unFixedKey0);
	free(keys->aes.unFixedKey1);
	
	// RSA
	free(keys->rsa.xsPvt);
	free(keys->rsa.xsPub);
	free(keys->rsa.cpPvt);
	free(keys->rsa.cpPub);

	free(keys->rsa.cciCfaPvt);
	free(keys->rsa.cciCfaPub);
	
	free(keys->rsa.acexPvt);
	free(keys->rsa.acexPub);
	free(keys->rsa.cxiHdrPub);
	free(keys->rsa.cxiHdrPvt);
	
	// Certs
	free(keys->certs.caCert);
	free(keys->certs.xsCert);
	free(keys->certs.cpCert);
	memset(keys,0,sizeof(keys_struct));
}

int SetRsaKeySet(u8 **PrivDest, u8 *PrivSource, u8 **PubDest, u8 *PubSource)
{
	int result = 0;
	if(PrivSource){
		result = CopyData(PrivDest,PrivSource,0x100);
		if(result) return result;
	}
	if(PubSource){
		result = CopyData(PubDest,PubSource,0x100);
		if(result) return result;
	}
	return 0;
}

int SetCommonKey(keys_struct *keys, u8 *commonKey, u8 Index)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.commonKey[Index],commonKey,16);
}

void InitcommonKeySlots(keys_struct *keys)
{
	if(!keys->aes.commonKey){
		keys->aes.commonKey = malloc(sizeof(u8*)*256);
		memset(keys->aes.commonKey,0,sizeof(u8*)*256);
	}
}

int SetCurrentCommonKey(keys_struct *keys, u8 Index)
{
	if(!keys) return -1;
	keys->aes.currentCommonKey = Index;
	return 0;
}

int SetNormalKey(keys_struct *keys, u8 *systemFixedKey)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.normalKey,systemFixedKey,16);
}

int SetSystemFixedKey(keys_struct *keys, u8 *systemFixedKey)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.systemFixedKey,systemFixedKey,16);
}

int SetNcchUnfixedKeys(keys_struct *keys, u8 *ncchSig)
{
	if(!keys) return -1;

	//memdump(stdout,"keyY:  ",ncchSig,16);
	//memdump(stdout,"keyX0: ",keys->aes.ncchKeyX0,16);
	//memdump(stdout,"keyX1: ",keys->aes.ncchKeyX1,16);

	if(keys->aes.ncchKeyX0)
		AesKeyScrambler(keys->aes.unFixedKey0,keys->aes.ncchKeyX0,ncchSig);
	if(keys->aes.ncchKeyX1)
		AesKeyScrambler(keys->aes.unFixedKey1,keys->aes.ncchKeyX1,ncchSig);

	return 0;
}

int SetTIK_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.xsPvt,PrivateExp,&keys->rsa.xsPub,PublicMod);
}

int SetTMD_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.cpPvt,PrivateExp,&keys->rsa.cpPub,PublicMod);
}

int Set_CCI_CFA_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.cciCfaPvt,PrivateExp,&keys->rsa.cciCfaPub,PublicMod);
}

int SetAccessDesc_RsaKey(keys_struct *keys, u8 *PrivateExp, u8 *PublicMod)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.acexPvt,PrivateExp,&keys->rsa.acexPub,PublicMod);
}

int SetCaCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.caCert,Cert,0x400);
}
int SetTikCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.xsCert,Cert,0x300);
}

int SetTmdCert(keys_struct *keys, u8 *Cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.cpCert,Cert,0x400);
}