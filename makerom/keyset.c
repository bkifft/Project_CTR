#include "lib.h"

// KeyData
#include "pki/test.h" // Test PKI
#include "pki/prod.h" // Production PKI
#include "pki/dev.h" // Development PKI

// Private Prototypes
int SetRsaKeySet(u8 **priv_exp_dst, const u8 *priv_exp_src, u8 **modulus_dst, const u8 *modulus_src);
void InitCommonKeySlots(keys_struct *keys);
void InitNcchKeyXSlots(keys_struct *keys);
int SetNcchKeyX(keys_struct *keys, const u8 *keyX, u8 index);

void keysetOpenError(char *file);
FILE* keyset_OpenFile(char *dir, char *name, bool FileRequired);

int SetTIK_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus);
int SetTMD_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus);
int Set_CCI_CFA_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus);
int SetAccessDesc_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus);
int SetCXI_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus);

int SetCaCert(keys_struct *keys, const u8 *cert);
int SetTikCert(keys_struct *keys, const u8 *cert);
int SetTmdCert(keys_struct *keys, const u8 *cert);

int LoadKeysFromResources(keys_struct *keys);
void SetDummyRsaData(keys_struct *keys);
int LoadKeysFromKeyfile(keys_struct *keys);
void CheckAccessDescKey(keys_struct *keys);
void DumpKeyset(keys_struct *keys);

// Code
void InitKeys(keys_struct *keys)
{
	memset(keys,0,sizeof(keys_struct));
	InitCommonKeySlots(keys);
	InitNcchKeyXSlots(keys);
	keys->rsa.cxiHdrPub = malloc(RSA_2048_KEY_SIZE);
	keys->rsa.cxiHdrPvt = malloc(RSA_2048_KEY_SIZE);
	keys->aes.ncchKey0 = malloc(AES_128_KEY_SIZE);
	keys->aes.ncchKey1 = malloc(AES_128_KEY_SIZE);
}

void PrintBadKeySize(char *path, u32 size)
{
	fprintf(stderr,"[KEYSET ERROR] %s has invalid size (0x%x)\n",path,size);
}

u8* AesKeyScrambler(u8 *key, const u8 *keyX, const u8 *keyY)
{
	// Process keyX/keyY to get raw normal key
	for(int i = 0; i < 16; i++)
		key[i] = keyX[i] ^ ((keyY[i] >> 2) | ((keyY[i < 15 ? i+1 : 0] & 3) << 6)); // keyX[i] ^

	const u8 SCRAMBLE_SECRET[16] = {0x51, 0xD7, 0x5D, 0xBE, 0xFD, 0x07, 0x57, 0x6A, 0x1C, 0xFC, 0x2A, 0xF0, 0x94, 0x4B, 0xD5, 0x6C};

	// Apply Secret to get final normal key
	for(int i = 0; i < 16; i++)
		key[i] = key[i] ^ SCRAMBLE_SECRET[i];

	return key;
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
		//SetCommonKey(keys, zeros_aesKey,1);
		if(keys->aes.currentCommonKey > 0xff)
			SetCurrentCommonKey(keys,0);
	
		// NCCH
		SetNormalKey(keys,zeros_aesKey);
		SetSystemFixedKey(keys,zeros_aesKey);

		/* RSA Keys */
		keys->rsa.isFalseSign = true;		
	}
	else if(keys->keyset == pki_DEVELOPMENT){
		keys->keysetLoaded = true;
		/* AES Keys */
		// CIA
		for(int i = 0; i < 2; i++)
			SetCommonKey(keys, ctr_common_etd_key_dpki[i],i);

		if(keys->aes.currentCommonKey > 0xff)
			SetCurrentCommonKey(keys,0);
	
		// NCCH
		SetNormalKey(keys, dev_fixed_ncch_key[0]);
		SetSystemFixedKey(keys, dev_fixed_ncch_key[1]);
		
		/*
		for(int i = 0; i < 2; i++)
			SetNcchKeyX(keys, dev_unfixed_ncch_keyX[i],i);
		*/

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys, xs9_dpki_rsa_priv, xs9_dpki_rsa_pub);
		SetTMD_RsaKey(keys, cpA_dpki_rsa_priv, cpA_dpki_rsa_pub);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys, dev_ncsd_cfa_priv, dev_ncsd_cfa_pub);
		// CXI
		SetAccessDesc_RsaKey(keys, dev_acex_priv, dev_acex_pub);
	
		/* Certs */
		SetCaCert(keys, ca4_dpki_cert);
		SetTikCert(keys, xs9_dpki_cert);
		SetTmdCert(keys, cpA_dpki_cert);
	}
	else if(keys->keyset == pki_PRODUCTION){
		keys->keysetLoaded = true;
		/* AES Keys */
		// CIA
		//for(int i = 0; i < 6; i++){
		//	keys->aes.commonKey[i] = malloc(16);
		//	AesKeyScrambler(keys->aes.commonKey[i], ctr_common_etd_keyX_ppki, ctr_common_etd_keyY_ppki[i]);
		//}
		if(keys->aes.currentCommonKey > 0xff)
			SetCurrentCommonKey(keys,0);
	
		// NCCH
		keys->aes.normalKey = NULL;
		keys->aes.systemFixedKey = NULL;
		/*
		for(int i = 0; i < 2; i++)
			SetNcchKeyX(keys, prod_unfixed_ncch_keyX[i],i);
		*/

		/* RSA Keys */
		// CIA
		SetTIK_RsaKey(keys, xsC_ppki_rsa_priv, xsC_ppki_rsa_pub);
		SetTMD_RsaKey(keys, cpB_ppki_rsa_priv, cpB_ppki_rsa_pub);
		// CCI/CFA
		Set_CCI_CFA_RsaKey(keys, prod_ncsd_cfa_priv, prod_ncsd_cfa_pub);
		// CXI
		SetAccessDesc_RsaKey(keys, prod_acex_priv, prod_acex_pub);
	
		/* Certs */
		SetCaCert(keys, ca3_ppki_cert);
		SetTikCert(keys, xsC_ppki_cert);
		SetTmdCert(keys, cpB_ppki_cert);
	}
	return 0;
}

void SetDummyRsaData(keys_struct *keys)
{
	if(!keys->rsa.xsPvt || !keys->rsa.xsPub)
		SetTIK_RsaKey(keys, tpki_rsa_privExp, tpki_rsa_pubMod);
	if(!keys->rsa.cpPvt || !keys->rsa.cpPub)
		SetTMD_RsaKey(keys, tpki_rsa_privExp, tpki_rsa_pubMod);
		
	if(!keys->rsa.cciCfaPvt || !keys->rsa.cciCfaPub)
		Set_CCI_CFA_RsaKey(keys, tpki_rsa_privExp, tpki_rsa_pubMod);
	
	if(!keys->rsa.acexPvt || !keys->rsa.acexPub)
		SetAccessDesc_RsaKey(keys, tpki_rsa_privExp, tpki_rsa_pubMod);

	/* Certs */
	if(!keys->certs.caCert)
		SetCaCert(keys, ca3_tpki_cert);
	if(!keys->certs.xsCert)
		SetTikCert(keys, xsC_tpki_cert);
	if(!keys->certs.cpCert)
		SetTmdCert(keys, cpB_tpki_cert);
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

void keysetOpenError(char *file)
{
	fprintf(stderr, "[KEYSET ERROR] Failed to open: %s\n", file);
}

FILE* keyset_OpenFile(char *dir, char *name, bool is_required)
{
	int file_path_len = sizeof(char)*(strlen(dir)+strlen(name)+1);
	char *file_path = malloc(file_path_len);
	memset(file_path,0,file_path_len);

	sprintf(file_path,"%s%s",dir,name);

	FILE *fp = fopen(file_path,"rb");
	
	if (!fp && is_required)
		keysetOpenError(file_path);

	free(file_path);
	return fp;
}



void FreeKeys(keys_struct *keys)
{
	// AES
	if(keys->aes.commonKey){
		for(int i = 0; i <= MAX_CMN_KEY; i++)
			free(keys->aes.commonKey[i]);
	}
	free(keys->aes.commonKey);
	free(keys->aes.normalKey);
	free(keys->aes.systemFixedKey);
	if(keys->aes.ncchKeyX){
		for(int i = 0; i <= MAX_NCCH_KEYX; i++)
			free(keys->aes.ncchKeyX[i]);
	}
	free(keys->aes.ncchKeyX);
	free(keys->aes.ncchKey0);
	free(keys->aes.ncchKey1);
	
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

int SetRsaKeySet(u8 **priv_exp_dst, const u8 *priv_exp_src, u8 **modulus_dst, const u8 *modulus_src)
{
	int result = 0;
	if(priv_exp_src){
		result = CopyData(priv_exp_dst,priv_exp_src,0x100);
		if(result) return result;
	}
	if(modulus_src){
		result = CopyData(modulus_dst,modulus_src,0x100);
		if(result) return result;
	}
	return 0;
}

int SetCommonKey(keys_struct *keys, const u8 *key, u8 index)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.commonKey[index],key,AES_128_KEY_SIZE);
}

void InitCommonKeySlots(keys_struct *keys)
{
	if(!keys->aes.commonKey)
		keys->aes.commonKey = calloc(MAX_CMN_KEY+1,sizeof(u8*));
}

int SetNcchKeyX(keys_struct *keys, const u8 *keyX, u8 index)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.ncchKeyX[index],keyX,AES_128_KEY_SIZE);
}

void InitNcchKeyXSlots(keys_struct *keys)
{
	if(!keys->aes.ncchKeyX)
		keys->aes.ncchKeyX = calloc(MAX_NCCH_KEYX+1,sizeof(u8*));
}

int SetCurrentCommonKey(keys_struct *keys, u8 Index)
{
	if(!keys) return -1;
	keys->aes.currentCommonKey = Index;
	return 0;
}

int SetNormalKey(keys_struct *keys, const u8 *key)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.normalKey,key,16);
}

int SetSystemFixedKey(keys_struct *keys, const u8 *key)
{
	if(!keys) return -1;
	return CopyData(&keys->aes.systemFixedKey,key,16);
}

int SetTIK_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.xsPvt,priv_exp,&keys->rsa.xsPub,modulus);
}

int SetTMD_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.cpPvt,priv_exp,&keys->rsa.cpPub,modulus);
}

int Set_CCI_CFA_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.cciCfaPvt,priv_exp,&keys->rsa.cciCfaPub,modulus);
}

int SetAccessDesc_RsaKey(keys_struct *keys, const u8 *priv_exp, const u8 *modulus)
{
	if(!keys) return -1;
	return SetRsaKeySet(&keys->rsa.acexPvt,priv_exp,&keys->rsa.acexPub,modulus);
}

int SetCaCert(keys_struct *keys, const u8 *cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.caCert,cert,0x400);
}
int SetTikCert(keys_struct *keys, const u8 *cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.xsCert,cert,0x300);
}

int SetTmdCert(keys_struct *keys, const u8 *cert)
{
	if(!keys) return -1;
	return CopyData(&keys->certs.cpCert,cert,0x400);
}