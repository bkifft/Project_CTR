#include "lib.h"
#include "certs.h"

// Cert Sizes

u32 GetCertSize(u8 *cert)
{
	u32 SigSize = 0;
	u32 SigPadding = 0;
	GetCertSigSectionSizes(&SigSize,&SigPadding,cert);
	if(!SigSize || !SigPadding) return 0;

	Cert_Struct *certcore = (Cert_Struct*)(cert+4+SigSize+SigPadding);

	u32 PubKSectionSize = GetCertPubkSectionSize((pubk_types)u8_to_u32(certcore->KeyType,BE));

	return (4+SigSize+SigPadding+sizeof(Cert_Struct)+PubKSectionSize);
}

void GetCertSigSectionSizes(u32 *SigSize, u32 *SigPadding, u8 *cert)
{
	sig_types sig = (sig_types)u8_to_u32(cert,BE);
	switch(sig){
		case RSA_4096_SHA1 :
			*SigSize = 0x200;
			*SigPadding = 0x3C;
			break;
		case RSA_2048_SHA1 :
			*SigSize = 0x100;
			*SigPadding = 0x3C;
			break;
		case ECC_SHA1 :
			*SigSize = 0x3C;
			*SigPadding = 0x40;
			break;
		case RSA_4096_SHA256 :
			*SigSize = 0x200;
			*SigPadding = 0x3C;
			break;
		case RSA_2048_SHA256 :
			*SigSize = 0x100;
			*SigPadding = 0x3C;
			break;
		case ECC_SHA256 :
			*SigSize = 0x3C;
			*SigPadding = 0x40;
			break;
		default :
			*SigSize = 0;
			*SigPadding = 0;
			break;
	}
	return;
}

u32 GetCertPubkSectionSize(pubk_types type)
{
	switch(type){
		case RSA_4096_PUBK : return sizeof(rsa_4096_pubk_struct);
		case RSA_2048_PUBK : return sizeof(rsa_2048_pubk_struct);
		case ECC_PUBK : return sizeof(ecc_pubk_struct);
		default : return 0;
	}
}

// Issuer/Name Functions
u8 *GetCertIssuer(u8 *cert)
{
	u32 SigSize = 0;
	u32 SigPadding = 0;
	GetCertSigSectionSizes(&SigSize,&SigPadding,cert);
	if(!SigSize || !SigPadding) return 0;

	Cert_Struct *certcore = (Cert_Struct*)(cert+4+SigSize+SigPadding);
	return certcore->Issuer;
}
u8 *GetCertName(u8 *cert)
{
	u32 SigSize = 0;
	u32 SigPadding = 0;
	GetCertSigSectionSizes(&SigSize,&SigPadding,cert);
	if(!SigSize || !SigPadding) return 0;

	Cert_Struct *certcore = (Cert_Struct*)(cert+4+SigSize+SigPadding);
	return certcore->Name;
}

int GenCertChildIssuer(u8 *dest, u8 *cert)
{
	u8 *issuer = GetCertIssuer(cert);
	u8 *name = GetCertName(cert);

	/*
	u32 out_size = strlen((char*)issuer) + strlen((char*)name) + 1;
	if(out_size > 0x40) return MEM_ERROR;
	*/

	snprintf((char*)dest,0x40,"%s-%s",issuer,name);

	/*
	strcat((char*)dest,(char*)issuer);
	strcat((char*)dest,"-");
	strcat((char*)dest,(char*)name);
	*/
	return 0;
}

// Pubk
pubk_types GetCertPubkType(u8 *cert)
{
	u32 SigSize = 0;
	u32 SigPadding = 0;
	GetCertSigSectionSizes(&SigSize,&SigPadding,cert);
	if(!SigSize || !SigPadding) return 0;

	Cert_Struct *certcore = (Cert_Struct*)(cert+4+SigSize+SigPadding);

	return (pubk_types)u8_to_u32(certcore->KeyType,BE);
}
u8 *GetCertPubk(u8 *cert)
{
	u32 SigSize = 0;
	u32 SigPadding = 0;
	GetCertSigSectionSizes(&SigSize,&SigPadding,cert);
	if(!SigSize || !SigPadding) return 0;
	return (cert+4+SigSize+SigPadding+sizeof(Cert_Struct));
}

bool VerifyCert(u8 *cert, u8 *pubk)
{
	u32 SigSize = 0;
	u32 SigPadding = 0;
	GetCertSigSectionSizes(&SigSize,&SigPadding,cert);
	if(!SigSize || !SigPadding) return 0;


	u8 *signature = (cert+4);
	u8 *data = (cert+4+SigSize+SigPadding);
	u32 datasize = sizeof(Cert_Struct) + GetCertPubkSectionSize(GetCertPubkType(cert));

	int result = ctr_sig(data,datasize,signature,pubk,NULL,u8_to_u32(cert,BE),CTR_RSA_VERIFY);

	if(result == 0) return true;
	else return false;
}