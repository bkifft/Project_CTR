#pragma once

typedef struct
{
	u8 Issuer[0x40];
	u8 KeyType[4];
	u8 Name[0x40];
	u8 Unknown[4];
} Cert_Struct;

typedef struct
{
	u8 Modulus[0x200];
	u8 PubExponent[4];
	u8 Padding[0x34];
} rsa_4096_pubk_struct;

typedef struct
{
	u8 Modulus[0x100];
	u8 PubExponent[4];
	u8 Padding[0x34];
} rsa_2048_pubk_struct;

typedef struct
{
	u8 PubK[0x3C];
	u8 Padding[0x3C];
} ecc_pubk_struct;

// Cert Sizes
u32 GetCertSize(u8 *cert);
void GetCertSigSectionSizes(u32 *SigSize, u32 *SigPadding, u8 *cert);
u32 GetCertPubkSectionSize(pubk_types type);

// Issuer/Name Functions
u8 *GetCertIssuer(u8 *cert);
u8 *GetCertName(u8 *cert);
int GenCertChildIssuer(u8 *dest, u8 *cert);

// Pubk
pubk_types GetCertPubkType(u8 *cert);
u8 *GetCertPubk(u8 *cert);

bool VerifyCert(u8 *cert, u8 *pubk);