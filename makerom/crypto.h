#pragma once

#include "polarssl/config.h"
#include "polarssl/aes.h"
#include "polarssl/rsa.h"
#include "polarssl/sha1.h"
#include "polarssl/sha2.h"

typedef enum
{
	RSA_4096_SHA1 = 0x00010000,
	RSA_2048_SHA1 = 0x00010001,
	ECC_SHA1 = 0x00010002,
	RSA_4096_SHA256 = 0x00010003,
	RSA_2048_SHA256 = 0x00010004,
	ECC_SHA256 = 0x00010005
} sig_types;

typedef enum
{
	RSA_2048 = 0,
	RSA_4096 = 1,
	ECC = 2,
} ctr_sig_types;

typedef enum
{
	CTR_RSA_VERIFY = 0,
	CTR_RSA_SIGN = 1,
} ctr_rsa_functions;

typedef enum
{
	CTR_SHA_1 = 1,
	CTR_SHA_256 = 256,
} ctr_sha_modes;

typedef enum
{
	RSA_4096_PUBK = 0,
	RSA_2048_PUBK,
	ECC_PUBK
} pubk_types;

typedef enum
{
	ENC,
	DEC
} aescbcmode;

typedef enum
{
	RSAKEY_INVALID,
	RSAKEY_PRIV,
	RSAKEY_PUB
} rsakeytype;

typedef struct
{
	u8 ctr[16];
	u8 iv[16];
	aes_context aes;
} ctr_aes_context;

typedef struct
{
	rsa_context rsa;
} ctr_rsa_context;

#ifdef __cplusplus
extern "C" {
#endif
// SHA
bool VerifySha256(void *data, u64 size, u8 hash[32]);
void ctr_sha(void *data, u64 size, u8 *hash, int mode);
// AES
void ctr_add_counter(ctr_aes_context* ctx, u32 carry);
void ctr_init_counter(ctr_aes_context* ctx, u8 key[16],u8 ctr[16]);
void ctr_crypt_counter_block(ctr_aes_context* ctx, u8 input[16], u8 output[16]);
void ctr_crypt_counter(ctr_aes_context* ctx, u8* input,  u8* output, u32 size);
void ctr_init_aes_cbc(ctr_aes_context* ctx,u8 key[16],u8 iv[16], u8 mode);
void ctr_aes_cbc(ctr_aes_context* ctx,u8* input,u8* output,u32 size,u8 mode);
// RSA
void ctr_rsa_free(ctr_rsa_context* ctx);
int ctr_rsa_init(ctr_rsa_context* ctx, u8 *modulus, u8 *private_exp, u8 *exponent, u8 rsa_type, u8 mode);
int ctr_rsa(u8 *hash, u8 *signature, u8 *modulus, u8 *private_exp, u32 type, u8 mode);
int ctr_rsa_rsassa_pkcs1_v15_sign( rsa_context *ctx,
                               int mode,
                               int hash_id,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig );

// Signature Functions
int ctr_sig(void *data, u64 size, u8 *signature, u8 *modulus, u8 *private_exp, u32 type, u8 mode);
					
#ifdef __cplusplus
}
#endif