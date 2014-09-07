#include "lib.h"
#include "crypto.h"

bool VerifySha256(void *data, u64 size, u8 hash[32])
{
	u8 calchash[32];
	ctr_sha(data, size, calchash, CTR_SHA_256);
	return memcmp(hash,calchash,32) == 0;
}

void ctr_sha(void *data, u64 size, u8 *hash, int mode)
{
	switch(mode){
		case(CTR_SHA_1): sha1((u8*)data, size, hash); break;
		case(CTR_SHA_256): sha2((u8*)data, size, hash, 0); break;
	}
}

void SetAesCtrOffset(u8 *ctr, u64 offset)
{
	u64_to_u8(ctr+8,u8_to_u64(ctr+8,BE)|align(offset,16)/16,BE);
}

void AesCtr(u8 *key, u8 *ctr, u8 *input, u8 *output, u64 length, u64 offset)
{
	u8 stream[16];
	aes_context aes;
	u64 nc_off = 0;
	
	clrmem(&aes,sizeof(aes_context));
	aes_setkey_enc(&aes, key, 128);
	SetAesCtrOffset(ctr,offset);
	
	aes_crypt_ctr(&aes, length, &nc_off, ctr, stream, input, output);
	
	
	return;
}

void AesCbc(u8 *key, u8 *iv, u8 *input, u8 *output, u64 length, u8 mode)
{
	aes_context aes;
	clrmem(&aes,sizeof(aes_context));
	
	switch(mode){
		case(ENC): 
			aes_setkey_enc(&aes, key, 128);
			aes_crypt_cbc(&aes, AES_ENCRYPT, length, iv, input, output);
			return;
		case(DEC):
			aes_setkey_dec(&aes, key, 128);
			aes_crypt_cbc(&aes, AES_DECRYPT, length, iv, input, output); 
			return;
		default:
			return;
	}
}

void ctr_rsa_free(ctr_rsa_context* ctx)
{
	rsa_free(&ctx->rsa);
}

int ctr_rsa_init(ctr_rsa_context* ctx, u8 *modulus, u8 *private_exp, u8 *exponent, u8 rsa_type, u8 mode)
{
	// Sanity Check
	if(ctx == NULL || modulus == NULL ||(private_exp == NULL && mode == RSAKEY_PRIV) || (exponent == NULL && mode == RSAKEY_PUB))
		return Fail;
	rsa_init(&ctx->rsa, RSA_PKCS_V15, 0);
	u16 n_size = 0;
	u16 d_size = 0;
	u16 e_size = 0;
	switch(rsa_type){
		case RSA_2048:
			ctx->rsa.len = 0x100;
			n_size = 0x100;
			d_size = 0x100;
			e_size = 3;
			break;
		case RSA_4096:
			ctx->rsa.len = 0x200;
			n_size = 0x200;
			d_size = 0x200;
			e_size = 3;
			break;
		default: return Fail;
	}
		
	switch(mode){
		case(RSAKEY_PUB):
			if (mpi_read_binary(&ctx->rsa.N, modulus, n_size))
				goto clean;
			if (mpi_read_binary(&ctx->rsa.E, exponent, e_size))
				goto clean;
			break;
		case(RSAKEY_PRIV):
			if (mpi_read_binary(&ctx->rsa.N, modulus, n_size))
				goto clean;
			if (mpi_read_binary(&ctx->rsa.D, private_exp, d_size))
				goto clean;
			break;
		default: return Fail;
	}

	return Good;
clean:
	ctr_rsa_free(ctx);
	return Fail;
}

int ctr_sig(void *data, u64 size, u8 *signature, u8 *modulus, u8 *private_exp, u32 type, u8 mode)
{
	int result = 0;
	int hashtype, hashlen, sigtype;
	if(data == NULL || signature == NULL || modulus == NULL ||(private_exp == NULL && mode == CTR_RSA_SIGN))
		return Fail;
		
	switch(type){
		case RSA_4096_SHA1:
			hashtype = CTR_SHA_1;
			hashlen = 0x14;
			sigtype = RSA_4096;
		case RSA_4096_SHA256:
			hashtype = CTR_SHA_256;
			hashlen = 0x20;
			sigtype = RSA_4096;
			break;
		case RSA_2048_SHA1:
			hashtype = CTR_SHA_1;
			hashlen = 0x14;
			sigtype = RSA_2048;
		case RSA_2048_SHA256:
			hashtype = CTR_SHA_256;
			hashlen = 0x20;
			sigtype = RSA_2048;
			break;
		case ECC_SHA1:
			hashtype = CTR_SHA_1;
			hashlen = 0x14;
			sigtype = ECC;
		case ECC_SHA256:
			hashtype = CTR_SHA_256;
			hashlen = 0x20;
			sigtype = ECC;
			break;
		default: return Fail;
	}
	
	u8 hash[hashlen];
	memset(hash,0,hashlen);
	ctr_sha(data,size,hash,hashtype);
	//memdump(stdout,"Data:        ",data,size);
	//memdump(stdout,"HashFor Sig: ",hash,hashlen);
	
	if(sigtype == RSA_2048 || sigtype == RSA_4096)
		result = ctr_rsa(hash,signature,modulus,private_exp,type,mode);
	else if(sigtype == ECC){
		printf("[!] ECC is not yet implemented\n");
		result = Fail;
	}
	return result;
}

int ctr_rsa(u8 *hash, u8 *signature, u8 *modulus, u8 *private_exp, u32 type, u8 mode)
{
	int result = 0;
	// Sanity Check
	if(hash == NULL || signature == NULL || modulus == NULL ||(private_exp == NULL && mode == CTR_RSA_SIGN))
		return Fail;
	
	// Getting details from sig type
	int hashtype;
	int hashlen;
	int sigtype;
	switch(type){
			case RSA_4096_SHA1:
				hashtype = SIG_RSA_SHA1;
				hashlen = 0x14;
				sigtype = RSA_4096;
				break;
			case RSA_4096_SHA256:
				hashtype = SIG_RSA_SHA256;
				hashlen = 0x14;
				sigtype = RSA_4096;
				break;
			case RSA_2048_SHA1:
				hashtype = SIG_RSA_SHA1;
				hashlen = 0x20;
				sigtype = RSA_2048;
				break;
			case RSA_2048_SHA256:
				hashtype = SIG_RSA_SHA256;
				hashlen = 0x20;
				sigtype = RSA_2048;
				break;
			default: return Fail;
	}
	
	// Setting up
	ctr_rsa_context ctx;
	u8 exponent[3] = {0x01,0x00,0x01};
	switch(mode){
		case CTR_RSA_VERIFY: 
			result = ctr_rsa_init(&ctx,modulus,NULL,(u8*)exponent,sigtype,RSAKEY_PUB);
			break;
		case CTR_RSA_SIGN: 
			result = ctr_rsa_init(&ctx,modulus,private_exp,NULL,sigtype,RSAKEY_PRIV);
			break;
	}
	if(result)return result;
	
	switch(mode){
		case CTR_RSA_VERIFY: 
			return rsa_pkcs1_verify(&ctx.rsa,RSA_PUBLIC,hashtype,hashlen,hash,signature);
		case CTR_RSA_SIGN: 
			return ctr_rsa_rsassa_pkcs1_v15_sign(&ctx.rsa,RSA_PRIVATE,hashtype,hashlen,hash,signature);
	}
	return Fail;
} 


/**
*  Hacked from rsa.c, polarssl doesn't like generating signatures when only D and N are present
**/
int ctr_rsa_rsassa_pkcs1_v15_sign( rsa_context *ctx,
                               int mode,
                               int hash_id,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    size_t nb_pad, olen, ret;
    unsigned char *p = sig;

    if( ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            nb_pad = olen - 3 - hashlen;
            break;

        case SIG_RSA_MD2:
        case SIG_RSA_MD4:
        case SIG_RSA_MD5:
            nb_pad = olen - 3 - 34;
            break;

        case SIG_RSA_SHA1:
            nb_pad = olen - 3 - 35;
            break;

        case SIG_RSA_SHA224:
            nb_pad = olen - 3 - 47;
            break;

        case SIG_RSA_SHA256:
            nb_pad = olen - 3 - 51;
            break;

        case SIG_RSA_SHA384:
            nb_pad = olen - 3 - 67;
            break;

        case SIG_RSA_SHA512:
            nb_pad = olen - 3 - 83;
            break;


        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    if( ( nb_pad < 8 ) || ( nb_pad > olen ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    *p++ = 0;
    *p++ = RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case SIG_RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 2; break;

        case SIG_RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 4; break;

        case SIG_RSA_MD5:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 5; break;

        case SIG_RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;

        case SIG_RSA_SHA224:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 28 );
            p[1] += 28; p[14] = 4; p[18] += 28; break;

        case SIG_RSA_SHA256:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 32 );
            p[1] += 32; p[14] = 1; p[18] += 32; break;

        case SIG_RSA_SHA384:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 48 );
            p[1] += 48; p[14] = 2; p[18] += 48; break;

        case SIG_RSA_SHA512:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 64 );
            p[1] += 64; p[14] = 3; p[18] += 64; break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    mpi T, T1, T2;

	mpi_init( &T ); mpi_init( &T1 ); mpi_init( &T2 );

    MPI_CHK( mpi_read_binary( &T, sig, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }	
	
	MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
	
    MPI_CHK( mpi_write_binary( &T, sig, olen ) );

cleanup:

    mpi_free( &T ); mpi_free( &T1 ); mpi_free( &T2 );

    return( 0 );
}