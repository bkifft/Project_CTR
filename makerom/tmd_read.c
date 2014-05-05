#include "lib.h"
#include "cia.h"
#include "tmd.h"

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