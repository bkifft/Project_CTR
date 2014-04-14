#include <stdio.h>
#include <string.h>

#include "types.h"
#include "exheader.h"
#include "utils.h"
#include "ncch.h"

void exheader_init(exheader_context* ctx)
{
	memset(ctx, 0, sizeof(exheader_context));
}

void exheader_set_file(exheader_context* ctx, FILE* file)
{
	ctx->file = file;
}

void exheader_set_offset(exheader_context* ctx, u32 offset)
{
	ctx->offset = offset;
}

void exheader_set_size(exheader_context* ctx, u32 size)
{
	ctx->size = size;
}

void exheader_set_usersettings(exheader_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void exheader_set_partitionid(exheader_context* ctx, u8 partitionid[8])
{
	memcpy(ctx->partitionid, partitionid, 8);
}

void exheader_set_programid(exheader_context* ctx, u8 programid[8])
{
	memcpy(ctx->programid, programid, 8);
}

void exheader_set_counter(exheader_context* ctx, u8 counter[16])
{
	memcpy(ctx->counter, counter, 16);
}

int exheader_get_compressedflag(exheader_context* ctx)
{
	return ctx->compressedflag;
}

void exheader_set_encrypted(exheader_context* ctx, u32 encrypted)
{
	ctx->encrypted = encrypted;
}

void exheader_set_key(exheader_context* ctx, u8 key[16])
{
	memcpy(ctx->key, key, 16);
}


void exheader_determine_key(exheader_context* ctx, u32 actions)
{
	u8* key = settings_get_ncch_key(ctx->usersettings);

	if (actions & PlainFlag)
		ctx->encrypted = 0;
	else
	{
		if (key)
		{
			ctx->encrypted = 1;
			memcpy(ctx->key, key, 0x10);
		}
	}
}

void exheader_read(exheader_context* ctx, u32 actions)
{
	if (ctx->haveread == 0)
	{
		fseek(ctx->file, ctx->offset, SEEK_SET);
		fread(&ctx->header, 1, sizeof(exheader_header), ctx->file);

		ctr_init_counter(&ctx->aes, ctx->key, ctx->counter);
		if (ctx->encrypted)
			ctr_crypt_counter(&ctx->aes, (u8*)&ctx->header, (u8*)&ctx->header, sizeof(exheader_header));

		ctx->haveread = 1;
	}
}

int exheader_programid_valid(exheader_context* ctx)
{
	if (!settings_get_ignore_programid(ctx->usersettings))
	{
		if (memcmp(ctx->header.arm11systemlocalcaps.programid, ctx->programid, 8))
		{
			fprintf(stderr, "Error, program id mismatch. Wrong key?\n");
			return 0;
		}
	}

	return 1;
}

int exheader_process(exheader_context* ctx, u32 actions)
{
	exheader_determine_key(ctx, actions);

	exheader_read(ctx, actions);

	if (ctx->header.codesetinfo.flags.flag & 1)
		ctx->compressedflag = 1;

	if (actions & VerifyFlag)
		exheader_verify(ctx);

	if (actions & InfoFlag)
	{
		exheader_print(ctx);		
	}

	return 1;
}

void exheader_print_arm9accesscontrol(exheader_context* ctx)
{
	unsigned int i;
	unsigned int flags[15*8];

	fprintf(stdout, "ARM9 Desc. version:     0x%X\n", ctx->header.arm9accesscontrol.descversion);

	for(i=0; i<15*8; i++)
	{
		if (ctx->header.arm9accesscontrol.descriptors[i/8] & (1<<(i&7)))
			flags[i] = 1;
		else
			flags[i] = 0;
	}

	fprintf(stdout, "Mount NAND fs:          %s\n", flags[0]? "YES" : "NO");
	fprintf(stdout, "Mount NAND RO write fs: %s\n", flags[1]? "YES" : "NO");
	fprintf(stdout, "Mount NAND TWL fs:      %s\n", flags[2]? "YES" : "NO");
	fprintf(stdout, "Mount NAND W fs:        %s\n", flags[3]? "YES" : "NO");
	fprintf(stdout, "Mount CARD SPI fs:      %s\n", flags[4]? "YES" : "NO");
	fprintf(stdout, "Use SDIF3:              %s\n", flags[5]? "YES" : "NO");
	fprintf(stdout, "Create seed:            %s\n", flags[6]? "YES" : "NO");
	fprintf(stdout, "Use CARD SPI:           %s\n", flags[7]? "YES" : "NO");
	fprintf(stdout, "SD Application:         %s\n", flags[8]? "YES" : "NO");
	fprintf(stdout, "Use Direct SDMC:        %s\n", flags[9]? "YES" : "NO");

	for(i=10; i<15*8; i++)
	{
		if (flags[i])
			fprintf(stdout, "Unknown flag:           %d\n", i);
	}
}

void exheader_print_arm11kernelcapabilities(exheader_context* ctx)
{
	unsigned int i, j;
	unsigned int systemcallmask[8];
	unsigned int unknowndescriptor[28];
	unsigned int svccount = 0;
	unsigned int svcmask = 0;
	unsigned int interrupt[0x80];
	unsigned int interruptcount = 0;

	memset(systemcallmask, 0, sizeof(systemcallmask));
	memset(interrupt, 0, sizeof(interrupt));

	for(i=0; i<28; i++)
	{
		unsigned int descriptor = getle32(ctx->header.arm11kernelcaps.descriptors[i]);

		unknowndescriptor[i] = 0;

		if ((descriptor & (0x1f<<27)) == (0x1e<<27))
			systemcallmask[(descriptor>>24) & 7] = descriptor & 0x00FFFFFF;
		else if ((descriptor & (0x7f<<25)) == (0x7e<<25))
			fprintf(stdout, "Kernel release version: %d.%d\n", (descriptor>>8)&0xFF, (descriptor>>0)&0xFF);
		else if ((descriptor & (0xf<<28)) == (0xe<<28))
		{
			for(j=0; j<4; j++)
				interrupt[(descriptor >> (j*7)) & 0x7F] = 1;
		}
		else if ((descriptor & (0xff<<24)) == (0xfe<<24))
			fprintf(stdout, "Handle table size:      0x%X\n", descriptor & 0x3FF);
		else if ((descriptor & (0xfff<<20)) == (0xffe<<20))
			fprintf(stdout, "Mapping IO address:     0x%X (%s)\n", (descriptor & 0xFFFFF)<<12, (descriptor&(1<<20))?"RO":"RW");
		else if ((descriptor & (0x7ff<<21)) == (0x7fc<<21))
			fprintf(stdout, "Mapping static address: 0x%X (%s)\n", (descriptor & 0x1FFFFF)<<12, (descriptor&(1<<20))?"RO":"RW");
		else if ((descriptor & (0x1ff<<23)) == (0x1fe<<23))
		{
			unsigned int memorytype = (descriptor>>8)&15;
			fprintf(stdout, "Kernel flags:           \n");
			fprintf(stdout, " > Allow debug:         %s\n", (descriptor&(1<<0))?"YES":"NO");
			fprintf(stdout, " > Force debug:         %s\n", (descriptor&(1<<1))?"YES":"NO");
			fprintf(stdout, " > Allow non-alphanum:  %s\n", (descriptor&(1<<2))?"YES":"NO");
			fprintf(stdout, " > Shared page writing: %s\n", (descriptor&(1<<3))?"YES":"NO");
			fprintf(stdout, " > Privilege priority:  %s\n", (descriptor&(1<<4))?"YES":"NO");
			fprintf(stdout, " > Allow main() args:   %s\n", (descriptor&(1<<5))?"YES":"NO");
			fprintf(stdout, " > Shared device mem:   %s\n", (descriptor&(1<<6))?"YES":"NO");
			fprintf(stdout, " > Runnable on sleep:   %s\n", (descriptor&(1<<7))?"YES":"NO");
			fprintf(stdout, " > Special memory:      %s\n", (descriptor&(1<<12))?"YES":"NO");
			

			switch(memorytype)
			{
			case 1: fprintf(stdout, " > Memory type:         APPLICATION\n"); break;
			case 2: fprintf(stdout, " > Memory type:         SYSTEM\n"); break;
			case 3: fprintf(stdout, " > Memory type:         BASE\n"); break;
			default: fprintf(stdout, " > Memory type:         Unknown (%d)\n", memorytype); break;
			}
		}
		else if (descriptor != 0xFFFFFFFF)
			unknowndescriptor[i] = 1;
	}

	fprintf(stdout, "Allowed systemcalls:    ");
	for(i=0; i<8; i++)
	{
		for(j=0; j<24; j++)
		{
			svcmask = systemcallmask[i];

			if (svcmask & (1<<j))
			{
				unsigned int svcid = i*24+j;
				if (svccount == 0)
				{
					fprintf(stdout, "0x%02X", svcid);
				}
				else if ( (svccount & 7) == 0)
				{
					fprintf(stdout, "                        ");
					fprintf(stdout, "0x%02X", svcid);
				}
				else
				{
					fprintf(stdout, ", 0x%02X", svcid);
				}

				svccount++;
				if ( (svccount & 7) == 0)
				{
					fprintf(stdout, "\n");
				}
			}
		}
	}
	if (svccount & 7)
		fprintf(stdout, "\n");
	if (svccount == 0)
		fprintf(stdout, "none\n");


	fprintf(stdout, "Allowed interrupts:     ");
	for(i=0; i<0x7F; i++)
	{
		if (interrupt[i])
		{
			if (interruptcount == 0)
			{
				fprintf(stdout, "0x%02X", i);
			}
			else if ( (interruptcount & 7) == 0)
			{
				fprintf(stdout, "                        ");
				fprintf(stdout, "0x%02X", i);
			}
			else
			{
				fprintf(stdout, ", 0x%02X", i);
			}

			interruptcount++;
			if ( (interruptcount & 7) == 0)
			{
				fprintf(stdout, "\n");
			}
		}
	}
	if (interruptcount & 7)
		fprintf(stdout, "\n");
	if (interruptcount == 0)
		fprintf(stdout, "none\n");

	for(i=0; i<28; i++)
	{
		unsigned int descriptor = getle32(ctx->header.arm11kernelcaps.descriptors[i]);

		if (unknowndescriptor[i])
			fprintf(stdout, "Unknown descriptor:     %08X\n", descriptor);
	}
}

void exheader_print_arm11accessinfo(exheader_context* ctx)
{
	u32 accessinfo = getle32(ctx->header.arm11systemlocalcaps.storageinfo.accessinfo);
	if((accessinfo & (1 << 0) )== (1 << 0))
		fprintf(stdout, " > Category System Application\n"); 
	if((accessinfo & (1 << 1) )== (1 << 1))
		fprintf(stdout, " > Category Hardware Check\n"); 
	if((accessinfo & (1 << 2) )== (1 << 2))
		fprintf(stdout, " > Category File System Tool\n"); 
	if((accessinfo & (1 << 3) )== (1 << 3))
		fprintf(stdout, " > Debug\n"); 
	if((accessinfo & (1 << 4) )== (1 << 4))
		fprintf(stdout, " > TWL Card Backup\n");
	if((accessinfo & (1 << 5) )== (1 << 5))
		fprintf(stdout, " > TWL Nand Data\n"); 
	if((accessinfo & (1 << 6) )== (1 << 6))
		fprintf(stdout, " > BOSS\n"); 
	if((accessinfo & (1 << 7) )== (1 << 7))
		fprintf(stdout, " > Direct SDMC\n");
	if((accessinfo & (1 << 8) )== (1 << 8))
		fprintf(stdout, " > Core\n");
	if((accessinfo & (1 << 9) )== (1 << 9))
		fprintf(stdout, " > CTR NAND RO\n");
	if((accessinfo & (1 << 10) )== (1 << 10))
		fprintf(stdout, " > CTR NAND RW\n"); 
	if((accessinfo & (1 << 11) )== (1 << 11))
		fprintf(stdout, " > CTR NAND RO (Write Access)\n");
	if((accessinfo & (1 << 12) )== (1 << 12))
		fprintf(stdout, " > Category System Settings\n");
	if((accessinfo & (1 << 13) )== (1 << 13))
		fprintf(stdout, " > CARD BOARD\n");
	if((accessinfo & (1 << 14) )== (1 << 14))
		fprintf(stdout, " > Export Import IVS\n");
	if((accessinfo & (1 << 15) )== (1 << 15))
		fprintf(stdout, " > Direct SDMC (Write Only)\n");
	if((accessinfo & (1 << 16) )== (1 << 16))
		fprintf(stdout, " > Switch Cleanup\n");
	if((accessinfo & (1 << 17) )== (1 << 17))
		fprintf(stdout, " > Save Data Move\n");
	if((accessinfo & (1 << 18) )== (1 << 18))
		fprintf(stdout, " > Shop\n");
	if((accessinfo & (1 << 19) )== (1 << 19))
		fprintf(stdout, " > Shell\n");
	if((accessinfo & (1 << 20) )== (1 << 20))
		fprintf(stdout, " > Category HomeMenu\n");
}

void exheader_print_arm11storageinfo(exheader_context* ctx)
{
	u32 i;

	// Storage Info
	u32 systemsaveID[2];
	u64 extdataID;
	u32 otherusersaveID[3];
	u32 accessiblesaveID[6];

	u8 otherattibutes = ctx->header.arm11systemlocalcaps.storageinfo.otherattributes;
	u8 accessOtherVariationSavedata = (getle64(ctx->header.arm11systemlocalcaps.storageinfo.accessibleuniqueids) & 0x1000000000000000) == 0x1000000000000000;	

	systemsaveID[0] = getle32(ctx->header.arm11systemlocalcaps.storageinfo.systemsavedataid);
	systemsaveID[1] = getle32(ctx->header.arm11systemlocalcaps.storageinfo.systemsavedataid+4);

	extdataID = getle64(ctx->header.arm11systemlocalcaps.storageinfo.extsavedataid);

	for(i = 0; i < 3; i++)
	{
		accessiblesaveID[i] = 0xfffff & (getle64(ctx->header.arm11systemlocalcaps.storageinfo.accessibleuniqueids) >> 20*(2-i));
		otherusersaveID[i] = 0xfffff & (getle64(ctx->header.arm11systemlocalcaps.storageinfo.accessibleuniqueids) >> 20*(2-i));
	}

	for(i = 0; i < 3; i++)
	{
		accessiblesaveID[i+3] = 0xfffff & (getle64(ctx->header.arm11systemlocalcaps.storageinfo.extsavedataid) >> 20*(2-i));
	}

	if(otherattibutes & 2)
	{
		extdataID = 0;
		for(i = 0; i < 3; i++)
			otherusersaveID[i] = 0;
	}
	else
	{
		for(i = 0; i < 6; i++)
			accessiblesaveID[i] = 0;
	}

	fprintf(stdout, "Ext savedata id:        0x%llX\n",extdataID);
	for(i = 0; i < 2; i++)
		fprintf(stdout, "System savedata id %d:   0x%08x %s\n",i+1,systemsaveID[i],exheader_getvalidstring(ctx->validsystemsaveID[i]));
	for(i = 0; i < 3; i++)
		fprintf(stdout, "OtherUserSaveDataId%d:   0x%05x\n",i+1,otherusersaveID[i]);
	fprintf(stdout, "Accessible Savedata Ids:\n");
	for(i = 0; i < 6; i++)
	{
		if(accessiblesaveID[i] != 0x00000)
			fprintf(stdout, " > 0x%05x\n",accessiblesaveID[i]);
	}
	
	fprintf(stdout, "Other Variation Saves:  %s\n", accessOtherVariationSavedata ? "Accessible" : "Inaccessible");
	if(ctx->validaccessinfo == Unchecked)
		memdump(stdout, "Access info:            ", ctx->header.arm11systemlocalcaps.storageinfo.accessinfo, 7);
	else if(ctx->validaccessinfo == Good)
		memdump(stdout, "Access info (GOOD):     ", ctx->header.arm11systemlocalcaps.storageinfo.accessinfo, 7);
	else
		memdump(stdout, "Access info (FAIL):     ", ctx->header.arm11systemlocalcaps.storageinfo.accessinfo, 7);
	exheader_print_arm11accessinfo(ctx);
	
	fprintf(stdout, "Other attributes:       %02X", ctx->header.arm11systemlocalcaps.storageinfo.otherattributes);
	/*
	if(otherattibutes & 1)
		fprintf(stdout," [no use romfs]");
	if(otherattibutes & 2)
		fprintf(stdout," [use extended savedata access control]");
	*/
	printf("\n");
}

int exheader_signature_verify(exheader_context* ctx, rsakey2048* key)
{
	u8 hash[0x20];

	ctr_sha_256(ctx->header.accessdesc.ncchpubkeymodulus, 0x300, hash);
	return ctr_rsa_verify_hash(ctx->header.accessdesc.signature, hash, key);
}


void exheader_verify(exheader_context* ctx)
{
	unsigned int i;
	u8 exheaderflag6[3];
	u8 descflag6[3];

	ctx->validsystemsaveID[0] = Good;
	ctx->validsystemsaveID[1] = Good;
	ctx->validaccessinfo = Good;
	ctx->validprogramid = Good;
	ctx->validpriority = Good;
	ctx->validaffinitymask = Good;
	ctx->valididealprocessor = Good;

	for(i=0; i<8; i++)
	{
		if (0 == (ctx->header.arm11systemlocalcaps.programid[i] & ~ctx->header.accessdesc.arm11systemlocalcaps.programid[i]))
			continue;
		ctx->validprogramid = Fail;
		break;
	}

	// Ideal Proccessor
	exheaderflag6[0] = (ctx->header.arm11systemlocalcaps.flags[6]>>0)&0x3;
	descflag6[0] = (ctx->header.accessdesc.arm11systemlocalcaps.flags[6]>>0)&0x3;
	// Affinity Mask
	exheaderflag6[1] = (ctx->header.arm11systemlocalcaps.flags[6]>>2)&0x3;
	descflag6[1] = (ctx->header.accessdesc.arm11systemlocalcaps.flags[6]>>2)&0x3;
	// System Mode
	//exheaderflag6[2] = (ctx->header.arm11systemlocalcaps.flags[6]>>4)&0xf;
	//descflag6[2] = (ctx->header.accessdesc.arm11systemlocalcaps.flags[6]>>4)&0xf;

	if (ctx->header.accessdesc.arm11systemlocalcaps.flags[7] > ctx->header.arm11systemlocalcaps.flags[7] ||  ctx->header.arm11systemlocalcaps.flags[7] > 127)
		ctx->validpriority = Fail;

	if((1<<exheaderflag6[0] & descflag6[0]) == 0)
		ctx->valididealprocessor = Fail;

	if (exheaderflag6[1] & ~descflag6[1])
		ctx->validaffinitymask = Fail;


	// Storage Info Verify
	for(i=0; i<8; i++)
	{
		if(0 == (ctx->header.arm11systemlocalcaps.storageinfo.systemsavedataid[i] & ~ctx->header.accessdesc.arm11systemlocalcaps.storageinfo.systemsavedataid[i]))
			continue;
		if(i < 4)
			ctx->validsystemsaveID[0] = Fail;
		else
			ctx->validsystemsaveID[1] = Fail;
	}
	for(i=0; i<7; i++)
	{
		if(0 == (ctx->header.arm11systemlocalcaps.storageinfo.accessinfo[i] & ~ctx->header.accessdesc.arm11systemlocalcaps.storageinfo.accessinfo[i]))
			continue;
		ctx->validaccessinfo = Fail;
		break;
	}

	if (ctx->usersettings)
		ctx->validsignature = exheader_signature_verify(ctx, &ctx->usersettings->keys.ncchdescrsakey);
}

const char* exheader_getvalidstring(int valid)
{
	if (valid == 0)
		return "";
	else if (valid == 1)
		return "(GOOD)";
	else
		return "(FAIL)";
}

void exheader_print(exheader_context* ctx)
{
	u32 i;
	char name[9];
	char service[9];
	exheader_codesetinfo* codesetinfo = &ctx->header.codesetinfo;

	memset(name, 0, sizeof(name));
	memcpy(name, codesetinfo->name, 8);


	fprintf(stdout, "\nExtended header:\n");
	if (ctx->validsignature == Unchecked)
		memdump(stdout, "Signature:              ", ctx->header.accessdesc.signature, 0x100);
	else if (ctx->validsignature == Good)
		memdump(stdout, "Signature (GOOD):       ", ctx->header.accessdesc.signature, 0x100);
	else if (ctx->validsignature == Fail)
		memdump(stdout, "Signature (FAIL):       ", ctx->header.accessdesc.signature, 0x100);
	printf("\n");
	memdump(stdout, "NCCH Hdr RSA Modulus:   ", ctx->header.accessdesc.ncchpubkeymodulus, 0x100);
	fprintf(stdout, "Name:                   %s\n", name);
	fprintf(stdout, "Flag:                   %02X ", codesetinfo->flags.flag);
	if (codesetinfo->flags.flag & 1)
		fprintf(stdout, "[compressed]");
	if (codesetinfo->flags.flag & 2)
		fprintf(stdout, "[sd application]");
	fprintf(stdout, "\n");
	fprintf(stdout, "Remaster version:       %04X\n", getle16(codesetinfo->flags.remasterversion));

	fprintf(stdout, "Code text address:      0x%08X\n", getle32(codesetinfo->text.address));
	fprintf(stdout, "Code text size:         0x%08X\n", getle32(codesetinfo->text.codesize));
	fprintf(stdout, "Code text max pages:    0x%08X (0x%08X)\n", getle32(codesetinfo->text.nummaxpages), getle32(codesetinfo->text.nummaxpages)*0x1000);
	fprintf(stdout, "Code ro address:        0x%08X\n", getle32(codesetinfo->ro.address));
	fprintf(stdout, "Code ro size:           0x%08X\n", getle32(codesetinfo->ro.codesize));
	fprintf(stdout, "Code ro max pages:      0x%08X (0x%08X)\n", getle32(codesetinfo->ro.nummaxpages), getle32(codesetinfo->ro.nummaxpages)*0x1000);
	fprintf(stdout, "Code data address:      0x%08X\n", getle32(codesetinfo->data.address));
	fprintf(stdout, "Code data size:         0x%08X\n", getle32(codesetinfo->data.codesize));
	fprintf(stdout, "Code data max pages:    0x%08X (0x%08X)\n", getle32(codesetinfo->data.nummaxpages), getle32(codesetinfo->data.nummaxpages)*0x1000);
	fprintf(stdout, "Code bss size:          0x%08X\n", getle32(codesetinfo->bsssize));
	fprintf(stdout, "Code stack size:        0x%08X\n", getle32(codesetinfo->stacksize));

	for(i=0; i<0x30; i++)
	{
		if (getle64(ctx->header.deplist.programid[i]) != 0x0000000000000000UL)
			fprintf(stdout, "Dependency:             %016llX\n", getle64(ctx->header.deplist.programid[i]));
	}

	fprintf(stdout, "Savedata size:          0x%016X\n", getle64(ctx->header.systeminfo.savedatasize));
	fprintf(stdout, "Jump id:                %016llX\n", getle64(ctx->header.systeminfo.jumpid));

	fprintf(stdout, "Program id:             %016llX %s\n", getle64(ctx->header.arm11systemlocalcaps.programid), exheader_getvalidstring(ctx->validprogramid));
	memdump(stdout, "Flags:                  ", ctx->header.arm11systemlocalcaps.flags, 8);
	fprintf(stdout, "Core version:           0x%X\n", getle32(ctx->header.arm11systemlocalcaps.flags));
	fprintf(stdout, "System mode:            0x%X\n", (ctx->header.arm11systemlocalcaps.flags[6]>>4)&0xF);
	fprintf(stdout, "Ideal processor:        %d %s\n", (ctx->header.arm11systemlocalcaps.flags[6]>>0)&0x3, exheader_getvalidstring(ctx->valididealprocessor));
	fprintf(stdout, "Affinity mask:          %d %s\n", (ctx->header.arm11systemlocalcaps.flags[6]>>2)&0x3, exheader_getvalidstring(ctx->validaffinitymask));
	fprintf(stdout, "Main thread priority:   %d %s\n", ctx->header.arm11systemlocalcaps.flags[7], exheader_getvalidstring(ctx->validpriority));
	// print resource limit descriptor too? currently mostly zeroes...
	exheader_print_arm11storageinfo(ctx);
	exheader_print_arm11kernelcapabilities(ctx);
	exheader_print_arm9accesscontrol(ctx);

		
	
	for(i=0; i<0x20; i++)
	{
		if (getle64(ctx->header.arm11systemlocalcaps.serviceaccesscontrol[i]) != 0x0000000000000000UL)
		{
			memset(service, 0, sizeof(service));
			memcpy(service, ctx->header.arm11systemlocalcaps.serviceaccesscontrol[i], 8);
			fprintf(stdout, "Service access:         %s\n", service);
		}
	}
	fprintf(stdout, "Reslimit category:      %02X\n", ctx->header.arm11systemlocalcaps.resourcelimitcategory);
}
