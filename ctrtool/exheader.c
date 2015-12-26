#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "types.h"
#include "exheader.h"
#include "utils.h"
#include "ncch.h"
#include "syscalls.h"
#include <inttypes.h>

void exheader_init(exheader_context* ctx)
{
	memset(ctx, 0, sizeof(exheader_context));
}

void exheader_set_file(exheader_context* ctx, FILE* file)
{
	ctx->file = file;
}

void exheader_set_offset(exheader_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void exheader_set_size(exheader_context* ctx, u64 size)
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

void exheader_set_hash(exheader_context* ctx, u8 hash[32])
{
	memcpy(ctx->hash, hash, 32);
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
		fseeko64(ctx->file, ctx->offset, SEEK_SET);
		fread(&ctx->header, 1, sizeof(exheader_header), ctx->file);

		ctr_init_counter(&ctx->aes, ctx->key, ctx->counter);
		if (ctx->encrypted)
			ctr_crypt_counter(&ctx->aes, (u8*)&ctx->header, (u8*)&ctx->header, sizeof(exheader_header));

		ctx->haveread = 1;
	}
}

int exheader_hash_valid(exheader_context* ctx)
{
	u8 hash[32];
	ctr_sha_256((u8*)&ctx->header, 0x400, hash);

	if(memcmp(ctx->hash,hash,0x20)){
		fprintf(stderr, "Error, exheader hash mismatch. Wrong key?\n");
		return 0;
	}
	
	return 1;
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

void exheader_deserialise_arm11localcaps_permissions(exheader_arm11systemlocalcaps_deserialised *caps, const exheader_arm11systemlocalcaps *arm11)
{
	int i;

	memset(caps, 0, sizeof(exheader_arm11systemlocalcaps_deserialised));

	memcpy(caps->program_id, arm11->programid, 8);
	caps->core_version = getle32(arm11->coreversion);

	caps->enable_l2_cache = (arm11->flag[0] >> 0) & 1;
	caps->new3ds_cpu_speed = (arm11->flag[0] >> 1) & 1;
	caps->new3ds_systemmode = (arm11->flag[1] >> 0) & 15;

	caps->ideal_processor = (arm11->flag[2] >> 0) & 3;
	caps->affinity_mask = (arm11->flag[2] >> 2) & 3;
	caps->old3ds_systemmode = (arm11->flag[2] >> 4) & 15;

	caps->priority = (s8)arm11->flag[3];

	// storage info
	if (arm11->storageinfo.otherattributes & 2) {
		caps->extdata_id = 0;
		for (i = 0; i < 3; i++)
			caps->other_user_saveid[i] = 0;
		caps->use_other_variation_savedata = 0;

		for (i = 0; i < 3; i++)
			caps->accessible_saveid[i] = 0xfffff & (getle64(arm11->storageinfo.accessibleuniqueids) >> 20 * (2 - i));
		for (i = 0; i < 3; i++)
			caps->accessible_saveid[i+3] = 0xfffff & (getle64(arm11->storageinfo.extsavedataid) >> 20 * (2 - i));
	}
	else {
		caps->extdata_id = getle64(arm11->storageinfo.extsavedataid);
		for (i = 0; i < 3; i++)
			caps->other_user_saveid[i] = 0xfffff & (getle64(arm11->storageinfo.accessibleuniqueids) >> 20 * (2 - i));
		caps->use_other_variation_savedata = (getle64(arm11->storageinfo.accessibleuniqueids) >> 60) & 1;

		for (i = 0; i < 6; i++)
			caps->accessible_saveid[i] = 0;
	}

	caps->system_saveid[0] = getle32(arm11->storageinfo.systemsavedataid);
	caps->system_saveid[1] = getle32(arm11->storageinfo.systemsavedataid + 4);
	caps->accessinfo = getle64(arm11->storageinfo.accessinfo) & ~((u64)0xff00000000000000);

	// Service Access Control
	for (i = 0; i < 34; i++)
		strncpy(caps->service_access_control[i], (char*)arm11->serviceaccesscontrol[i], 8);

	caps->resource_limit_category = arm11->resourcelimitcategory;
}

int exheader_process(exheader_context* ctx, u32 actions)
{
	exheader_determine_key(ctx, actions);

	exheader_read(ctx, actions);

	if (ctx->header.codesetinfo.flags.flag & 1)
		ctx->compressedflag = 1;

	exheader_deserialise_arm11localcaps_permissions(&ctx->system_local_caps, &ctx->header.arm11systemlocalcaps);

	if (actions & VerifyFlag)
		exheader_verify(ctx);

	if (actions & InfoFlag)
		exheader_print(ctx, actions);

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

void exheader_print_arm11kernelcapabilities(exheader_context* ctx, u32 actions)
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
			fprintf(stdout, " > Access Core 2:       %s\n", (descriptor&(1<<13))?"YES":"NO");
			

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
	if(!(actions & ShowSyscallsFlag))
	{
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
	}
	else
	{
		fprintf(stdout, "\n");

		for(i=0; i<8; i++)
		{
			for(j=0; j<24; j++)
			{
				svcmask = systemcallmask[i];

				if (svcmask & (1 << j))
				{
					unsigned int svcid = i * 24 + j;
					char svcname[128];

					syscall_get_name(svcname, sizeof(svcname), svcid);

					fprintf(stdout, " > 0x%02X %s\n", svcid, svcname);
				}
			}
		}
	}

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

char* exheader_print_accessinfobit(u32 bit, char *str)
{
	switch(bit)
	{
		case 0 : 
			sprintf(str,"Category System Application");
			break;
		case 1 : 
			sprintf(str,"Category Hardware Check");
			break;
		case 2 : 
			sprintf(str,"Category File System Tool");
			break;
		case 3 : 
			sprintf(str,"Debug");
			break;
		case 4 : 
			sprintf(str,"TWL Card Backup");
			break;
		case 5 : 
			sprintf(str,"TWL Nand Data");
			break;
		case 6 : 
			sprintf(str,"BOSS");
			break;
		case 7 : 
			sprintf(str,"Direct SDMC");
			break;
		case 8 : 
			sprintf(str,"Core");
			break;
		case 9 : 
			sprintf(str,"CTR NAND RO");
			break;
		case 10 : 
			sprintf(str,"CTR NAND RW");
			break;
		case 11 : 
			sprintf(str,"CTR NAND RO (Write Access)");
			break;
		case 12 : 
			sprintf(str,"Category System Settings");
			break;
		case 13 : 
			sprintf(str,"CARD BOARD");
			break;
		case 14 : 
			sprintf(str,"Export Import IVS");
			break;
		case 15 : 
			sprintf(str,"Direct SDMC (Write Only)");
			break;
		case 16 : 
			sprintf(str,"Switch Cleanup");
			break;
		case 17 : 
			sprintf(str,"Save Data Move");
			break;
		case 18 : 
			sprintf(str,"Shop");
			break;
		case 19 : 
			sprintf(str,"Shell");
			break;
		case 20 : 
			sprintf(str,"Category HomeMenu");
			break;
		default : 
			sprintf(str,"Bit %d (unknown)",bit);
			break;
	}
	
	return str;
}

void exheader_print_arm11accessinfo(exheader_context* ctx)
{
	char str[100];
	u64 i, bit;
	for(i = 0; i < 56; i++)
	{
		bit = ((u64)1 << i);
		if((ctx->system_local_caps.accessinfo & bit) == bit)
			fprintf(stdout, " > %s\n",exheader_print_accessinfobit((u32)i,str)); 
	}
}

void exheader_print_arm11storageinfo(exheader_context* ctx)
{
	u32 i;

	fprintf(stdout, "Ext savedata id:        0x%"PRIx64"\n",ctx->system_local_caps.extdata_id);
	for(i = 0; i < 2; i++)
		fprintf(stdout, "System savedata id %d:   0x%x %s\n",i+1, ctx->system_local_caps.system_saveid[i],exheader_getvalidstring(ctx->validsystemsaveID[i]));
	for(i = 0; i < 3; i++)
		fprintf(stdout, "OtherUserSaveDataId%d:   0x%x\n",i+1, ctx->system_local_caps.other_user_saveid[i]);
	fprintf(stdout, "Accessible Savedata Ids:\n");
	for(i = 0; i < 6; i++)
	{
		if(ctx->system_local_caps.accessible_saveid[i] != 0x00000)
			fprintf(stdout, " > 0x%05x\n", ctx->system_local_caps.accessible_saveid[i]);
	}
	
	fprintf(stdout, "Other Variation Saves:  %s\n", ctx->system_local_caps.use_other_variation_savedata ? "Accessible" : "Inaccessible");
	fprintf(stdout, "Access info:            0x%"PRIx64" %s\n", ctx->system_local_caps.accessinfo,exheader_getvalidstring(ctx->validaccessinfo));
	exheader_print_arm11accessinfo(ctx);	
}

int exheader_signature_verify(exheader_context* ctx, rsakey2048* key)
{
	u8 hash[0x20];

	ctr_sha_256(ctx->header.accessdesc.ncchpubkeymodulus, 0x300, hash);
	return ctr_rsa_verify_hash(ctx->header.accessdesc.signature, hash, key);
}

void exheader_verify(exheader_context* ctx)
{
	unsigned int i, j;
	exheader_arm11systemlocalcaps_deserialised accessdesc;

	exheader_deserialise_arm11localcaps_permissions(&accessdesc, &ctx->header.accessdesc.arm11systemlocalcaps);

	ctx->validsystemsaveID[0] = Good;
	ctx->validsystemsaveID[1] = Good;
	ctx->validaccessinfo = Good;
	ctx->validcoreversion = Good;
	ctx->validprogramid = Good;
	ctx->validpriority = Good;
	ctx->validaffinitymask = Good;
	ctx->valididealprocessor = Good;
	ctx->validold3dssystemmode = Good;
	ctx->validnew3dssystemmode = Good;
	ctx->validenablel2cache = Good;
	ctx->validnew3dscpuspeed = Good;
	ctx->validservicecontrol = Good;

	for(i=0; i<8; i++)
	{
		if (ctx->system_local_caps.program_id[i] == accessdesc.program_id[i] || accessdesc.program_id[i] == 0xFF)
			continue;
		ctx->validprogramid = Fail;
		break;
	}

	if (ctx->system_local_caps.core_version != accessdesc.core_version)
		ctx->validcoreversion = Fail;

	if (ctx->system_local_caps.priority < accessdesc.priority)
		ctx->validpriority = Fail;

	if((1<<ctx->system_local_caps.ideal_processor & accessdesc.ideal_processor) == 0)
		ctx->valididealprocessor = Fail;

	if (ctx->system_local_caps.affinity_mask & ~accessdesc.affinity_mask)
		ctx->validaffinitymask = Fail;

	if (ctx->system_local_caps.old3ds_systemmode > accessdesc.old3ds_systemmode)
		ctx->validold3dssystemmode = Fail;

	if (ctx->system_local_caps.new3ds_systemmode > accessdesc.new3ds_systemmode)
		ctx->validnew3dssystemmode = Fail;

	if (ctx->system_local_caps.enable_l2_cache != accessdesc.enable_l2_cache)
		ctx->validenablel2cache = Fail;

	if (ctx->system_local_caps.new3ds_cpu_speed != accessdesc.new3ds_cpu_speed)
		ctx->validnew3dscpuspeed = Fail;




	// Storage Info Verify
	if(ctx->system_local_caps.system_saveid[0] & ~accessdesc.system_saveid[0])
		ctx->validsystemsaveID[0] = Fail;
	if(ctx->system_local_caps.system_saveid[1] & ~accessdesc.system_saveid[1])
		ctx->validsystemsaveID[1] = Fail;


	if (ctx->system_local_caps.accessinfo & ~accessdesc.accessinfo)
		ctx->validaccessinfo = Fail;

	// Service Access Control
	for (i = 0; i < 34; i++) {
		if (strlen(ctx->system_local_caps.service_access_control[i]) == 0)
			continue;

		for (j = 0; j < 34; j++) {
			if (strcmp(ctx->system_local_caps.service_access_control[i], accessdesc.service_access_control[j]) == 0)
				break;
		}

		if (strcmp(ctx->system_local_caps.service_access_control[i], accessdesc.service_access_control[j]) == 0)
			continue;

		ctx->validservicecontrol = Fail;
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

const char* exheader_getsystemmodestring(u8 systemmode)
{
	switch (systemmode)
	{
	case (sysmode_64MB) :
		return "64MB";
	case (sysmode_96MB) :
		return "96MB";
	case (sysmode_80MB) :
		return "80MB";
	case (sysmode_72MB) :
		return "72MB";
	case (sysmode_32MB) :
		return "32MB";
	default:
		return "Unknown";
	}
}

const char* exheader_getsystemmodeextstring(u8 systemmodeext, u8 systemmode)
{
	switch (systemmodeext)
	{
	case (sysmode_ext_LEGACY) :
		return exheader_getsystemmodestring(systemmode);
	case (sysmode_ext_124MB) :
		return "124MB";
	case (sysmode_ext_178MB) :
		return "178MB";
	default:
		return "124MB";
	}
}


void exheader_print(exheader_context* ctx, u32 actions)
{
	u32 i;
	u64 savedatasize = getle64(ctx->header.systeminfo.savedatasize);
	exheader_codesetinfo* codesetinfo = &ctx->header.codesetinfo;


	fprintf(stdout, "\nExtended header:\n");
	if (ctx->validsignature == Unchecked)
		memdump(stdout, "Signature:              ", ctx->header.accessdesc.signature, 0x100);
	else if (ctx->validsignature == Good)
		memdump(stdout, "Signature (GOOD):       ", ctx->header.accessdesc.signature, 0x100);
	else if (ctx->validsignature == Fail)
		memdump(stdout, "Signature (FAIL):       ", ctx->header.accessdesc.signature, 0x100);
	printf("\n");
	memdump(stdout, "NCCH Hdr RSA Modulus:   ", ctx->header.accessdesc.ncchpubkeymodulus, 0x100);
	fprintf(stdout, "Name:                   %.8s\n", codesetinfo->name);
	fprintf(stdout, "Flag:                   %02X ", codesetinfo->flags.flag);
	if (codesetinfo->flags.flag & 1)
		fprintf(stdout, "[compressed]");
	if (codesetinfo->flags.flag & 2)
		fprintf(stdout, "[sd app]");
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
			fprintf(stdout, "Dependency:             %016"PRIx64"\n", getle64(ctx->header.deplist.programid[i]));
	}
	if(savedatasize < sizeKB)
		fprintf(stdout, "Savedata size:          0x%"PRIx64"\n", savedatasize);
	else if(savedatasize < sizeMB)
		fprintf(stdout, "Savedata size:          %"PRIu64"K\n", savedatasize/sizeKB);
	else
		fprintf(stdout, "Savedata size:          %"PRIu64"M\n", savedatasize/sizeMB);
	fprintf(stdout, "Jump id:                %016"PRIx64"\n", getle64(ctx->header.systeminfo.jumpid));

	fprintf(stdout, "Program id:             %016"PRIx64" %s\n", getle64(ctx->header.arm11systemlocalcaps.programid), exheader_getvalidstring(ctx->validprogramid));
	fprintf(stdout, "Core version:           0x%X\n", getle32(ctx->header.arm11systemlocalcaps.coreversion));
	fprintf(stdout, "System mode:            %s %s\n", exheader_getsystemmodestring(ctx->system_local_caps.old3ds_systemmode), exheader_getvalidstring(ctx->validold3dssystemmode));
	fprintf(stdout, "System mode (New3DS):   %s %s\n", exheader_getsystemmodeextstring(ctx->system_local_caps.new3ds_systemmode, ctx->system_local_caps.old3ds_systemmode), exheader_getvalidstring(ctx->validnew3dssystemmode));
	fprintf(stdout, "CPU Speed (New3DS):     %s %s\n", ctx->system_local_caps.new3ds_cpu_speed? "804MHz" : "268MHz", exheader_getvalidstring(ctx->validnew3dscpuspeed));
	fprintf(stdout, "Enable L2 Cache:        %s %s\n", ctx->system_local_caps.enable_l2_cache ? "YES" : "NO", exheader_getvalidstring(ctx->validnew3dscpuspeed));
	fprintf(stdout, "Ideal processor:        %d %s\n", ctx->system_local_caps.ideal_processor, exheader_getvalidstring(ctx->valididealprocessor));
	fprintf(stdout, "Affinity mask:          %d %s\n", ctx->system_local_caps.affinity_mask, exheader_getvalidstring(ctx->validaffinitymask));
	fprintf(stdout, "Main thread priority:   %d %s\n", ctx->system_local_caps.priority, exheader_getvalidstring(ctx->validpriority));
	// print resource limit descriptor too? currently mostly zeroes...
	exheader_print_arm11storageinfo(ctx);
	exheader_print_arm11kernelcapabilities(ctx, actions);
	exheader_print_arm9accesscontrol(ctx);

	fprintf(stdout, "Service access: %s\n", exheader_getvalidstring(ctx->validservicecontrol));
	for(i=0; i<34; i++)
	{
		if (strlen(ctx->system_local_caps.service_access_control[i]) > 0)
			fprintf(stdout, " > %s\n", ctx->system_local_caps.service_access_control[i]);
	}
	fprintf(stdout, "Reslimit category:      %02X\n", ctx->header.arm11systemlocalcaps.resourcelimitcategory);
}
