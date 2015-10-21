#ifndef _EXHEADER_H_
#define _EXHEADER_H_

#include <stdio.h>
#include "types.h"
#include "ctr.h"
#include "settings.h"

typedef enum
{
	sysmode_64MB,
	sysmode_UNK,
	sysmode_96MB,
	sysmode_80MB,
	sysmode_72MB,
	sysmode_32MB,
} exheader_systemmode;

typedef enum
{
	sysmode_ext_LEGACY,
	sysmode_ext_124MB,
	sysmode_ext_178MB,
} exheader_systemmodeext;

typedef struct
{
	u8 reserved[5];
	u8 flag;
	u8 remasterversion[2];
} exheader_systeminfoflags;

typedef struct
{
	u8 address[4];
	u8 nummaxpages[4];
	u8 codesize[4];
} exheader_codesegmentinfo;

typedef struct
{
	u8 name[8];
	exheader_systeminfoflags flags;
	exheader_codesegmentinfo text;
	u8 stacksize[4];
	exheader_codesegmentinfo ro;
	u8 reserved[4];
	exheader_codesegmentinfo data;
	u8 bsssize[4];
} exheader_codesetinfo;

typedef struct
{
	u8 programid[0x30][8];
} exheader_dependencylist;

typedef struct
{
	u8 savedatasize[8];
	u8 jumpid[8];
	u8 reserved2[0x30];
} exheader_systeminfo;

typedef struct
{
	u8 extsavedataid[8];
	u8 systemsavedataid[8];
	u8 accessibleuniqueids[8];
	u8 accessinfo[7];
	u8 otherattributes;
} exheader_storageinfo;

typedef struct
{
	u8 programid[8];
	u8 coreversion[4];
	u8 flag[4];
	u8 resourcelimitdescriptor[0x10][2];
	exheader_storageinfo storageinfo;
	u8 serviceaccesscontrol[34][8];
	u8 reserved[0xf];
	u8 resourcelimitcategory;
} exheader_arm11systemlocalcaps;

typedef struct 
{
	u8 program_id[8];
	u32 core_version;

	// flag
	u8 enable_l2_cache;
	u8 new3ds_cpu_speed;
	u8 new3ds_systemmode;
	u8 ideal_processor;
	u8 affinity_mask;
	u8 old3ds_systemmode;
	s8 priority;

	// storageinfo
	u64 extdata_id;
	u32 other_user_saveid[3];
	u8 use_other_variation_savedata;
	u32 accessible_saveid[6];
	u32 system_saveid[2];
	u64 accessinfo;


	char service_access_control[34][10];
	u8 resource_limit_category;
} exheader_arm11systemlocalcaps_deserialised;

typedef struct
{
	u8 descriptors[28][4];
	u8 reserved[0x10];
} exheader_arm11kernelcapabilities;

typedef struct
{
	u8 descriptors[15];
	u8 descversion;
} exheader_arm9accesscontrol;

typedef struct
{
	// systemcontrol info {
	//   coreinfo {
	exheader_codesetinfo codesetinfo;
	exheader_dependencylist deplist;
	//   }
	exheader_systeminfo systeminfo;
	// }
	// accesscontrolinfo {
	exheader_arm11systemlocalcaps arm11systemlocalcaps;
	exheader_arm11kernelcapabilities arm11kernelcaps;
	exheader_arm9accesscontrol arm9accesscontrol;
	// }
	struct {
		u8 signature[0x100];
		u8 ncchpubkeymodulus[0x100];
		exheader_arm11systemlocalcaps arm11systemlocalcaps;
		exheader_arm11kernelcapabilities arm11kernelcaps;
		exheader_arm9accesscontrol arm9accesscontrol;
	} accessdesc;
} exheader_header;

typedef struct
{
	int haveread;
	FILE* file;
	settings* usersettings;
	u8 partitionid[8];
	u8 programid[8];
	u8 hash[32];
	u8 counter[16];
	u8 key[16];
	u32 offset;
	u32 size;
	exheader_header header;

	exheader_arm11systemlocalcaps_deserialised system_local_caps;

	ctr_aes_context aes;
	ctr_rsa_context rsa;
	int compressedflag;
	int encrypted;
	int validprogramid;
	int validpriority;
	int validaffinitymask;
	int valididealprocessor;
	int validold3dssystemmode;
	int validnew3dssystemmode;
	int validenablel2cache;
	int validnew3dscpuspeed;
	int validcoreversion;
	int validsystemsaveID[2];
	int validaccessinfo;
	int validservicecontrol;
	int validsignature;
} exheader_context;

void exheader_init(exheader_context* ctx);
void exheader_set_file(exheader_context* ctx, FILE* file);
void exheader_set_offset(exheader_context* ctx, u32 offset);
void exheader_set_size(exheader_context* ctx, u32 size);
void exheader_set_partitionid(exheader_context* ctx, u8 partitionid[8]);
void exheader_set_counter(exheader_context* ctx, u8 counter[16]);
void exheader_set_programid(exheader_context* ctx, u8 programid[8]);
void exheader_set_hash(exheader_context* ctx, u8 hash[32]);
void exheader_set_encrypted(exheader_context* ctx, u32 encrypted);
void exheader_set_key(exheader_context* ctx, u8 key[16]);
void exheader_set_usersettings(exheader_context* ctx, settings* usersettings);
int exheader_get_compressedflag(exheader_context* ctx);
void exheader_read(exheader_context* ctx, u32 actions);
int exheader_process(exheader_context* ctx, u32 actions);
const char* exheader_getvalidstring(int valid);
void exheader_print(exheader_context* ctx);
void exheader_verify(exheader_context* ctx);
int exheader_hash_valid(exheader_context* ctx);
int exheader_programid_valid(exheader_context* ctx);
void exheader_determine_key(exheader_context* ctx, u32 actions);

#endif // _EXHEADER_H_
