#include "lib.h"
#include "dir.h"
#include "ncch_build.h"
#include "romfs.h"

const int ROMFS_BLOCK_SIZE = 0x1000;
const unsigned int ROMFS_UNUSED_ENTRY = 0xffffffff;

// Build
bool IsFileWanted(fs_file *file, void *filter_criteria);
bool IsDirWanted(fs_dir *dir, void *filter_criteria);
void CalcDirSize(romfs_buildctx *ctx, fs_dir *fs);
int CalcRomfsSize(romfs_buildctx *ctx);
int AddFileToRomfs(romfs_buildctx *ctx, fs_file *file, u32 parent, u32 sibling);
int AddDirToRomfs(romfs_buildctx *ctx, fs_dir *fs, u32 parent, u32 sibling);
int FilterRomFS(fs_dir *fs_raw, fs_dir *fs_filtered, void *filter_criteria);
int PopulateRomfs(romfs_buildctx *ctx);
void BuildRomfsHeader(romfs_buildctx *ctx);
void BuildIvfcHeader(romfs_buildctx *ctx);
void GenIvfcHashTree(romfs_buildctx *ctx);


int PrepareBuildRomFsBinary(ncch_settings *ncchset, romfs_buildctx *ctx)
{
	// Input Path
	//printf("Get input path\n");

	const int CWD_MAX_LEN = 1024;
	char *cwd = calloc(CWD_MAX_LEN,sizeof(char));
	getcwd(cwd,CWD_MAX_LEN);

	char *dir = ncchset->rsfSet->Rom.HostRoot;

	fs_char *fs_path;
	fs_romfs_char *path;
	u32 path_len;
#ifdef _WIN32
	str_u8_to_u16(&path,&path_len,(u8*)dir,strlen(dir));
	fs_path = path;
#else
	str_utf8_to_u16(&path,&path_len,(u8*)dir,strlen(dir));
	fs_path = dir;
#endif

	// FS Structures
	void *filter_criteria = NULL;
	//printf("calloc fs_raw\n");
	fs_dir *fs_raw = calloc(1,sizeof(fs_dir));
	//printf("calloc ctx->fs\n");
	ctx->fs = calloc(1,sizeof(fs_dir));
	//memdump(stdout,"ctx->fs: ",(u8*)ctx->fs,sizeof(fs_dir));
	//printf("ctx->fs = 0x%x\n",ctx->fs);

	// Import FS and process
	//printf("open fs into fs_raw\n");
	fs_OpenDir(fs_path,path,path_len,fs_raw);
	//printf("filter fs_raw into ctx->fs\n");
	FilterRomFS(fs_raw,ctx->fs,filter_criteria);
	
	// free unfiltered FS
	//fs_PrintDir(fs_raw,0);
	//printf("free discarded file ptrs\n");
	fs_FreeFiles(fs_raw); // All important FPs have been moved with FilterRomFS, so only un-wanted FPs are closed here
	//printf("free structs in fs_raw\n");
	fs_FreeDir(fs_raw);
	//printf("free fs_raw\n");
	free(fs_raw);
	
	//printf("leave if no ROMFS needs to be made\n");
	if(ctx->fs->u_file == 0){
		ctx->romfsSize = 0;
		goto finish;
	}
	
	
	// Print Filtered FS
	//printf("print filtered FS\n");
	if(ncchset->options.verbose){
		printf("[ROMFS] File System:\n");
		fs_PrintDir(ctx->fs,0);
	}
	
	//printf("predict romfs size\n");
	CalcRomfsSize(ctx);
	
finish:
	chdir(cwd);
	return 0;
}

int BuildRomFsBinary(romfs_buildctx *ctx)
{
	// Decide IVFC Level Actual Offsets
	ctx->level[0].offset = 0;
	ctx->level[3].offset = ctx->level[0].offset + align(ctx->level[0].size, ROMFS_BLOCK_SIZE);
	ctx->level[1].offset = ctx->level[3].offset + align(ctx->level[3].size, ROMFS_BLOCK_SIZE);
	ctx->level[2].offset = ctx->level[1].offset + align(ctx->level[1].size, ROMFS_BLOCK_SIZE);
	
	// Decide IVFC Level Logical Offsets
	for(int i = 1; i < 4; i++){
		if(i == 1)
			ctx->level[i].logicalOffset = 0;
		else
			ctx->level[i].logicalOffset = align(ctx->level[i-1].logicalOffset + ctx->level[i-1].size,ROMFS_BLOCK_SIZE);
	}
	
	// Setup IVFC Level Ptrs
	for(int i = 0; i < 4; i++){
		ctx->level[i].pos = (ctx->output + ctx->level[i].offset);
		if(i == 0)
			ctx->level[i].pos += align(sizeof(ivfc_hdr),0x10);
	}
	
	// Build Romfs
	ctx->romfsHdr = (romfs_infoheader*)(ctx->level[3].pos);
	BuildRomfsHeader(ctx);
	if(PopulateRomfs(ctx) != 0)
		return -1;
	
	
	// Finalise by building IVFC hash tree
	ctx->ivfcHdr = (ivfc_hdr*)(ctx->output + ctx->level[0].offset);
	BuildIvfcHeader(ctx);
	GenIvfcHashTree(ctx);

	return 0;
}


bool IsFileWanted(fs_file *file, void *filter_criteria)
{
	return true;
}

bool IsDirWanted(fs_dir *dir, void *filter_criteria)
{
	bool ret = false;
	for(u32 i = 0; i < dir->u_file; i++)
	{
		if(IsFileWanted(&dir->file[i],filter_criteria))
		{
			ret = true;
			break;
		}
	}
	fs_dir *tmp = (fs_dir*)dir->dir;
	for(u32 i = 0; i < dir->u_dir; i++)
	{
		if(IsDirWanted(&tmp[i],filter_criteria))
		{
			ret = true;
			break;
		}
	}
	return ret;
}

void CalcDirSize(romfs_buildctx *ctx, fs_dir *fs)
{
	if(ctx->m_dirTableLen == 0)
		ctx->m_dirTableLen = sizeof(romfs_direntry);
	else
		ctx->m_dirTableLen += sizeof(romfs_direntry) + align(fs->name_len,4);
		
	for(u32 i = 0; i < fs->u_file; i++)
	{
		ctx->m_fileTableLen += sizeof(romfs_fileentry) + align(fs->file[i].name_len,4);
		if(fs->file[i].size)
			ctx->m_dataLen =  align(ctx->m_dataLen,0x10) + fs->file[i].size;
	}
	
	fs_dir *dir = (fs_dir*)fs->dir;
	for(u32 i = 0; i < fs->u_dir; i++)
	{
		CalcDirSize(ctx,&dir[i]);
	}
	ctx->fileNum += fs->u_file;
	ctx->dirNum += fs->u_dir;
}

int CalcRomfsSize(romfs_buildctx *ctx)
{
	ctx->dirNum = 1; // root dir
	//printf("Recursively get FS sizes\n");
	CalcDirSize(ctx,ctx->fs);
	
	//printf("check U tables\n");
	ctx->u_dirUTableEntry = 0;
	ctx->m_dirUTableEntry = 3;
	if(ctx->dirNum > 3)
		ctx->m_dirUTableEntry += align(ctx->dirNum-3,2);
		
	ctx->u_fileUTableEntry = 0;
	ctx->m_fileUTableEntry = 3;
	if(ctx->fileNum > 3)
		ctx->m_fileUTableEntry += align(ctx->fileNum-3,2);
	
	//printf("calc romfs header size\n");
	u32 romfsHdrSize = align(sizeof(romfs_infoheader) + ctx->m_dirUTableEntry*sizeof(u32) + ctx->m_dirTableLen + ctx->m_fileUTableEntry*sizeof(u32) + ctx->m_fileTableLen,0x10); 
	
	//printf("predict level sizes\n");
	ctx->level[3].size = romfsHdrSize + ctx->m_dataLen; // data
	ctx->level[2].size = align(ctx->level[3].size,ROMFS_BLOCK_SIZE) / ROMFS_BLOCK_SIZE * 0x20 ;
	ctx->level[1].size = align(ctx->level[2].size,ROMFS_BLOCK_SIZE) / ROMFS_BLOCK_SIZE * 0x20 ;
	ctx->level[0].size = align(ctx->level[1].size,ROMFS_BLOCK_SIZE) / ROMFS_BLOCK_SIZE * 0x20 + align(sizeof(ivfc_hdr),0x10); // hdr
	
	ctx->romfsHeaderSize = ctx->level[0].size;

	//printf("calc total ROMFS size\n");
	ctx->romfsSize = 0;
	for(int i = 0; i < 4; i++)
		ctx->romfsSize += align(ctx->level[i].size,ROMFS_BLOCK_SIZE);
		
	//printf("return from CalcRomfsSize();\n");
	return 0;
}

int FilterRomFS(fs_dir *fs_raw, fs_dir *fs_filtered, void *filter_criteria)
{
	memset(fs_filtered,0,sizeof(fs_dir));
	if(!IsDirWanted(fs_raw,filter_criteria))
		return 0;
	
	fs_filtered->name_len = fs_raw->name_len;
	fs_filtered->name = calloc(fs_filtered->name_len+2,1);
	memcpy(fs_filtered->name,fs_raw->name,fs_filtered->name_len);
	
	fs_filtered->u_dir = 0;
	fs_filtered->m_dir = fs_raw->u_dir;
	fs_filtered->dir = calloc(fs_filtered->m_dir,sizeof(fs_dir));
	
	fs_filtered->u_file = 0;
	fs_filtered->m_file = fs_raw->u_file;
	fs_filtered->file = calloc(fs_filtered->m_file,sizeof(fs_file));
	
	
	fs_dir *dir_raw = (fs_dir*)fs_raw->dir;
	fs_dir *dir_filtered = (fs_dir*)fs_filtered->dir;
	for(u32 i = 0; i < fs_raw->u_dir; i++)
	{
		if(IsDirWanted(&dir_raw[i],filter_criteria))
		{
			FilterRomFS(&dir_raw[i],&dir_filtered[fs_filtered->u_dir],filter_criteria);
			fs_filtered->u_dir++;
		}
	}
	
	for(u32 i = 0; i < fs_raw->u_file; i++)
	{
		if(IsFileWanted(&fs_raw->file[i],filter_criteria))
		{
			fs_filtered->file[fs_filtered->u_file].name_len = fs_raw->file[i].name_len;
			fs_filtered->file[fs_filtered->u_file].name = malloc(fs_filtered->file[fs_filtered->u_file].name_len+2);
			memset(fs_filtered->file[fs_filtered->u_file].name,0,fs_filtered->file[fs_filtered->u_file].name_len+2);
			memcpy(fs_filtered->file[fs_filtered->u_file].name,fs_raw->file[i].name,fs_filtered->file[fs_filtered->u_file].name_len);
			
			fs_filtered->file[fs_filtered->u_file].size = fs_raw->file[i].size;
			
			fs_filtered->file[fs_filtered->u_file].fp = fs_raw->file[i].fp;
			fs_raw->file[i].fp = NULL;
			
			fs_filtered->u_file++;
		}
	}
	
	return 0;
}

void BuildRomfsHeader(romfs_buildctx *ctx)
{
	u32 level3_pos = 0;
	
	u32_to_u8(ctx->romfsHdr->headersize,sizeof(romfs_infoheader),LE);
	
	level3_pos += sizeof(romfs_infoheader);
	
	for(int i = 0; i < 4; i++){
		if(i == 0){
			ctx->dirUTable = (u32*)(ctx->level[3].pos + level3_pos);
			u32_to_u8(ctx->romfsHdr->section[i].offset,level3_pos,LE);
			u32_to_u8(ctx->romfsHdr->section[i].size,ctx->m_dirUTableEntry*sizeof(u32),LE);
			level3_pos += ctx->m_dirUTableEntry*sizeof(u32);
		}
		else if(i == 1 && ctx->m_dirTableLen){
			ctx->dirTable = ctx->level[3].pos + level3_pos;
			u32_to_u8(ctx->romfsHdr->section[i].offset,level3_pos,LE);
			u32_to_u8(ctx->romfsHdr->section[i].size,ctx->m_dirTableLen,LE);
			level3_pos += ctx->m_dirTableLen;
		}
		else if(i == 2){
			ctx->fileUTable = (u32*)(ctx->level[3].pos + level3_pos);
			u32_to_u8(ctx->romfsHdr->section[i].offset,level3_pos,LE);
			u32_to_u8(ctx->romfsHdr->section[i].size,ctx->m_fileUTableEntry*sizeof(u32),LE);
			level3_pos += ctx->m_fileUTableEntry*sizeof(u32);
		}
		else if(i == 3 && ctx->m_fileTableLen){
			ctx->fileTable = ctx->level[3].pos + level3_pos;
			u32_to_u8(ctx->romfsHdr->section[i].offset,level3_pos,LE);
			u32_to_u8(ctx->romfsHdr->section[i].size,ctx->m_fileTableLen,LE);
			level3_pos += ctx->m_fileTableLen;
		}
		else{
			u32_to_u8(ctx->romfsHdr->section[i].offset,0,LE);
			u32_to_u8(ctx->romfsHdr->section[i].size,0,LE);
		}
	}
	
	ctx->data = ctx->level[3].pos + align(level3_pos,0x10);
	u32_to_u8(ctx->romfsHdr->dataoffset,align(level3_pos,0x10),LE);
	
	memset(ctx->dirUTable,0xff,ctx->m_dirUTableEntry*sizeof(u32));
	memset(ctx->fileUTable,0xff,ctx->m_fileUTableEntry*sizeof(u32));
	
	return;
}

u32 GetFileUTableIndex(romfs_buildctx *ctx, fs_file *file)
{
	u32 ret = ctx->u_fileUTableEntry;
	ctx->u_fileUTableEntry++;
	return ret;
}

u32 GetDirUTableIndex(romfs_buildctx *ctx, fs_dir *dir)
{
	u32 ret = ctx->u_dirUTableEntry;
	ctx->u_dirUTableEntry++;
	return ret;
}

int AddFileToRomfs(romfs_buildctx *ctx, fs_file *file, u32 parent, u32 sibling)
{
	romfs_fileentry *entry = (romfs_fileentry*)(ctx->fileTable + ctx->u_fileTableLen);
	
	u32_to_u8(entry->parentdiroffset,parent,LE);
	u32_to_u8(entry->siblingoffset,sibling,LE);
	
	u32 uTableIndex = GetFileUTableIndex(ctx,file);
	u32_to_u8(entry->weirdoffset,ctx->fileUTable[uTableIndex],LE);
	ctx->fileUTable[uTableIndex] = ctx->u_fileTableLen;
	
	// Import Name
	u32_to_u8(entry->namesize,file->name_len,LE);
	u8 *name_pos = (u8*)(ctx->fileTable + ctx->u_fileTableLen + sizeof(romfs_fileentry));
	memset(name_pos,0,align(file->name_len,4));
	memcpy(name_pos,(u8*)file->name,file->name_len);
	
	// Import Data
	if(file->size)
	{
		ctx->u_dataLen = align(ctx->u_dataLen,0x10); // Padding
		u64_to_u8(entry->dataoffset,ctx->u_dataLen,LE);
		u64_to_u8(entry->datasize,file->size,LE);
		u8 *data_pos = (ctx->data + ctx->u_dataLen);
		ReadFile64(data_pos,file->size,0,file->fp);
		ctx->u_dataLen += file->size; // adding file size
	}
	else
		u64_to_u8(entry->dataoffset,0x40,LE);
	
	ctx->u_fileTableLen += sizeof(romfs_fileentry) + align(file->name_len,4);
		
	return 0;
}

int AddDirToRomfs(romfs_buildctx *ctx, fs_dir *fs, u32 parent, u32 sibling)
{
	//wprintf(L"adding %s \n",fs->name);
	romfs_direntry *entry = (romfs_direntry*)(ctx->dirTable + ctx->u_dirTableLen);
	
	u32_to_u8(entry->parentoffset,parent,LE);
	u32_to_u8(entry->siblingoffset,sibling,LE);
	
	u32 uTableIndex = GetDirUTableIndex(ctx,fs);
	u32_to_u8(entry->weirdoffset,ctx->dirUTable[uTableIndex],LE);
	ctx->dirUTable[uTableIndex] = ctx->u_dirTableLen;

	u32 Currentdir = ctx->u_dirTableLen;
	
	if(Currentdir == 0)
	{
		u32_to_u8(entry->namesize,0,LE);
		ctx->u_dirTableLen += sizeof(romfs_direntry);
	}
	else
	{
		u32_to_u8(entry->namesize,fs->name_len,LE);
		u8 *name_pos = (u8*)(ctx->dirTable + ctx->u_dirTableLen + sizeof(romfs_direntry));
		memset(name_pos,0,(u32)align(fs->name_len,4));
		memcpy(name_pos,(u8*)fs->name,fs->name_len);
		ctx->u_dirTableLen += sizeof(romfs_direntry) + (u32)align(fs->name_len,4);
	}
	
	if(fs->u_file)
	{
		u32_to_u8(entry->fileoffset,ctx->u_fileTableLen,LE);
		for(u32 i = 0; i < fs->u_file; i++)
		{
			u32 file_sibling = 0;
			if(i >= fs->u_file-1)
				file_sibling = ROMFS_UNUSED_ENTRY;
			else
				file_sibling = ctx->u_fileTableLen + sizeof(romfs_fileentry) + (u32)align(fs->file[i].name_len,4);
			//wprintf(L"adding %s (0x%lx)\n",fs->file[i].name,fs->file[i].size);
			AddFileToRomfs(ctx,&fs->file[i],Currentdir,file_sibling);
			//wprintf(L"added %s (0x%lx)\n",fs->file[i].name,fs->file[i].size);
		}
	}
	else
		u32_to_u8(entry->fileoffset,ROMFS_UNUSED_ENTRY,LE);
	
	//printf("Checking if to add dirs\n");
	if(fs->u_dir)
	{
		//printf(" is adding dirs \n");
		u32_to_u8(entry->childoffset,ctx->u_dirTableLen,LE);
		fs_dir *dir = (fs_dir*)fs->dir;
		for(u32 i = 0; i < fs->u_dir; i++)
		{
			u32 dir_sibling = 0;
			if(i >= fs->u_dir-1)
				dir_sibling = ROMFS_UNUSED_ENTRY;
			else
			{
				//printf(" dir has sibling\n");
				dir_sibling = ctx->u_dirTableLen + sizeof(romfs_direntry) + (u32)align(dir[i].name_len,4);
			}
			AddDirToRomfs(ctx,&dir[i],Currentdir,dir_sibling);
		}
	}
	else
		u32_to_u8(entry->childoffset,ROMFS_UNUSED_ENTRY,LE);
	//printf(" finished adding dirs \n");

	//wprintf(L"added %s \n",fs->name);
	return 0;
}

int PopulateRomfs(romfs_buildctx *ctx)
{
	return AddDirToRomfs(ctx,ctx->fs,0x0,ROMFS_UNUSED_ENTRY);
}

void BuildIvfcHeader(romfs_buildctx *ctx)
{
	memcpy(ctx->ivfcHdr->magic,"IVFC",4);
	u32_to_u8(ctx->ivfcHdr->id,0x10000,LE);
	
	u32 masterHashSize = ( align(ctx->level[1].size,ROMFS_BLOCK_SIZE) / ROMFS_BLOCK_SIZE ) * 0x20 ;
	u32_to_u8(ctx->ivfcHdr->masterHashSize,masterHashSize,LE);
	
	for(int i = 1; i < 4; i++){
		u64_to_u8(ctx->ivfcHdr->level[i-1].logicalOffset,ctx->level[i].logicalOffset,LE);
		u64_to_u8(ctx->ivfcHdr->level[i-1].hashDataSize,ctx->level[i].size,LE);
		u32_to_u8(ctx->ivfcHdr->level[i-1].blockSize,log2l(ROMFS_BLOCK_SIZE),LE);
	}
	
	u32_to_u8(ctx->ivfcHdr->optionalSize,sizeof(ivfc_hdr),LE);
	
	return;
}

void GenIvfcHashTree(romfs_buildctx *ctx)
{
	for(int i = 2; i >= 0; i--){
		u32 numHashes = align(ctx->level[i+1].size,ROMFS_BLOCK_SIZE) / ROMFS_BLOCK_SIZE;
		for(u32 j = 0; j < numHashes; j++){
			u8 *datapos = (u8*)(ctx->level[i+1].pos + ROMFS_BLOCK_SIZE * j);
			u8 *hashpos = (u8*)(ctx->level[i].pos + 0x20 * j);
			ShaCalc(datapos, ROMFS_BLOCK_SIZE, hashpos, CTR_SHA_256);
		}
	}
	
	return;
}