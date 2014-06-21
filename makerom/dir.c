#include "lib.h"
#include "dir.h"
#include "utf.h"

/* This is mainly a FS interface for ROMFS generation */


int fs_InitDir(u16 *path, u32 pathlen, fs_dir *dir);
int fs_ManageDirSlot(fs_dir *dir);
int fs_ManageFileSlot(fs_dir *dir);
void fs_chdirUp(void);
fs_entry* fs_GetEntry(fs_DIR *dp);
void fs_FreeEntry(fs_entry *entry);
bool fs_EntryIsDirNav(fs_entry *entry);
int fs_AddDir(fs_entry *entry, fs_dir *dir);
int fs_AddFile(fs_entry *entry, fs_dir *dir);

int fs_InitDir(u16 *path, u32 pathlen, fs_dir *dir)
{
	dir->name_len = pathlen;
	dir->name = calloc(dir->name_len+2,1);	
	memcpy(dir->name,path,dir->name_len);
	
	
	dir->m_dir = 10;
	dir->u_dir = 0;
	dir->dir = calloc(dir->m_dir,sizeof(fs_dir));
	
	dir->m_file = 10;
	dir->u_file = 0;
	dir->file = calloc(dir->m_file,sizeof(fs_file));
	
	return 0;
}

int fs_ManageDirSlot(fs_dir *dir)
{
	if(dir->u_dir >= dir->m_dir)
	{
		dir->m_dir *= 2;
		fs_dir *tmp = calloc(dir->m_dir,sizeof(fs_dir));
		memcpy(tmp,dir->dir,sizeof(fs_dir)*dir->u_dir);
		free(dir->dir);
		dir->dir = tmp;
	}
	return 0;
}

int fs_ManageFileSlot(fs_dir *dir)
{
	if(dir->u_file >= dir->m_file)
	{
		dir->m_file *= 2;
		fs_file *tmp = calloc(dir->m_file,sizeof(fs_file));
		memcpy(tmp,dir->file,sizeof(fs_file)*dir->u_file);
		free(dir->file);
		dir->file = tmp;
	}
	return 0;
}

void fs_chdirUp(void)
{
#ifdef _WIN32
	fs_chdir(L"..");
#else
	fs_chdir("..");
#endif
}

fs_entry* fs_GetEntry(fs_DIR *dp)
{
	// Directory structs
	struct fs_dirent *tmp_entry;
	fs_DIR *tmp_dptr;
	u32 namlen = 0;
	
	//printf("get api dir entry from dir ptr\n");
	tmp_entry = fs_readdir(dp);
	
	//printf("if null, return\n");
	if(!tmp_entry) 
		return NULL;
		
#ifdef _WIN32
	namlen = tmp_entry->d_namlen;
#else
	namlen = strlen(tmp_entry->d_name);
#endif
		
	//printf("allocate memory for entry\n");
	fs_entry *entry  = malloc(sizeof(fs_entry));
	memset(entry,0,sizeof(fs_entry));
	
	//Copy FS compatible Entry name
	entry->fs_name = malloc(sizeof(fs_char)*(namlen+1));
	memset(entry->fs_name,0,sizeof(fs_char)*(namlen+1));
	memcpy(entry->fs_name,tmp_entry->d_name,sizeof(fs_char)*namlen);
	
	// Convert Entry name into RomFS u16 char (windows wchar_t, thanks Nintendo)
#if _WIN32
	str_u16_to_u16(&entry->name,&entry->name_len,tmp_entry->d_name,namlen);
#else
	str_utf8_to_u16(&entry->name,&entry->name_len,(u8*)tmp_entry->d_name,namlen);
#endif
	
	//printf("get dir entry from dir ptr to check if dir\n");
	tmp_dptr = fs_opendir(entry->fs_name);
	if(tmp_dptr)
	{
		//printf("is dir\n");
		fs_closedir(tmp_dptr);
		entry->IsDir = true;
		entry->size = 0;
		entry->fp = NULL;
	}
	else // Open file if it is a file
	{
		entry->IsDir = false;
#ifdef _WIN32
		entry->size = wGetFileSize_u64(entry->fs_name);
		entry->fp = _wfopen(entry->fs_name,L"rb");
#else
		entry->size = GetFileSize_u64(entry->fs_name);
		entry->fp = fopen(entry->fs_name,"rb");
#endif
	}
	//printf("fs_GetEntry() return\n");
	return entry;
}

void fs_FreeEntry(fs_entry *entry)
{
	free(entry->fs_name);
	free(entry->name);
	free(entry);
}

bool fs_EntryIsDirNav(fs_entry *entry)
{
	//memdump(stdout,"Entry RomFS Name: ",(u8*)entry->name,entry->name_len);
	const fs_romfs_char currentdir = 0x2E;
	const fs_romfs_char upperdir[2] = {0x2E,0x2E};
	if(entry->name_len == sizeof(fs_romfs_char)*1 && memcmp(entry->name,&currentdir,sizeof(fs_romfs_char)*1) == 0)
		return true;
	if(entry->name_len == sizeof(fs_romfs_char)*2 && memcmp(entry->name,upperdir,sizeof(fs_romfs_char)*2) == 0)
		return true;
	return false;
	
}

int fs_AddDir(fs_entry *entry, fs_dir *dir)
{
	fs_ManageDirSlot(dir);
	u32 current_slot = dir->u_dir;
	dir->u_dir++;
	fs_dir *tmp = (fs_dir*)dir->dir;
	return fs_OpenDir(entry->fs_name,entry->name,entry->name_len,&tmp[current_slot]);
}

int fs_AddFile(fs_entry *entry, fs_dir *dir)
{
	fs_ManageFileSlot(dir);
	dir->file[dir->u_file].name_len = entry->name_len;
	dir->file[dir->u_file].name = malloc(entry->name_len+2);
	memset(dir->file[dir->u_file].name,0,entry->name_len+2);	
	memcpy(dir->file[dir->u_file].name,entry->name,entry->name_len);
	
	dir->file[dir->u_file].size = entry->size;
	dir->file[dir->u_file].fp = entry->fp;
	
	dir->u_file++;
	return 0;
}

int fs_OpenDir(fs_char *fs_path, fs_romfs_char *path, u32 pathlen, fs_dir *dir)
{
	//printf("init open dir\n");
	int ret = 0;
	fs_DIR *dp;
	fs_entry *entry;
	
	//printf("check if path exists\n");
	dp = fs_opendir(fs_path);
	if(!dp)
	{
		//wprintf(L"[!] Failed to open directory: \"%s\"\n",path);
		return -1;
	}
	
	//printf("do some more init\n");
	fs_InitDir(path,pathlen,dir);
	//wprintf(L" rec: \"%s\" (%d)\n",dir->name,dir->name_len);
	
	//printf("chdir\n");
	fs_chdir(fs_path);
	
	//printf("read entries\n");
	while((entry = fs_GetEntry(dp)))
	{
		if(!entry)
		{
			ret = -1;
			break;
		}
		
		if(entry->IsDir)
		{		
			//printf("Found Dir ");
			if(!fs_EntryIsDirNav(entry))
			{
#ifdef _WIN32
			//wprintf(L"is a dir: \"%s\" (%d)\n",entry->fs_name,entry->name_len);
#else
			//printf("is a dir: \"%s\" (%d)\n",entry->fs_name,entry->name_len);
#endif
				ret = fs_AddDir(entry,dir);
			}
			else
			{
				//printf("Not wanted dir\n");
				ret = 0;
			}
		}
		else
		{
#ifdef _WIN32
			//wprintf(L"is a file: \"%s\" (%d)\n",entry->fs_name,entry->name_len);
#else
			//printf("is a file: \"%s\" (%d)\n",entry->fs_name,entry->name_len);
#endif
			ret = fs_AddFile(entry,dir);
		}
		
		//printf("free entry\n");		
		fs_FreeEntry(entry);
		
		if(ret)
		{
			//printf("error parsing entry\n");
			break;
		}
	}
	//printf("close dir ptr\n");
	fs_closedir(dp);
	//printf("return up dir\n");
	fs_chdirUp();
	//printf("return from fs_OpenDir();\n");
	return ret;
}


void fs_PrintDir(fs_dir *dir, u32 depth) // This is just for simple debugging, please don't shoot me
{
	for(u32 i = 0; i < depth; i++)
		printf(" ");

#ifdef _WIN32
	wprintf(L"%s\n",dir->name);
#else
	char *name = (char*)dir->name;
	for(u32 i = 0; i < dir->name_len; i+=2)
		putchar(name[i]);
	putchar('\n');
#endif
	
	if(dir->u_file)
	{
		for(u32 i = 0; i < dir->u_file; i++)
		{
			for(u32 j = 0; j < depth+1; j++)
				printf(" ");
			
#ifdef _WIN32
			wprintf(L"%s (0x%lx)\n",dir->file[i].name,dir->file[i].size);
#else
			name = (char*)dir->file[i].name;
			for(u32 j = 0; j < dir->file[i].name_len; j+=2)
				putchar(name[j]);
			printf(" (0x%llx)\n",dir->file[i].size);
#endif
		}
	}
	if(dir->u_dir)
	{
		fs_dir *tmp = (fs_dir*)dir->dir;
		for(u32 i = 0; i < dir->u_dir; i++)
			fs_PrintDir(&tmp[i],depth+1);
	}
}

void fs_FreeDir(fs_dir *dir)
{
	//printf("DIR!! free file names\n");
	for(u32 i = 0; i < dir->u_file; i++)
	{
		free(dir->file[i].name);
	}
	//printf("free file struct\n");
	free(dir->file);
	
	
	fs_dir *tmp = (fs_dir*)dir->dir;
	//printf("free dir names\n");
	for(u32 i = 0; i < dir->u_dir; i++)
	{	
		//wprintf(L"freeing: %s\n",tmp[i].name);
		free(tmp[i].name);
		fs_FreeDir(&tmp[i]);
	}
	//printf("free dir struct\n");
	free(dir->dir);
	
}

void fs_FreeFiles(fs_dir *dir)
{
	for(u32 i = 0; i < dir->u_file; i++)
	{
		if(dir->file[i].fp)
			fclose(dir->file[i].fp);
	}
	
	fs_dir *tmp = (fs_dir*)dir->dir;
	for(u32 i = 0; i < dir->u_dir; i++)
		fs_FreeFiles(&tmp[i]);
}
