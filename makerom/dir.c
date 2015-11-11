#include "lib.h"
#include "dir.h"
#include "utf.h"

const fs_romfs_char FS_CURRENT_DIR_PATH = 0x2E;
const fs_romfs_char FS_PARENT_DIR_PATH[2] = { 0x2E,0x2E };

/* This is the FS interface for ROMFS generation */
/* Tested working on Windows/Linux/OSX */
int fs_InitDir(const fs_entry *entry, fs_dir *dir);
int fs_ManageDirSlot(fs_dir *dir);
int fs_ManageFileSlot(fs_dir *dir);
void fs_chdirUp(void);
fs_entry* fs_GetEntry(const fs_char *parent_path, fs_DIR *dp);
void fs_FreeEntry(fs_entry *entry);
bool fs_EntryIsDirNav(fs_entry *entry);
int fs_AddDir(fs_entry *entry, fs_dir *dir);
int fs_AddFile(fs_entry *entry, fs_dir *dir);

u32 fs_romfs_strlen(const fs_romfs_char *str)
{
	u32 i;
	for( i = 0; str[i] != 0x0; i++ );
	return i;
}

u32 fs_strlen(const fs_char *str)
{
	u32 i;
	for (i = 0; str[i] != 0x0; i++);
	return i;
}

FILE* fs_fopen(fs_char *path)
{
#ifdef _WIN32
	return _wfopen(path, L"rb");
#else
	return fopen(path, "rb");
#endif
}

u64 fs_fsize(fs_char *path)
{
#ifdef _WIN32
	return wGetFileSize64(path);
#else
	return GetFileSize64(path);
#endif
}

fs_char* fs_AppendToPath(const fs_char *src, const fs_char *add)
{
	u32 src_len, add_len;
	fs_char *new_path;

	src_len = fs_strlen(src);
	add_len = fs_strlen(add);
	new_path = calloc(src_len + add_len + 0x10, sizeof(fs_char));

#ifdef _WIN32
	_snwprintf(new_path, src_len + add_len + 0x10, L"%s%c%s", src, FS_PATH_SEPARATOR, add);
#else
	snprintf(new_path, src_len + add_len + 0x10, "%s%c%s", src, FS_PATH_SEPARATOR, add);
#endif

	return new_path;
}

fs_char* fs_CopyPath(const fs_char *src)
{
	u32 src_len;
	fs_char *new_path;

	src_len = fs_strlen(src);
	new_path = calloc(src_len + 0x10, sizeof(fs_char));

	for (u32 i = 0; i < src_len; i++)
		new_path[i] = src[i];

	return new_path;
}

fs_romfs_char* fs_CopyRomfsName(const fs_romfs_char *src)
{
	u32 src_len;
	fs_romfs_char *new_path;

	src_len = fs_strlen(src);
	new_path = calloc(src_len + 0x10, sizeof(fs_romfs_char));

	for (u32 i = 0; i < src_len; i++)
		new_path[i] = src[i];

	return new_path;
}

void fs_fputs(FILE *out, const fs_char *str)
{
#ifdef _WIN32
	wprintf(L"%s", str);
#else
	printf("%s", str);
#endif
}

void fs_romfs_fputs(FILE *out, const fs_romfs_char *str)
{
#ifdef _WIN32
	wprintf(L"%s", str);
#else
	const char *name = (const char*)str;
	for (u32 i = 0; i < fs_romfs_strlen(str)*2; i += 2)
		putchar(name[i]);
#endif
}

int fs_InitDir(const fs_entry *entry, fs_dir *dir)
{
	dir->fs_path = fs_CopyPath(entry->fs_path);

	dir->name_len = entry->name_len;
	dir->name = fs_CopyRomfsName(entry->name);
	
	dir->m_child = 10;
	dir->u_child = 0;
	dir->child = calloc(dir->m_child,sizeof(fs_dir));
	
	dir->m_file = 10;
	dir->u_file = 0;
	dir->file = calloc(dir->m_file,sizeof(fs_file));
	
	return 0;
}

int fs_ManageDirSlot(fs_dir *dir)
{
	if(dir->u_child >= dir->m_child)
	{
		dir->m_child *= 2;
		fs_dir *tmp = calloc(dir->m_child,sizeof(fs_dir));
		memcpy(tmp,dir->child,sizeof(fs_dir)*dir->u_child);
		free(dir->child);
		dir->child = tmp;
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

fs_entry* fs_GetEntry(const fs_char *parent_path, fs_DIR *dp)
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
	fs_char *fs_name = calloc(sizeof(fs_char)*(namlen+1),1);
	memcpy(fs_name,tmp_entry->d_name,sizeof(fs_char)*namlen);
	entry->fs_path = fs_AppendToPath(parent_path, fs_name);
	
	// Convert Entry name into RomFS u16 char (windows wchar_t, thanks Nintendo)
#if _WIN32
	str_u16_to_u16(&entry->name,&entry->name_len,tmp_entry->d_name,namlen);
#else
	str_utf8_to_u16(&entry->name,&entry->name_len,(u8*)tmp_entry->d_name,namlen);
#endif
	
	//printf("get dir entry from dir ptr to check if dir\n");
	tmp_dptr = fs_opendir(entry->fs_path);
	if(tmp_dptr)
	{
		//printf("is dir\n");
		fs_closedir(tmp_dptr);
		entry->IsDir = true;
		entry->size = 0;
	}
	else // Open file if it is a file
	{
		entry->IsDir = false;
		entry->size = fs_fsize(entry->fs_path);
	}
	
	// Don't bother returning current entry, if it is useless
	if (fs_EntryIsDirNav(entry)) {
		fs_FreeEntry(entry);
		return fs_GetEntry(parent_path, dp);
	}

	return entry;
}

void fs_FreeEntry(fs_entry *entry)
{
	free(entry->fs_path);
	free(entry->name);
	free(entry);
}

bool fs_EntryIsDirNav(fs_entry *entry)
{
	if(entry->name_len == sizeof(fs_romfs_char)*1 && memcmp(entry->name,&FS_CURRENT_DIR_PATH,sizeof(fs_romfs_char)*1) == 0)
		return true;
	if(entry->name_len == sizeof(fs_romfs_char)*2 && memcmp(entry->name,FS_PARENT_DIR_PATH,sizeof(fs_romfs_char)*2) == 0)
		return true;
	return false;
	
}

int fs_AddDir(fs_entry *entry, fs_dir *dir)
{
	fs_ManageDirSlot(dir);
	u32 current_slot = dir->u_child;

	dir->u_child++;
	return fs_OpenDir(entry,&dir->child[current_slot]);
}

int fs_AddFile(fs_entry *entry, fs_dir *dir)
{
	fs_ManageFileSlot(dir);
	dir->file[dir->u_file].fs_path = fs_CopyPath(entry->fs_path);
	dir->file[dir->u_file].name_len = entry->name_len;
	dir->file[dir->u_file].name = fs_CopyRomfsName(entry->name);
	dir->file[dir->u_file].size = entry->size;
	
	dir->u_file++;
	return 0;
}

int fs_OpenRootDir(const char *path, fs_dir *dir)
{
	fs_entry *root = calloc(1, sizeof(fs_entry));
	u32 nul;

	root->IsDir = true;
	root->size = 0;

	str_u16_to_u16(&root->name, &root->name_len, ROMFS_EMPTY_PATH, 0);
#ifdef _WIN32
	str_u8_to_u16(&root->fs_path, &nul, (u8*)path, strlen(path));
#else
	str_u8_to_u8(&root->fs_path, &nul, (u8*)path, strlen(path));
#endif


	int ret = fs_OpenDir(root, dir);

	fs_FreeEntry(root);

	return ret;
}

int fs_OpenDir(fs_entry *curr_dir_entry, fs_dir *dir)
{
	//printf("init open dir\n");
	int ret = 0;
	fs_DIR *dp;
	fs_entry *entry;
	
	//printf("do some more init\n");
	fs_InitDir(curr_dir_entry, dir);
	//wprintf(L" rec: \"%s\" (%d)\n",dir->name,dir->name_len);

	//printf("check if path exists\n");
	dp = fs_opendir(dir->fs_path);
	if(!dp)
	{
		wprintf(L"[!] Failed to open directory: \"%s\"\n",dir->fs_path);
		return -1;
	}
	
	//printf("read entries\n");
	while((entry = fs_GetEntry(dir->fs_path, dp)) != NULL)
	{		
		ret = entry->IsDir? fs_AddDir(entry, dir) : fs_AddFile(entry, dir);

		//printf("free entry\n");		
		fs_FreeEntry(entry);
		
		if(ret)
		{
			//printf("error parsing entry\n");
			break;
		}
	}
	fs_closedir(dp);
	return ret;
}


void fs_PrintDir(fs_dir *dir, u32 depth) // This is just for simple debugging, please don't shoot me
{
	for(u32 i = 0; i < depth; i++)
		printf(" ");

	if (depth > 0)
		fs_romfs_fputs(stdout, dir->name);
	else
		printf("romfs:");
	putchar('\n');
	
	if(dir->u_file)
	{
		for(u32 i = 0; i < dir->u_file; i++)
		{
			for(u32 j = 0; j < depth+1; j++)
				printf(" ");
			fs_romfs_fputs(stdout, dir->file[i].name);
			printf(" (0x%"PRIx64")\n", dir->file[i].size);
		}
	}
	if(dir->u_child)
	{
		for(u32 i = 0; i < dir->u_child; i++)
			fs_PrintDir(&dir->child[i],depth+1);
	}
}

void fs_FreeDir(fs_dir *dir)
{
	//printf("DIR!! free file names\n");
	for(u32 i = 0; i < dir->u_file; i++)
	{
		free(dir->file[i].fs_path);
		free(dir->file[i].name);
	}
	//printf("free file struct\n");
	free(dir->file);
	
	
	//printf("free dir names and\n");
	for(u32 i = 0; i < dir->u_child; i++)
	{	
		free(dir->child[i].fs_path);
		free(dir->child[i].name);
		fs_FreeDir(&dir->child[i]);
	}
	//printf("free dir struct\n");
	free(dir->child);
	
}