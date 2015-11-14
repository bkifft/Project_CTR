#include "lib.h"
#include "dir.h"
#include "utf.h"

/* This is the FS interface for ROMFS generation */
/* Tested working on Windows/Linux/OSX */
int OpenDir(romfs_dir *dir);
int InitDir(romfs_dir *dir);
int ManageDir(romfs_dir *dir);

u32 fs_strlen(const fs_char *str)
{
#ifdef _WIN32
	return strlen_char16(str);
#else
	return strlen(str);
#endif
}

u32 romfs_strlen(const romfs_char *str)
{
	return strlen_char16(str);
}

int fs_strcmp(const fs_char *str1, const fs_char *str2)
{
#ifdef _WIN32
	return wcscmp(str1, str2);
#else
	return strcmp(str1, str2);
#endif
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

fs_char* fs_CopyStr(const fs_char *src)
{
#ifdef _WIN32
	return strcopy_16to16(src);
#else
	return strcopy_8to8(src);
#endif
}

romfs_char* romfs_CopyConvertStr(const fs_char *src)
{
#ifdef _WIN32
	return strcopy_16to16(src);
#else
	return strcopy_utf8to16(src);
#endif
}


romfs_char* romfs_CopyStr(const romfs_char *src)
{
	return strcopy_16to16(src);
}

void fs_fputs(const fs_char *str, FILE *out)
{
#ifdef _WIN32
	fwprintf(out,L"%s", str);
#else
	fprintf(out,"%s", str);
#endif
}

void romfs_fputs(const romfs_char *str, FILE *out)
{
#ifdef _WIN32
	fwprintf(out,L"%s", str);
#else
	const char *name = (const char*)str;
	for (u32 i = 0; i < romfs_strlen(str)*2; i += 2)
		fputc(name[i],out);
#endif
}

int InitDir(romfs_dir *dir)
{
	dir->m_child = 10;
	dir->u_child = 0;
	dir->child = calloc(dir->m_child,sizeof(romfs_dir));
	
	dir->m_file = 10;
	dir->u_file = 0;
	dir->file = calloc(dir->m_file,sizeof(romfs_file));

	if (dir->child == NULL || dir->file == NULL)
		return MEM_ERROR;
	
	return 0;
}

int ManageDir(romfs_dir *dir)
{
	if (dir->u_child >= dir->m_child) {
		dir->m_child = 2 * dir->u_child;
		dir->child = realloc(dir->child, dir->m_child*sizeof(romfs_dir));
	}
	if (dir->u_file >= dir->m_file) {
		dir->m_file = 2 * dir->u_file;
		dir->file = realloc(dir->file, dir->m_file*sizeof(romfs_file));
	}

	if (dir->child == NULL || dir->file == NULL)
		return MEM_ERROR;

	return 0;
}

int OpenRootDir(const char *path, romfs_dir *dir)
{
	// Create native FS path
#ifdef _WIN32
	dir->path = strcopy_8to16(path);
#else
	dir->path = strcopy_8to8(path);
#endif
	// Copy romfs name (empty string)
	dir->name = romfs_CopyStr(ROMFS_EMPTY_PATH);
	dir->namesize = 0;
	
	return OpenDir(dir);
}

int OpenDir(romfs_dir *dir)
{
	fs_DIR *dp, *tmp_dp;
	struct fs_dirent *entry;

	if (InitDir(dir))
		return MEM_ERROR;

	// Open Directory
	if((dp = fs_opendir(dir->path)) == NULL)
	{
		printf("[ROMFS] Failed to open directory: \"");
		fs_fputs(dir->path, stdout);
		printf("\"\n");
		return -1;
	}
	
	// Process Entries
	while ((entry = fs_readdir(dp)) != NULL)
	{
		// Skip if "." or ".."
		if (fs_strcmp(entry->d_name, FS_CURRENT_DIR_PATH) == 0 || fs_strcmp(entry->d_name, FS_PARENT_DIR_PATH) == 0)
			continue;

		// Ensures that there is always memory for child directory and file structs
		if (ManageDir(dir))
			return MEM_ERROR;

		// Get native FS path
		fs_char *path = fs_AppendToPath(dir->path, entry->d_name);
		
		// Opening directory with fs path to test if directory
		if ((tmp_dp = fs_opendir(path)) != NULL) {
			fs_closedir(tmp_dp);

			dir->child[dir->u_child].path = path;
			dir->child[dir->u_child].name = romfs_CopyConvertStr(entry->d_name);
			dir->child[dir->u_child].namesize = fs_strlen(entry->d_name)*sizeof(romfs_char);
			dir->u_child++;
			
			// Populate directory
			OpenDir(&dir->child[dir->u_child-1]);
		}
		// Otherwise this is a file
		else {
			dir->file[dir->u_file].path = path;
			dir->file[dir->u_file].name = romfs_CopyConvertStr(entry->d_name);
			dir->file[dir->u_file].namesize = fs_strlen(entry->d_name)*sizeof(romfs_char);
			dir->file[dir->u_file].size = fs_fsize(path);
			dir->u_file++;
		}
	}

	fs_closedir(dp);

	return 0;
}


void PrintDir(romfs_dir *dir, u32 depth)
{
	for(u32 i = 0; i < depth; i++)
		printf(" ");

	if (depth > 0)
		romfs_fputs(dir->name, stdout);
	else
		printf("romfs:");
	putchar('\n');
	
	if(dir->u_file)
	{
		for(u32 i = 0; i < dir->u_file; i++)
		{
			for(u32 j = 0; j < depth+1; j++)
				printf(" ");
			romfs_fputs(dir->file[i].name, stdout);
			printf(" (0x%"PRIx64")\n", dir->file[i].size);
		}
	}
	if(dir->u_child)
	{
		for(u32 i = 0; i < dir->u_child; i++)
			PrintDir(&dir->child[i],depth+1);
	}
}

void FreeDir(romfs_dir *dir)
{
	//printf("DIR!! free file names\n");
	for(u32 i = 0; i < dir->u_file; i++)
	{
		free(dir->file[i].path);
		free(dir->file[i].name);
	}
	//printf("free file struct\n");
	free(dir->file);
	
	
	//printf("free dir names and\n");
	for(u32 i = 0; i < dir->u_child; i++)
	{	
		free(dir->child[i].path);
		free(dir->child[i].name);
		FreeDir(&dir->child[i]);
	}
	//printf("free dir struct\n");
	free(dir->child);
	
}