#pragma once

#ifdef _WIN32
	#define fs_romfs_char u16
	#define fs_char wchar_t
	#define fs_dirent _wdirent
	#define fs_DIR _WDIR
	#define fs_readdir _wreaddir
	#define fs_chdir _wchdir
	#define fs_opendir _wopendir
	#define fs_closedir _wclosedir
#else
	#define fs_romfs_char u16
	#define fs_char char
	#define fs_dirent dirent
	#define fs_DIR DIR
	#define fs_readdir readdir
	#define fs_chdir chdir
	#define fs_opendir opendir
	#define fs_closedir closedir
#endif
	

typedef struct
{
	bool IsDir;
	fs_char *fs_name;
	fs_romfs_char *name;
	u32 name_len;
	u64 size;
	FILE *fp;
} fs_entry;

typedef struct
{
	fs_romfs_char *name;
	u32 name_len;
	u64 size;
	FILE *fp;
} fs_file;

typedef struct
{
	u16 *name;
	u32 name_len;
	
	void *dir; // treated as type 'fs_dir'. This officially type 'void' to prevent self referencing problems
	u32 m_dir;
	u32 u_dir;
	
	fs_file *file;
	u32 m_file;
	u32 u_file;
} fs_dir;


int fs_u8String_to_u16String(u16 **dst, u32 *dst_len, u8 *src, u32 src_len);
int fs_u16String_to_u16String(u16 **dst, u32 *dst_len, u16 *src, u32 src_len);
int fs_u32String_to_u16String(u16 **dst, u32 *dst_len, u32 *src, u32 src_len);
int fs_u16StrLen(fs_romfs_char *str);

int fs_OpenDir(fs_char *fs_path, fs_romfs_char *path, u32 pathlen, fs_dir *dir);
void fs_PrintDir(fs_dir *dir, u32 depth);
void fs_FreeDir(fs_dir *dir);
void fs_FreeFiles(fs_dir *dir);