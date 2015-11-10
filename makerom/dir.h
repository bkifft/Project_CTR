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
	

struct fs_entry
{
	bool IsDir;
	fs_char *fs_name;
	fs_romfs_char *name;
	u32 name_len;
	u64 size;
	FILE *fp;
};

struct fs_file
{
	fs_romfs_char *name;
	u32 name_len;
	u64 size;
	FILE *fp;
};

struct fs_dir
{
	fs_romfs_char *name;
	u32 name_len;
	
	struct fs_dir *child;
	u32 m_child;
	u32 u_child;
	
	struct fs_file *file;
	u32 m_file;
	u32 u_file;
};

typedef struct fs_entry fs_entry;
typedef struct fs_file fs_file;
typedef struct fs_dir fs_dir;

int fs_RomFsStrLen(fs_romfs_char *str);

int fs_OpenDir(fs_char *fs_path, fs_romfs_char *path, u32 pathlen, fs_dir *dir);
void fs_PrintDir(fs_dir *dir, u32 depth);
void fs_FreeDir(fs_dir *dir);
void fs_FreeFiles(fs_dir *dir);