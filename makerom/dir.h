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
	#define FS_PATH_SEPARATOR '\\'
#else
	#define fs_romfs_char u16
	#define fs_char char
	#define fs_dirent dirent
	#define fs_DIR DIR
	#define fs_readdir readdir
	#define fs_chdir chdir
	#define fs_opendir opendir
	#define fs_closedir closedir
	#define FS_PATH_SEPARATOR '/'
#endif
	

struct fs_entry
{
	bool IsDir;
	fs_char *fs_path;
	fs_romfs_char *name;
	u32 name_len;
	u64 size;
};

struct fs_file
{
	fs_char *fs_path;
	fs_romfs_char *name;
	u32 name_len;
	u64 size;
};

struct fs_dir
{
	fs_char *fs_path;
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

static const fs_romfs_char ROMFS_EMPTY_PATH[2] = { 0 };
static const fs_char FS_EMPTY_PATH[2] = { 0 };

u32 fs_romfs_strlen(const fs_romfs_char *str);
u32 fs_strlen(const fs_char *str);
FILE* fs_fopen(fs_char *path);
u64 fs_fsize(fs_char *path);

fs_char* fs_AppendToPath(const fs_char *src, const fs_char *add);
fs_char* fs_CopyPath(const fs_char *src);
fs_romfs_char* fs_CopyRomfsName(const fs_romfs_char *src);
void fs_fputs(FILE *out, const fs_char *str);
void fs_romfs_fputs(FILE *out, const fs_romfs_char *str);

int fs_OpenRootDir(const char *path, fs_dir *dir);
int fs_OpenDir(fs_entry *entry, fs_dir *dir);
void fs_PrintDir(fs_dir *dir, u32 depth);
void fs_FreeDir(fs_dir *dir);