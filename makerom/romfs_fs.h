#pragma once

#ifdef _WIN32
	#define romfs_char u16
	#define fs_char wchar_t
	#define fs_dirent _wdirent
	#define fs_DIR _WDIR
	#define fs_readdir _wreaddir
	#define fs_chdir _wchdir
	#define fs_opendir _wopendir
	#define fs_closedir _wclosedir
	#define FS_PATH_SEPARATOR '\\'
#else
	#define romfs_char u16
	#define fs_char char
	#define fs_dirent dirent
	#define fs_DIR DIR
	#define fs_readdir readdir
	#define fs_chdir chdir
	#define fs_opendir opendir
	#define fs_closedir closedir
	#define FS_PATH_SEPARATOR '/'
#endif

struct romfs_file
{
	fs_char *path;
	romfs_char *name;
	u32 namesize;
	u64 size;
};

struct romfs_dir
{
	fs_char *path;
	romfs_char *name;
	u32 namesize;
	
	struct romfs_dir *child;
	u32 m_child;
	u32 u_child;
	
	struct romfs_file *file;
	u32 m_file;
	u32 u_file;
};

typedef struct romfs_file romfs_file;
typedef struct romfs_dir romfs_dir;

static const romfs_char ROMFS_EMPTY_PATH[2] = { 0 };
static const fs_char FS_EMPTY_PATH[2] = { 0 };
static const fs_char FS_CURRENT_DIR_PATH[2] = { '.' };
static const fs_char FS_PARENT_DIR_PATH[3] = { '.', '.' };

u32 romfs_strlen(const romfs_char *str);
u32 fs_strlen(const fs_char *str);
int fs_strcmp(const fs_char *str1, const fs_char *str2);
FILE* fs_fopen(fs_char *path);
u64 fs_fsize(fs_char *path);

fs_char* fs_AppendToPath(const fs_char *src, const fs_char *add);
fs_char* fs_CopyStr(const fs_char *src);
romfs_char* romfs_CopyStr(const romfs_char *src);
void fs_fputs(const fs_char *str, FILE *out);
void romfs_fputs(const romfs_char *str, FILE *out);

int OpenRootDir(const char *path, romfs_dir *dir);
void PrintDir(romfs_dir *dir, u32 depth);
void FreeDir(romfs_dir *dir);