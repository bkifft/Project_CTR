#include <stdlib.h>
#include <stdint.h>
//Bools
typedef enum
{
	Good,
	Fail
} return_basic;

typedef enum
{
	MEM_ERROR = -1,
	FAILED_TO_OPEN_FILE = -2,
	FAILED_TO_IMPORT_FILE = -3,
	FAILED_TO_CREATE_OUTFILE = -4,
} global_errors;

typedef enum
{
	BE = 0,
	LE = 1
} endianness_flag;

typedef enum
{
	KB = 1024,
	MB = 1048576,
	GB = 1073741824
} file_unit_size;

typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
typedef unsigned long long      u64;

typedef signed char     s8;
typedef signed short    s16;
typedef signed int      s32;
typedef signed long long        s64;
