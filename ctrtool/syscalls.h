#ifndef _SYSCALLS_H_
#define _SYSCALLS_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum { NUM_SYSCALLS = 0x80 };

void syscall_get_name(char *output, size_t size, unsigned int call_num);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
