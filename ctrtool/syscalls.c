#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "syscalls.h"

// List of 3DS system calls.  NULL indicates unknown.
static const char *const syscall_list[NUM_SYSCALLS] =
{
	NULL,                                // 00
	"ControlMemory",                     // 01
	"QueryMemory",                       // 02
	"ExitProcess",                       // 03
	"GetProcessAffinityMask",            // 04
	"SetProcessAffinityMask",            // 05
	"GetProcessIdealProcessor",          // 06
	"SetProcessIdealProcessor",          // 07
	"CreateThread",                      // 08
	"ExitThread",                        // 09
	"SleepThread",                       // 0A
	"GetThreadPriority",                 // 0B
	"SetThreadPriority",                 // 0C
	"GetThreadAffinityMask",             // 0D
	"SetThreadAffinityMask",             // 0E
	"GetThreadIdealProcessor",           // 0F
	"SetThreadIdealProcessor",           // 10
	"GetCurrentProcessorNumber",         // 11
	"Run",                               // 12
	"CreateMutex",                       // 13
	"ReleaseMutex",                      // 14
	"CreateSemaphore",                   // 15
	"ReleaseSemaphore",                  // 16
	"CreateEvent",                       // 17
	"SignalEvent",                       // 18
	"ClearEvent",                        // 19
	"CreateTimer",                       // 1A
	"SetTimer",                          // 1B
	"CancelTimer",                       // 1C
	"ClearTimer",                        // 1D
	"CreateMemoryBlock",                 // 1E
	"MapMemoryBlock",                    // 1F
	"UnmapMemoryBlock",                  // 20
	"CreateAddressArbiter",              // 21
	"ArbitrateAddress",                  // 22
	"CloseHandle",                       // 23
	"WaitSynchronization1",              // 24
	"WaitSynchronizationN",              // 25
	"SignalAndWait",                     // 26
	"DuplicateHandle",                   // 27
	"GetSystemTick",                     // 28
	"GetHandleInfo",                     // 29
	"GetSystemInfo",                     // 2A
	"GetProcessInfo",                    // 2B
	"GetThreadInfo",                     // 2C
	"ConnectToPort",                     // 2D
	"SendSyncRequest1",                  // 2E
	"SendSyncRequest2",                  // 2F
	"SendSyncRequest3",                  // 30
	"SendSyncRequest4",                  // 31
	"SendSyncRequest",                   // 32
	"OpenProcess",                       // 33
	"OpenThread",                        // 34
	"GetProcessId",                      // 35
	"GetProcessIdOfThread",              // 36
	"GetThreadId",                       // 37
	"GetResourceLimit",                  // 38
	"GetResourceLimitLimitValues",       // 39
	"GetResourceLimitCurrentValues",     // 3A
	"GetThreadContext",                  // 3B
	"Break",                             // 3C
	"OutputDebugString",                 // 3D
	"ControlPerformanceCounter",         // 3E
	NULL,                                // 3F
	NULL,                                // 40
	NULL,                                // 41
	NULL,                                // 42
	NULL,                                // 43
	NULL,                                // 44
	NULL,                                // 45
	NULL,                                // 46
	"CreatePort",                        // 47
	"CreateSessionToPort",               // 48
	"CreateSession",                     // 49
	"AcceptSession",                     // 4A
	"ReplyAndReceive1",                  // 4B
	"ReplyAndReceive2",                  // 4C
	"ReplyAndReceive3",                  // 4D
	"ReplyAndReceive4",                  // 4E
	"ReplyAndReceive",                   // 4F
	"BindInterrupt",                     // 50
	"UnbindInterrupt",                   // 51
	"InvalidateProcessDataCache",        // 52
	"StoreProcessDataCache",             // 53
	"FlushProcessDataCache",             // 54
	"StartInterProcessDma",              // 55
	"StopDma",                           // 56
	"GetDmaState",                       // 57
	"RestartDma",                        // 58
	"SetGpuProt",                        // 59
	"SetWifiEnabled",                    // 5A
	NULL,                                // 5B
	NULL,                                // 5C
	NULL,                                // 5D
	NULL,                                // 5E
	NULL,                                // 5F
	"DebugActiveProcess",                // 60
	"BreakDebugProcess",                 // 61
	"TerminateDebugProcess",             // 62
	"GetProcessDebugEvent",              // 63
	"ContinueDebugEvent",                // 64
	"GetProcessList",                    // 65
	"GetThreadList",                     // 66
	"GetDebugThreadContext",             // 67
	"SetDebugThreadContext",             // 68
	"QueryDebugProcessMemory",           // 69
	"ReadProcessMemory",                 // 6A
	"WriteProcessMemory",                // 6B
	"SetHardwareBreakPoint",             // 6C
	"GetDebugThreadParam",               // 6D
	NULL,                                // 6E
	NULL,                                // 6F
	"ControlProcessMemory",              // 70
	"MapProcessMemory",                  // 71
	"UnmapProcessMemory",                // 72
	"CreateCodeSet",                     // 73
	NULL,                                // 74
	"CreateProcess",                     // 75
	"TerminateProcess",                  // 76
	"SetProcessResourceLimits",          // 77
	"CreateResourceLimit",               // 78
	"SetResourceLimitValues",            // 79
	"AddCodeSegment",                    // 7A
	"Backdoor",                          // 7B
	"KernelSetState",                    // 7C
	"QueryProcessMemory",                // 7D
	NULL,                                // 7E
	NULL,                                // 7F
};


void syscall_get_name(char *output, size_t size, unsigned int call_num)
{
	_Static_assert(sizeof(syscall_list) / sizeof(syscall_list[0]) == NUM_SYSCALLS,
		"syscall table length mismatch");

	if (size == 0)
	{
		return;
	}

	const char *name = NULL;
	if (call_num < (unsigned int) NUM_SYSCALLS)
	{
		name = syscall_list[call_num];
	}

	char name_buf[] = "UnknownXX";
	sprintf(&name_buf[sizeof(name_buf) - 3], "%02X", call_num & 0xFFu);

	name = name ? name : name_buf;

	size_t length = strlen(name);
	length = (length > (size - 1)) ? (size - 1) : length;

	memcpy(output, name, length);
	output[length] = '\0';
}
