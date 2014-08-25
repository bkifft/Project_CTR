#pragma once

typedef enum
{
	NOT_ELF_FILE = -10,
	NOT_ARM_ELF = -11,
	NON_EXECUTABLE_ELF = -12,
	ELF_SECTION_NOT_FOUND = -13,
	NOT_FIND_BSS_SIZE = -14,
	NOT_FIND_CODE_SECTIONS = -15,
	ELF_SEGMENT_SECTION_SIZE_MISMATCH = -16,
	ELF_SEGMENTS_NOT_CONTINUOUS = -17,
	ELF_SEGMENTS_NOT_FOUND = -18,
} elf_errors;

typedef struct
{
	char *name;
	u64 type;
	u64 flags;
	u8 *ptr;
	u64 offsetInFile;
	u64 size;
	u64 address;
	u64 alignment;
} elf_section_entry;

typedef struct
{
	u64 type;
	u64 flags;
	u8 *ptr;
	u64 offsetInFile;
	u64 sizeInFile;
	u64 virtualAddress;
	u64 physicalAddress;
	u64 sizeInMemory;
	u64 alignment;
} elf_program_entry;

typedef struct
{
	char *name;
	u64 vAddr;

	elf_program_entry *header;
	u32 sectionNum;
	elf_section_entry *sections;
} elf_segment;

typedef struct
{
	u32 address;
	u32 size;
	u32 maxPageNum;
	u8 *data;
} code_segment;

typedef struct
{
	u32 pageSize;
	bool IsLittleEndian;
	bool Is64bit;
		
	u64 programTableOffset;
	u16 programTableEntrySize;
	u16 programTableEntryCount;
	
	u64 sectionTableOffset;
	u16 sectionTableEntrySize;
	u16 sectionTableEntryCount;
	
	u16 sectionHeaderNameEntryIndex;

	elf_section_entry *sections;
	elf_program_entry *programHeaders;

	u16 activeSegments;
	elf_segment *segments;

} elf_context;

int BuildExeFsCode(ncch_settings *ncchset);