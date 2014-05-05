#pragma once

static const u32 ELF_MAGIC = 0x7f454c46;

typedef enum
{
	elf_32_bit = 1,
	elf_64_bit = 2,
} elf_bit_format_types;

typedef enum
{
	elf_little_endian = 1,
	elf_big_endian = 2,
} elf_endianness;

typedef enum
{
	elf_relocatable = 1,
	elf_executeable = 2,
	elf_shared = 3,
	elf_core = 4,
} elf_type;

typedef enum
{
	elf_arm = 0x28,
} elf_target_architecture;

typedef struct
{
	u8 magic[4];
	u8 bitFormat;
	u8 endianness;
	u8 elfVersion;
	u8 os;
	u8 padding0[8];
	u8 type[2];
	u8 targetArchitecture[2];
	u8 version[4];
	u8 entryPoint[4];
	u8 programHeaderTableOffset[4];
	u8 sectionHeaderTableOffset[4];
	u8 flags[4];
	u8 headerSize[2];
	u8 programHeaderEntrySize[2];
	u8 programHeaderEntryCount[2];
	u8 sectionTableEntrySize[2];
	u8 sectionHeaderEntryCount[2];
	u8 sectionHeaderNameEntryIndex[2];
} elf_32_hdr;

typedef struct
{
	u8 magic[4];
	u8 bitFormat;
	u8 endianness;
	u8 elfVersion;
	u8 os;
	u8 padding0[8];
	u8 type[2];
	u8 targetArchitecture[2];
	u8 version[4];
	u8 entryPoint[8];
	u8 programHeaderTableOffset[8];
	u8 sectionHeaderTableOffset[8];
	u8 flags[4];
	u8 headerSize[2];
	u8 programHeaderEntrySize[2];
	u8 programHeaderEntryCount[2];
	u8 sectionTableEntrySize[2];
	u8 sectionHeaderEntryCount[2];
	u8 sectionHeaderNameEntryIndex[2];
} elf_64_hdr;

/* taken from elf specs, will not follow global style */

/* Section header.  */

/* Legal values for sh_type (section type).  */

#define SHT_NULL	 0		/* Section header table entry unused */
#define SHT_PROGBITS	 1		/* Program data */
#define SHT_SYMTAB	 2		/* Symbol table */
#define SHT_STRTAB	 3		/* String table */
#define SHT_RELA	 4		/* Relocation entries with addends */
#define SHT_HASH	 5		/* Symbol hash table */
#define SHT_DYNAMIC	 6		/* Dynamic linking information */
#define SHT_NOTE	 7		/* Notes */
#define SHT_NOBITS	 8		/* Program space with no data (bss) */
#define SHT_REL		 9		/* Relocation entries, no addends */
#define SHT_SHLIB	 10		/* Reserved */
#define SHT_DYNSYM	 11		/* Dynamic linker symbol table */
#define	SHT_NUM		 12		/* Number of defined types.  */
#define SHT_LOOS	 0x60000000	/* Start OS-specific */
#define SHT_LOSUNW	 0x6ffffffb	/* Sun-specific low bound.  */
#define SHT_SUNW_COMDAT  0x6ffffffb
#define SHT_SUNW_syminfo 0x6ffffffc
#define SHT_GNU_verdef	 0x6ffffffd	/* titleVersion definition section.  */
#define SHT_GNU_verneed	 0x6ffffffe	/* titleVersion needs section.  */
#define SHT_GNU_versym	 0x6fffffff	/* titleVersion symbol table.  */
#define SHT_HISUNW	 0x6fffffff	/* Sun-specific high bound.  */
#define SHT_HIOS	 0x6fffffff	/* End OS-specific type */
#define SHT_LOPROC	 0x70000000	/* Start of processor-specific */
#define SHT_HIPROC	 0x7fffffff	/* End of processor-specific */
#define SHT_LOUSER	 0x80000000	/* Start of application-specific */
#define SHT_HIUSER	 0x8fffffff	/* End of application-specific */


typedef struct
{
  u8 sh_name[4];		/* Section name (string tbl index) */
  u8 sh_type[4];		/* Section type */
  u8 sh_flags[4];		/* Section flags */
  u8 sh_addr[4];		/* Section virtual addr at execution */
  u8 sh_offset[4];		/* Section file offset */
  u8 sh_size[4];		/* Section size in bytes */
  u8 sh_link[4];		/* Link to another section */
  u8 sh_info[4];		/* Additional section information */
  u8 sh_addralign[4];		/* Section alignment */
  u8 sh_entsize[4];		/* Entry size if section holds table */
} elf_32_shdr;

typedef struct
{
  u8 sh_name[8];		/* Section name (string tbl index) */
  u8 sh_type[8];		/* Section type */
  u8 sh_flags[8];		/* Section flags */
  u8 sh_addr[8];		/* Section virtual addr at execution */
  u8 sh_offset[8];		/* Section file offset */
  u8 sh_size[8];		/* Section size in bytes */
  u8 sh_link[8];		/* Link to another section */
  u8 sh_info[8];		/* Additional section information */
  u8 sh_addralign[8];		/* Section alignment */
  u8 sh_entsize[8];		/* Entry size if section holds table */
} elf_64_shdr;

/* Program segment header.  */

/* p_type legal values */
#define	PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved */
#define PT_PHDR		6		/* Entry for header table itself */
#define	PT_NUM		7		/* Number of defined types.  */
#define PT_LOOS		0x60000000	/* Start of OS-specific */
#define PT_HIOS		0x6fffffff	/* End of OS-specific */
#define PT_LOPROC	0x70000000	/* Start of processor-specific */
#define PT_HIPROC	0x7fffffff	/* End of processor-specific */

typedef struct
{
  u8 p_type[4];			/* Segment type */
  u8 p_offset[4];		/* Segment file offset */
  u8 p_vaddr[4];		/* Segment virtual address */
  u8 p_paddr[4];		/* Segment physical address */
  u8 p_filesz[4];		/* Segment size in file */
  u8 p_memsz[4];		/* Segment size in memory */
  u8 p_flags[4];		/* Segment flags */
  u8 p_align[4];		/* Segment alignment */
} elf_32_phdr;

typedef struct
{
  u8 p_type[8];			/* Segment type */
  u8 p_flags[8];		/* Segment flags */
  u8 p_offset[8];		/* Segment file offset */
  u8 p_vaddr[8];		/* Segment virtual address */
  u8 p_paddr[8];		/* Segment physical address */
  u8 p_filesz[8];		/* Segment size in file */
  u8 p_memsz[8];		/* Segment size in memory */
  u8 p_align[8];		/* Segment alignment */
} elf_64_phdr;