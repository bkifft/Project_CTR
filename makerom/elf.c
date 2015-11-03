#include "lib.h"
#include "elf.h"

static const u32 ELF_MAGIC = 0x7f454c46;

typedef enum elf_bit_format_types
{
	elf_32_bit = 1,
	elf_64_bit = 2,
} elf_bit_format_types;

typedef enum elf_endianness
{
	elf_little_endian = 1,
	elf_big_endian = 2,
} elf_endianness;

typedef enum elf_type
{
	elf_relocatable = 1,
	elf_executeable = 2,
	elf_shared = 3,
	elf_core = 4,
} elf_type;

typedef enum elf_target_architecture
{
	elf_arm = 0x28,
} elf_target_architecture;

typedef struct elf_hdr
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
} elf_hdr;

/* taken from elf specs, will not follow global style */

/* Section header.  */
typedef struct elf_shdr
{
	u8 name[4];		/* Section name (string tbl index) */
	u8 type[4];		/* Section type */
	u8 flags[4];		/* Section flags */
	u8 addr[4];		/* Section virtual addr at execution */
	u8 offset[4];		/* Section file offset */
	u8 size[4];		/* Section size in bytes */
	u8 link[4];		/* Link to another section */
	u8 info[4];		/* Additional section information */
	u8 addralign[4];		/* Section alignment */
	u8 entsize[4];		/* Entry size if section holds table */
} elf_shdr;

/* Program segment header.  */
typedef struct elf_phdr
{
	u8 type[4];			/* Segment type */
	u8 offset[4];		/* Segment file offset */
	u8 vaddr[4];		/* Segment virtual address */
	u8 paddr[4];		/* Segment physical address */
	u8 filesz[4];		/* Segment size in file */
	u8 memsz[4];		/* Segment size in memory */
	u8 flags[4];		/* Segment flags */
	u8 align[4];		/* Segment alignment */
} elf_phdr;

// ELF Functions
int GetElfSectionEntries(elf_context *elf);
int GetElfProgramEntries(elf_context *elf);
void PrintElfContext(elf_context *elf);
int ReadElfHdr(elf_context *elf);

int CreateElfSegments(elf_context *elf);
bool IsIgnoreSection(elf_section_entry info);

// ELF Functions

int GetElfContext(elf_context *elf, const u8 *elfFile)
{
	elf->file = elfFile;
	
	int result;

	if((result = ReadElfHdr(elf))) return result;
	if((result = GetElfSectionEntries(elf))) return result;
	if((result = GetElfProgramEntries(elf))) return result;
	if((result = CreateElfSegments(elf))) return result;

	return 0;
}

void FreeElfContext(elf_context *elf)
{
	for (int i = 0; i < elf->activeSegments; i++)
		free(elf->segments[i].sections);
	free(elf->sections);
	free(elf->programHeaders);
	free(elf->segments);
}

int ReadElfHdr(elf_context *elf)
{
	const elf_hdr *hdr = (const elf_hdr*)elf->file;

	if (u8_to_u32(hdr->magic, BE) != ELF_MAGIC)
		return NOT_ELF_FILE;
	if (hdr->bitFormat != elf_32_bit)
		return NOT_CTR_ARM_ELF;
	if (hdr->endianness != elf_little_endian)
		return NOT_CTR_ARM_ELF;
	if (u8_to_u16(hdr->targetArchitecture, LE) != elf_arm)
		return NOT_CTR_ARM_ELF;
	if (u8_to_u16(hdr->type, LE) != elf_executeable)
		return NON_EXECUTABLE_ELF;

	elf->programTableOffset = u8_to_u32(hdr->programHeaderTableOffset, LE);
	elf->programTableEntrySize = u8_to_u16(hdr->programHeaderEntrySize, LE);
	elf->programTableEntryCount = u8_to_u16(hdr->programHeaderEntryCount, LE);

	elf->sectionTableOffset = u8_to_u32(hdr->sectionHeaderTableOffset, LE);
	elf->sectionTableEntrySize = u8_to_u16(hdr->sectionTableEntrySize, LE);
	elf->sectionTableEntryCount = u8_to_u16(hdr->sectionHeaderEntryCount, LE);

	elf->sectionHeaderNameEntryIndex = u8_to_u16(hdr->sectionHeaderNameEntryIndex, LE);

	return 0;
}

int GetElfSectionEntries(elf_context *elf)
{
	elf->sections = calloc(elf->sectionTableEntryCount,sizeof(elf_section_entry));
	if(!elf->sections) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	const elf_shdr *shdr = (const elf_shdr *)(elf->file + elf->sectionTableOffset);
	const char *nameTable = (const char*)(elf->file + u8_to_u32(shdr[elf->sectionHeaderNameEntryIndex].offset, LE));

	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		elf->sections[i].name = nameTable + u8_to_u32(shdr[i].name, LE);
		elf->sections[i].type = u8_to_u32(shdr[i].type, LE);
		elf->sections[i].flags = u8_to_u32(shdr[i].flags, LE);
		elf->sections[i].offsetInFile = u8_to_u32(shdr[i].offset, LE);
		elf->sections[i].size = u8_to_u32(shdr[i].size, LE);
		elf->sections[i].ptr = elf->file + elf->sections[i].offsetInFile;
		elf->sections[i].address = u8_to_u32(shdr[i].addr, LE);
		elf->sections[i].alignment = u8_to_u32(shdr[i].addralign, LE);
	}
	return 0;
}

int GetElfProgramEntries(elf_context *elf)
{
	elf->programHeaders = calloc(elf->programTableEntryCount,sizeof(elf_program_entry));
	if(!elf->programHeaders) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	const elf_phdr *phdr = (const elf_phdr*)(elf->file + elf->programTableOffset);

	for(int i = 0; i < elf->programTableEntryCount; i++){
		elf->programHeaders[i].type = u8_to_u32(phdr[i].type, LE);
		elf->programHeaders[i].flags = u8_to_u32(phdr[i].flags, LE);
		elf->programHeaders[i].offsetInFile = u8_to_u32(phdr[i].offset, LE);
		elf->programHeaders[i].sizeInFile = u8_to_u32(phdr[i].filesz, LE);
		elf->programHeaders[i].ptr = elf->file + elf->programHeaders[i].offsetInFile;
		elf->programHeaders[i].physicalAddress = u8_to_u32(phdr[i].paddr, LE);
		elf->programHeaders[i].virtualAddress = u8_to_u32(phdr[i].vaddr, LE);
		elf->programHeaders[i].sizeInMemory = u8_to_u32(phdr[i].memsz, LE);
		elf->programHeaders[i].alignment = u8_to_u32(phdr[i].align, LE);
	}

	return 0;
}

/* Section Hdr Functions */

bool IsBss(elf_section_entry *section)
{
	return (section->type == SHT_NOBITS && section->flags == (SHF_WRITE | SHF_ALLOC));
}

bool IsData(elf_section_entry *section)
{
	return (section->type == SHT_PROGBITS && section->flags == (SHF_WRITE | SHF_ALLOC));
}

bool IsRoData(elf_section_entry *section)
{
	return (section->type == SHT_PROGBITS && section->flags == SHF_ALLOC);
}

bool IsText(elf_section_entry *section)
{
	return (section->type == SHT_PROGBITS && section->flags == (SHF_ALLOC | SHF_EXECINSTR));
}

/* Program Segment Functions */
void InitSegment(elf_segment *segment)
{
	memset(segment, 0, sizeof(elf_segment));

	segment->sectionNumMax = 10;
	segment->sectionNum = 0;
	segment->sections = calloc(segment->sectionNumMax, sizeof(elf_section_entry));
}

void AddSegmentSection(elf_segment *segment, elf_section_entry *section)
{
	if (segment->sectionNum < segment->sectionNumMax)
		memcpy(&segment->sections[segment->sectionNum], section, sizeof(elf_section_entry));
	else {
		segment->sectionNumMax *= 2;
		elf_section_entry *tmp = calloc(segment->sectionNumMax, sizeof(elf_section_entry));
		for (int k = 0; k < segment->sectionNum; k++)
			memcpy(&tmp[k], &segment->sections[k], sizeof(elf_section_entry));
		free(segment->sections);
		segment->sections = tmp;
		memcpy(&segment->sections[segment->sectionNum], section, sizeof(elf_section_entry));
	}

	segment->sectionNum++;
}

bool IsIgnoreSection(elf_section_entry info)
{
	return !(info.flags & SHF_ALLOC);//(info.type != SHT_PROGBITS && info.type != SHT_NOBITS && info.type != SHT_INIT_ARRAY && info.type != SHT_FINI_ARRAY && info.type != SHT_ARM_EXIDX);
}

int CreateElfSegments(elf_context *elf)
{
	// Interate through Each Program Header
	elf->activeSegments = 0;
	elf->segments = calloc(elf->programTableEntryCount,sizeof(elf_segment));

	elf_segment segment;

	bool foundFirstSection = false;
	int curr, prev;
	u32 padding, size, sizeInMemory;

	for (int i = 0; i < elf->programTableEntryCount; i++){
		if (elf->programHeaders[i].sizeInMemory != 0 && elf->programHeaders[i].type == PF_X){
			InitSegment(&segment);

			foundFirstSection = false;
			size = 0;
			sizeInMemory = elf->programHeaders[i].sizeInMemory;

			// Itterate Through Section Headers
			for (curr = 0; curr < elf->sectionTableEntryCount && size != sizeInMemory; curr++){
				// Skip irrelevant sections
				if (IsIgnoreSection(elf->sections[curr]))
					continue;


				if (!foundFirstSection) {
					if (elf->sections[curr].address != elf->programHeaders[i].virtualAddress)
						continue;

					foundFirstSection = true;
					segment.vAddr = elf->sections[curr].address;
					segment.name = elf->sections[curr].name;

					AddSegmentSection(&segment, &elf->sections[curr]);
					size = elf->sections[curr].size;
				}
				else {
					AddSegmentSection(&segment, &elf->sections[curr]);
					padding = elf->sections[curr].address - (elf->sections[prev].address + elf->sections[prev].size);
					size += padding + elf->sections[curr].size;
				}
				prev = curr;

				// Catch section parsing fails
				if (size > sizeInMemory){
					fprintf(stderr,"[ELF ERROR] Too large section size.\n Segment size = 0x%x\n Section Size = 0x%x\n", sizeInMemory, size);
					return ELF_SEGMENT_SECTION_SIZE_MISMATCH;
				}
            }
			if(segment.sectionNum){
				segment.header = &elf->programHeaders[i];
				memcpy(&elf->segments[elf->activeSegments],&segment,sizeof(elf_segment));
				elf->activeSegments++;
			}
			else{
				free(segment.sections);
				fprintf(stderr,"[ELF ERROR] Program Header Has no corresponding Sections, ELF Cannot be proccessed\n");
				return ELF_SEGMENTS_NOT_FOUND;
			}
		}
	}

	return 0;
}