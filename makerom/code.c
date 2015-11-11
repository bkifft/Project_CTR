#include "lib.h"
#include "elf.h"
#include "blz.h"
#include "ncch_build.h"
#include "exheader_read.h"
#include "code.h"

const char *SDK_PLAINREGION_SEGMENT_NAME = ".module_id";

typedef struct code_segment
{
	u32 address;
	u32 size;
	u32 maxPageNum;
	u8 *data;
} code_segment;

u32 GetPageSize(ncch_settings *set)
{
	if (set->rsfSet->Option.PageSize)
		return strtoul(set->rsfSet->Option.PageSize, NULL, 10);
	return 0x1000;
}

u32 SizeToPage(u32 memorySize, elf_context *elf)
{
	return align(memorySize, elf->pageSize) / elf->pageSize;
}

int ImportPlainRegionFromFile(ncch_settings *set)
{
	set->sections.plainRegion.size = align(set->componentFilePtrs.plainregionSize, set->options.blockSize);
	set->sections.plainRegion.buffer = malloc(set->sections.plainRegion.size);
	if (!set->sections.plainRegion.buffer) { fprintf(stderr, "[ELF ERROR] Not enough memory\n"); return MEM_ERROR; }
	ReadFile64(set->sections.plainRegion.buffer, set->componentFilePtrs.plainregionSize, 0, set->componentFilePtrs.plainregion);
	return 0;
}

int ImportExeFsCodeBinaryFromFile(ncch_settings *set)
{
	u32 size = set->componentFilePtrs.codeSize;
	u8 *buffer = malloc(size);
	if (!buffer) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(buffer, size, 0, set->componentFilePtrs.code);

	set->exefsSections.code.size = set->componentFilePtrs.codeSize;
	set->exefsSections.code.buffer = malloc(set->exefsSections.code.size);
	if (!set->exefsSections.code.buffer) { fprintf(stderr, "[ELF ERROR] Not enough memory\n"); return MEM_ERROR; }
	ReadFile64(set->exefsSections.code.buffer, set->exefsSections.code.size, 0, set->componentFilePtrs.code);
	if (set->options.CompressCode) {
		if (set->options.verbose)
			printf("[CODE] Compressing code... ");
		u32 new_len;
		set->exefsSections.code.buffer = BLZ_Code(buffer, size, &new_len, BLZ_NORMAL);
		set->exefsSections.code.size = new_len;
		free(buffer);
		if (set->options.verbose)
			printf("Done!\n");
	}
	else {
		set->exefsSections.code.size = size;
		set->exefsSections.code.buffer = buffer;
	}

	size = set->componentFilePtrs.exhdrSize;
	if (size < sizeof(extended_hdr)) {
		fprintf(stderr, "[CODE ERROR] Exheader code info template is too small\n");
		return FAILED_TO_IMPORT_FILE;
	}
	extended_hdr *exhdr = malloc(size);
	if (!exhdr) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(exhdr, size, 0, set->componentFilePtrs.exhdr);

	/* Setting code_segment data */
	set->codeDetails.textAddress = u8_to_u32(exhdr->codeSetInfo.text.address, LE);
	set->codeDetails.textMaxPages = u8_to_u32(exhdr->codeSetInfo.text.numMaxPages, LE);
	set->codeDetails.textSize = u8_to_u32(exhdr->codeSetInfo.text.codeSize, LE);

	set->codeDetails.roAddress = u8_to_u32(exhdr->codeSetInfo.rodata.address, LE);
	set->codeDetails.roMaxPages = u8_to_u32(exhdr->codeSetInfo.rodata.numMaxPages, LE);
	set->codeDetails.roSize = u8_to_u32(exhdr->codeSetInfo.rodata.codeSize, LE);

	set->codeDetails.rwAddress = u8_to_u32(exhdr->codeSetInfo.data.address, LE);
	set->codeDetails.rwMaxPages = u8_to_u32(exhdr->codeSetInfo.data.numMaxPages, LE);
	set->codeDetails.rwSize = u8_to_u32(exhdr->codeSetInfo.data.codeSize, LE);

	set->codeDetails.bssSize = u8_to_u32(exhdr->codeSetInfo.bssSize, LE);

	set->codeDetails.stackSize = u8_to_u32(exhdr->codeSetInfo.stackSize, LE);

	free(exhdr);

	return 0;
}

int GetBSSFromElf(elf_context *elf, ncch_settings *set)
{
	set->codeDetails.bssSize = 0;

	for (int i = 0; i < elf->sectionTableEntryCount; i++) {
		if (IsBss(&elf->sections[i]))
			set->codeDetails.bssSize = elf->sections[i].size;
	}

	return 0;
}

int ImportPlainRegionFromElf(elf_context *elf, ncch_settings *set) // Doesn't work same as N makerom
{
	u64 size = 0;
	u64 offset = 0;
	for (u16 i = 0; i < elf->activeSegments; i++) {
		if (strcmp(elf->segments[i].name, SDK_PLAINREGION_SEGMENT_NAME) == 0) {
			size = elf->segments[i].header->sizeInFile;
			offset = elf->segments[i].header->offsetInFile;
			break;
		}
	}


	if (size > 0) {
		/* Creating Output Buffer */
		set->sections.plainRegion.size = align(size, set->options.blockSize);
		set->sections.plainRegion.buffer = malloc(set->sections.plainRegion.size);
		if (!set->sections.plainRegion.buffer) { fprintf(stderr, "[ELF ERROR] Not enough memory\n"); return MEM_ERROR; }
		memset(set->sections.plainRegion.buffer, 0, set->sections.plainRegion.size);

		/* Copy Plain Region */
		memcpy(set->sections.plainRegion.buffer, elf->file + offset, size);
	}

	return 0;
}

int CreateCodeSegmentFromElf(code_segment *out, elf_context *elf, u64 segment_flags)
{
	memset(out, 0, sizeof(code_segment));

	u16 seg_num = 0;
	elf_segment **seg = calloc(elf->activeSegments, sizeof(elf_segment*));

	for (u16 i = 0; i < elf->activeSegments; i++) {
		// Skip SDK ELF plain region
		if (strcmp(elf->segments[i].name, SDK_PLAINREGION_SEGMENT_NAME) == 0)
			continue;

		//printf("SegName: %s (flags: %x)\n", elf->segments[i].name, elf->segments[i].header->flags);
		if ((elf->segments[i].header->flags & ~PF_CTRSDK) == segment_flags) {
			if (seg_num == 0) {
				seg[seg_num] = &elf->segments[i];
				seg_num++;
			}
			else if (elf->segments[i].vAddr == (u32)align(seg[seg_num - 1]->vAddr, seg[seg_num - 1]->header->alignment)) {
				seg[seg_num] = &elf->segments[i];
				seg_num++;
			}
		}
	}

	/* Return if there are no applicable segment */
	if (seg_num == 0)
		return 0;

	/* Getting Segment Size/Settings */
	u32 vAddr = 0;
	u32 memorySize = 0;
	for (u16 i = 0; i < seg_num; i++) {
		if (i == 0) {
			vAddr = seg[i]->vAddr;
		}
		else { // Add rounded size from previous segment
			u32 padding = seg[i]->vAddr - (vAddr + memorySize);
			memorySize += padding;
		}

		memorySize += seg[i]->header->sizeInMemory;

		if (IsBss(&seg[i]->sections[seg[i]->sectionNum - 1]))
			memorySize -= seg[i]->sections[seg[i]->sectionNum - 1].size;
	}

	// For Check
#ifdef DEBUG
	printf("Address: 0x%x\n", vAddr);
	printf("Size:    0x%x\n", memorySize);
#endif

	out->address = vAddr;
	out->size = memorySize;
	out->maxPageNum = SizeToPage(memorySize, elf);
	out->data = malloc(memorySize);

	/* Writing Segment to Buffer */
	for (int i = 0; i < seg_num; i++) {

		for (int j = 0; j < seg[i]->sectionNum; j++) {
			elf_section_entry *section = &seg[i]->sections[j];
			if (!IsBss(section)) {
				u8 *pos = (out->data + (section->address - seg[i]->vAddr));
				memcpy(pos, section->ptr, section->size);
				//size += section->size;
			}
		}
	}

	free(seg);
	return 0;
}

int CreateExeFsCode(elf_context *elf, ncch_settings *set)
{
	/* Getting Code Segments */
	code_segment text;
	memset(&text, 0, sizeof(code_segment));
	code_segment rodata;
	memset(&rodata, 0, sizeof(code_segment));
	code_segment rwdata;
	memset(&rwdata, 0, sizeof(code_segment));

	int result = CreateCodeSegmentFromElf(&text, elf, PF_TEXT);
	if (result) return result;
	result = CreateCodeSegmentFromElf(&rodata, elf, PF_RODATA);
	if (result) return result;
	result = CreateCodeSegmentFromElf(&rwdata, elf, PF_DATA);
	if (result) return result;

	/* Checking the existence of essential ELF Segments */
	if (!text.size) return NOT_FIND_TEXT_SEGMENT;
	if (!rwdata.size) return NOT_FIND_DATA_SEGMENT;

	/* Allocating Buffer for ExeFs Code */
	u32 size = (text.maxPageNum + rodata.maxPageNum + rwdata.maxPageNum)*elf->pageSize;
	u8 *code = calloc(1, size);

	/* Writing Code into Buffer */
	u8 *textPos = (code + 0);
	u8 *rodataPos = (code + text.maxPageNum*elf->pageSize);
	u8 *rwdataPos = (code + (text.maxPageNum + rodata.maxPageNum)*elf->pageSize);
	if (text.size) memcpy(textPos, text.data, text.size);
	if (rodata.size) memcpy(rodataPos, rodata.data, rodata.size);
	if (rwdata.size) memcpy(rwdataPos, rwdata.data, rwdata.size);


	/* Compressing If needed */
	if (set->options.CompressCode) {
		if (set->options.verbose)
			printf("[CODE] Compressing code... ");
		u32 new_len;
		set->exefsSections.code.buffer = BLZ_Code(code, size, &new_len, BLZ_NORMAL);
		set->exefsSections.code.size = new_len;
		free(code);
		if (set->options.verbose)
			printf("Done!\n");
	}
	else {
		set->exefsSections.code.size = size;
		set->exefsSections.code.buffer = code;
	}

	/* Setting code_segment data and freeing original buffers */
	set->codeDetails.textAddress = text.address;
	set->codeDetails.textMaxPages = text.maxPageNum;
	set->codeDetails.textSize = text.size;
	if (text.size) free(text.data);

	set->codeDetails.roAddress = rodata.address;
	set->codeDetails.roMaxPages = rodata.maxPageNum;
	set->codeDetails.roSize = rodata.size;
	if (rodata.size) free(rodata.data);

	set->codeDetails.rwAddress = rwdata.address;
	set->codeDetails.rwMaxPages = rwdata.maxPageNum;
	set->codeDetails.rwSize = rwdata.size;
	if (rwdata.size) free(rwdata.data);

	if (set->rsfSet->SystemControlInfo.StackSize)
		set->codeDetails.stackSize = strtoul(set->rsfSet->SystemControlInfo.StackSize, NULL, 0);
	else {
		fprintf(stderr, "[CODE ERROR] RSF Parameter Not Found: \"SystemControlInfo/StackSize\"\n");
		return 1;
	}

	/* Return */
	return 0;
}

void PrintElfContext(elf_context *elf)
{
	printf("[ELF] Program Table Data\n");
	printf(" Offset: 0x%x\n", elf->programTableOffset);
	printf(" Size:   0x%x\n", elf->programTableEntrySize);
	printf(" Count:  0x%x\n", elf->programTableEntryCount);
	printf("[ELF] Section Table Data\n");
	printf(" Offset: 0x%x\n", elf->sectionTableOffset);
	printf(" Size:   0x%x\n", elf->sectionTableEntrySize);
	printf(" Count:  0x%x\n", elf->sectionTableEntryCount);
	printf(" Label index: 0x%x\n", elf->sectionHeaderNameEntryIndex);
	for (int i = 0; i < elf->activeSegments; i++) {
		printf(" Segment [%d][%s]\n", i, elf->segments[i].name);
		printf(" > Size :     0x%x\n", elf->segments[i].header->sizeInFile);
		printf(" > Address :  0x%x\n", elf->segments[i].vAddr);
		printf(" > Flags:     0x%x\n", elf->segments[i].header->flags);
		printf(" > Type:      0x%x\n", elf->segments[i].header->type);
		printf(" > Sections : %d\n", elf->segments[i].sectionNum);
		for (int j = 0; j < elf->segments[i].sectionNum; j++)
			printf("    > Section [%d][%s][0x%x][0x%x]\n", j, elf->segments[i].sections[j].name, elf->segments[i].sections[j].flags, elf->segments[i].sections[j].type);

		/*
		char outpath[100];
		memset(&outpath,0,100);
		sprintf(outpath,"%s.bin",elf->sections[i].name);
		chdir("elfsections");
		FILE *tmp = fopen(outpath,"wb");
		WriteBuffer(elf->sections[i].ptr,elf->sections[i].size,0,tmp);
		fclose(tmp);
		chdir("..");
		*/
	}

}

int BuildExeFsCode(ncch_settings *set)
{
	int result = 0;
	if (set->options.IsCfa)
		return result;

	if (set->componentFilePtrs.plainregion) // Import PlainRegion from file
		if ((result = ImportPlainRegionFromFile(set))) return result;
	if (!set->options.IsBuildingCodeSection) // Import ExeFs Code from file and return
		return ImportExeFsCodeBinaryFromFile(set);

	/* Import ELF */
	u8 *elfFile = malloc(set->componentFilePtrs.elfSize);
	if (!elfFile) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(elfFile, set->componentFilePtrs.elfSize, 0, set->componentFilePtrs.elf);

	/* Create ELF Context */
	elf_context *elf = calloc(1, sizeof(elf_context));
	if (!elf) {
		fprintf(stderr, "[CODE ERROR] Not enough memory\n");
		free(elfFile);
		return MEM_ERROR;
	}

	if ((result = GetElfContext(elf, elfFile))) goto finish;

	/* Setting Page Size */
	elf->pageSize = GetPageSize(set);

	if (!set->componentFilePtrs.plainregion)
		if ((result = ImportPlainRegionFromElf(elf, set))) goto finish;

	if (set->options.verbose)
		PrintElfContext(elf);

	if ((result = CreateExeFsCode(elf, set))) goto finish;
	if ((result = GetBSSFromElf(elf, set))) goto finish;

finish:
	switch (result) {
	case (0) :
		break;
	case (NOT_ELF_FILE) :
		fprintf(stderr, "[CODE ERROR] Not ELF File\n");
		break;
	case (NOT_CTR_ARM_ELF) :
		fprintf(stderr, "[CODE ERROR] Not CTR ARM ELF\n");
		break;
	case (NON_EXECUTABLE_ELF) :
		fprintf(stderr, "[CODE ERROR] Not Executeable ELF\n");
		break;
	case (NOT_FIND_TEXT_SEGMENT) :
		fprintf(stderr, "[CODE ERROR] Failed to retrieve text sections from ELF\n");
		break;
	case (NOT_FIND_DATA_SEGMENT) :
		fprintf(stderr, "[CODE ERROR] Failed to retrieve data sections from ELF\n");
		break;
	default:
		fprintf(stderr, "[CODE ERROR] Failed to process ELF file (%d)\n", result);
	}
	
	FreeElfContext(elf);
	free(elfFile);
	free(elf);
	return result;
}
