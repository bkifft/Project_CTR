#include "lib.h"
#include "ncch_build.h"
#include "exheader_read.h"
#include "elf_hdr.h"
#include "elf.h"
#include "blz.h"

int ImportPlainRegionFromFile(ncch_settings *set);
int ImportExeFsCodeBinaryFromFile(ncch_settings *set);

u32 GetPageSize(ncch_settings *set);
u32 SizeToPage(u32 memorySize, elf_context *elf);

int GetBSSFromElf(elf_context *elf, u8 *elfFile, ncch_settings *set);
int ImportPlainRegionFromElf(elf_context *elf, u8 *elfFile, ncch_settings *set);
int CreateExeFsCode(elf_context *elf, u8 *elfFile, ncch_settings *set);
int CreateCodeSegmentFromElf(code_segment *out, elf_context *elf, u8 *elfFile, char **names, u32 nameNum);
elf_segment** GetContinuousSegments(u16 *ContinuousSegmentNum, elf_context *elf, char **names, u32 nameNum);
elf_segment** GetSegments(u16 *SegmentNum, elf_context *elf, char **names, u32 nameNum);

// ELF Functions
int GetElfContext(elf_context *elf, u8 *elfFile);
int GetElfSectionEntries(elf_context *elf, u8 *elfFile);
int GetElfProgramEntries(elf_context *elf, u8 *elfFile);
void PrintElfContext(elf_context *elf, u8 *elfFile);
int ReadElfHdr(elf_context *elf, u8 *elfFile);

int CreateElfSegments(elf_context *elf, u8 *elfFile);
bool IsIgnoreSection(elf_section_entry info);

/* ELF Section Entry Functions */
u8* GetELFSectionHeader(u16 index, elf_context *elf, u8 *elfFile);
u8* GetELFSectionEntry(u16 index, elf_context *elf, u8 *elfFile);
char* GetELFSectionEntryName(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFSectionEntryType(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFSectionEntryFlags(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFSectionEntryAddress(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFSectionEntryFileOffset(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFSectionEntrySize(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFSectionEntryAlignment(u16 index, elf_context *elf, u8 *elfFile);

u16 GetElfSectionIndexFromName(char *name, elf_context *elf, u8 *elfFile);

bool IsBss(elf_section_entry *section);
bool IsData(elf_section_entry *section);
bool IsRoData(elf_section_entry *section);
bool IsText(elf_section_entry *section);

/* ELF Program Entry Functions */
u8* GetELFProgramHeader(u16 index, elf_context *elf, u8 *elfFile);
u8* GetELFProgramEntry(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryType(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryFlags(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryFileSize(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryFileOffset(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryMemorySize(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryVAddress(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryPAddress(u16 index, elf_context *elf, u8 *elfFile);
u64 GetELFProgramEntryAlignment(u16 index, elf_context *elf, u8 *elfFile);


int BuildExeFsCode(ncch_settings *set)
{
	int result = 0;
	if(set->options.IsCfa)
		return result;
	if(set->componentFilePtrs.plainregion){ // Import PlainRegion from file
		result = ImportPlainRegionFromFile(set);
		if(result) return result;
	}
	if(!set->options.IsBuildingCodeSection){ // Import ExeFs Code from file and return
		result = ImportExeFsCodeBinaryFromFile(set);
		return result;
	}

	/* Import ELF */
	u8 *elfFile = malloc(set->componentFilePtrs.elfSize);
	if(!elfFile) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}
	ReadFile64(elfFile,set->componentFilePtrs.elfSize,0,set->componentFilePtrs.elf);

	/* Create ELF Context */
	elf_context *elf = calloc(1,sizeof(elf_context));
	if(!elf) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		free(elfFile); 
		return MEM_ERROR;
	}
	
	result = GetElfContext(elf,elfFile);
	if(result) goto finish;

	/* Setting Page Size */
	elf->pageSize = GetPageSize(set);

	if(!set->componentFilePtrs.plainregion){
		result = ImportPlainRegionFromElf(elf,elfFile,set);
		if(result) goto finish;
	}

	if(set->options.verbose)
		PrintElfContext(elf,elfFile);

	result = CreateExeFsCode(elf,elfFile,set);
	if(result) goto finish;

	result = GetBSSFromElf(elf,elfFile,set);
	if(result) goto finish;

finish:
	switch (result) {
		case (0) :
			break;
		case (NOT_ELF_FILE) :
			fprintf(stderr, "[ELF ERROR] Not ELF File\n");
			break;
		case (NOT_ARM_ELF) :
			fprintf(stderr, "[ELF ERROR] Not ARM ELF\n");
			break;
		case (NON_EXECUTABLE_ELF) :
			fprintf(stderr, "[ELF ERROR] Not Executeable ELF\n");
			break;
		case (NOT_FIND_TEXT_SEGMENT) :
			fprintf(stderr, "[ELF ERROR] Failed to retrieve text sections from ELF\n");
			break;
		case (NOT_FIND_DATA_SEGMENT) :
			fprintf(stderr, "[ELF ERROR] Failed to retrieve data sections from ELF\n");
			break;
		default:
			fprintf(stderr, "[ELF ERROR] Failed to process ELF file (%d)\n", result);
	}
	for(int i = 0; i < elf->activeSegments; i++)
		free(elf->segments[i].sections);
	free(elfFile);
	free(elf->sections);
	free(elf->programHeaders);
	free(elf->segments);
	free(elf);
	return result;	
}

int ImportPlainRegionFromFile(ncch_settings *set)
{
	set->sections.plainRegion.size = align(set->componentFilePtrs.plainregionSize,set->options.blockSize);
	set->sections.plainRegion.buffer = malloc(set->sections.plainRegion.size);
	if(!set->sections.plainRegion.buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	ReadFile64(set->sections.plainRegion.buffer,set->componentFilePtrs.plainregionSize,0,set->componentFilePtrs.plainregion);
	return 0;
}

int ImportExeFsCodeBinaryFromFile(ncch_settings *set)
{
	u32 size = set->componentFilePtrs.codeSize;
	u8 *buffer = malloc(size);
	if(!buffer) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(buffer,size,0,set->componentFilePtrs.code);

	set->exefsSections.code.size = set->componentFilePtrs.codeSize;
	set->exefsSections.code.buffer = malloc(set->exefsSections.code.size);
	if(!set->exefsSections.code.buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	ReadFile64(set->exefsSections.code.buffer,set->exefsSections.code.size,0,set->componentFilePtrs.code);
	if(set->options.CompressCode){
		u32 new_len;
		set->exefsSections.code.buffer = BLZ_Code(buffer,size,&new_len,BLZ_NORMAL);
		set->exefsSections.code.size = new_len;
		free(buffer);
	}
	else{
		set->exefsSections.code.size = size;
		set->exefsSections.code.buffer = buffer;
	}
	
	size = set->componentFilePtrs.exhdrSize;
	if(size < sizeof(extended_hdr)){
		fprintf(stderr,"[ELF ERROR] Exheader code info template is too small\n");
		return FAILED_TO_IMPORT_FILE;
	}
	extended_hdr *exhdr = malloc(size);
	if(!exhdr) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n");
		return MEM_ERROR;
	}
	ReadFile64(exhdr,size,0,set->componentFilePtrs.exhdr);
	
	/* Setting code_segment data */
	set->codeDetails.textAddress = u8_to_u32(exhdr->codeSetInfo.text.address,LE);
	set->codeDetails.textMaxPages = u8_to_u32(exhdr->codeSetInfo.text.numMaxPages,LE);
	set->codeDetails.textSize = u8_to_u32(exhdr->codeSetInfo.text.codeSize,LE);

	set->codeDetails.roAddress = u8_to_u32(exhdr->codeSetInfo.rodata.address,LE);
	set->codeDetails.roMaxPages = u8_to_u32(exhdr->codeSetInfo.rodata.numMaxPages,LE);
	set->codeDetails.roSize = u8_to_u32(exhdr->codeSetInfo.rodata.codeSize,LE);

	set->codeDetails.rwAddress = u8_to_u32(exhdr->codeSetInfo.data.address,LE);
	set->codeDetails.rwMaxPages = u8_to_u32(exhdr->codeSetInfo.data.numMaxPages,LE);
	set->codeDetails.rwSize = u8_to_u32(exhdr->codeSetInfo.data.codeSize,LE);
	
	set->codeDetails.bssSize = u8_to_u32(exhdr->codeSetInfo.bssSize,LE);
	
	free(exhdr);
	
	return 0;
}

u32 GetPageSize(ncch_settings *set)
{
	if(set->rsfSet->Option.PageSize)
		return strtoul(set->rsfSet->Option.PageSize,NULL,10);
	return 0x1000;
}

u32 SizeToPage(u32 memorySize, elf_context *elf)
{
	return align(memorySize,elf->pageSize)/elf->pageSize;
}


int GetBSSFromElf(elf_context *elf, u8 *elfFile, ncch_settings *set)
{
	set->codeDetails.bssSize = 0;
	
	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		if(IsBss(&elf->sections[i]))
			set->codeDetails.bssSize = elf->sections[i].size;
	}
	
	return 0;
}

int ImportPlainRegionFromElf(elf_context *elf, u8 *elfFile, ncch_settings *set) // Doesn't work same as N makerom
{
	if(!set->rsfSet->PlainRegionNum) return 0;
	u16 *index = calloc(set->rsfSet->PlainRegionNum,sizeof(u16));

	/* Getting index Values for each section */
	for(int i = 0; i < set->rsfSet->PlainRegionNum; i++){
		index[i] = GetElfSectionIndexFromName(set->rsfSet->PlainRegion[i],elf,elfFile);
	}

	// Eliminating Duplicated Sections
	for(int i = set->rsfSet->PlainRegionNum - 1; i >= 0; i--){
		for(int j = i-1; j >= 0; j--){
			if(index[i] == index[j]) index[i] = 0;
		}
	}

	/* Calculating Total Size of Data */
	u64 totalSize = 0;
	for(int i = 0; i < set->rsfSet->PlainRegionNum; i++){
		totalSize += elf->sections[index[i]].size;
	}
	
	/* Creating Output Buffer */
	set->sections.plainRegion.size = align(totalSize,set->options.blockSize);
	set->sections.plainRegion.buffer = malloc(set->sections.plainRegion.size);
	if(!set->sections.plainRegion.buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	memset(set->sections.plainRegion.buffer,0,set->sections.plainRegion.size);

	/* Storing Sections */
	u64 pos = 0;
	for(int i = 0; i < set->rsfSet->PlainRegionNum; i++){
		memcpy((set->sections.plainRegion.buffer+pos),elf->sections[index[i]].ptr,elf->sections[index[i]].size);
		pos += elf->sections[index[i]].size;
	}
	return 0;
}

int CreateExeFsCode(elf_context *elf, u8 *elfFile, ncch_settings *set)
{
	/* Getting Code Segments */
	code_segment text;
	memset(&text,0,sizeof(code_segment));
	code_segment rodata;
	memset(&rodata,0,sizeof(code_segment));
	code_segment rwdata;
	memset(&rwdata,0,sizeof(code_segment));

	int result = CreateCodeSegmentFromElf(&text,elf,elfFile,set->rsfSet->ExeFs.Text,set->rsfSet->ExeFs.TextNum);
	if(result) return result;
	result = CreateCodeSegmentFromElf(&rodata,elf,elfFile,set->rsfSet->ExeFs.ReadOnly,set->rsfSet->ExeFs.ReadOnlyNum);
	if(result) return result;
	result = CreateCodeSegmentFromElf(&rwdata,elf,elfFile,set->rsfSet->ExeFs.ReadWrite,set->rsfSet->ExeFs.ReadWriteNum);
	if(result) return result;

	/* Checking the existence of essential ELF Segments */
	if(!text.size) return NOT_FIND_TEXT_SEGMENT;
	if(!rwdata.size) return NOT_FIND_DATA_SEGMENT;
	
	/* Allocating Buffer for ExeFs Code */
	u32 size = (text.maxPageNum + rodata.maxPageNum + rwdata.maxPageNum)*elf->pageSize;
	u8 *code = calloc(1,size);

	/* Writing Code into Buffer */
	u8 *textPos = (code + 0);
	u8 *rodataPos = (code + text.maxPageNum*elf->pageSize);
	u8 *rwdataPos = (code + (text.maxPageNum + rodata.maxPageNum)*elf->pageSize);
	if(text.size) memcpy(textPos,text.data,text.size);
	if(rodata.size) memcpy(rodataPos,rodata.data,rodata.size);
	if(rwdata.size) memcpy(rwdataPos,rwdata.data,rwdata.size);


	/* Compressing If needed */
	if(set->options.CompressCode){
		u32 new_len;
		set->exefsSections.code.buffer = BLZ_Code(code,size,&new_len,BLZ_NORMAL);
		set->exefsSections.code.size = new_len;
		free(code);
	}
	else{
		set->exefsSections.code.size = size;
		set->exefsSections.code.buffer = code;
	}

	/* Setting code_segment data and freeing original buffers */
	set->codeDetails.textAddress = text.address;
	set->codeDetails.textMaxPages = text.maxPageNum;
	set->codeDetails.textSize = text.size;
	if(text.size) free(text.data);

	set->codeDetails.roAddress = rodata.address;
	set->codeDetails.roMaxPages = rodata.maxPageNum;
	set->codeDetails.roSize = rodata.size;
	if(rodata.size) free(rodata.data);

	set->codeDetails.rwAddress = rwdata.address;
	set->codeDetails.rwMaxPages = rwdata.maxPageNum;
	set->codeDetails.rwSize = rwdata.size;
	if(rwdata.size) free(rwdata.data);

	/* Return */
	return 0;
}

int CreateCodeSegmentFromElf(code_segment *out, elf_context *elf, u8 *elfFile, char **names, u32 nameNum)
{
	u16 ContinuousSegmentNum = 0;
	memset(out,0,sizeof(code_segment));
	elf_segment **ContinuousSegments = GetContinuousSegments(&ContinuousSegmentNum,elf,names,nameNum);
	if (ContinuousSegments == NULL){
		if(!ContinuousSegmentNum){// Nothing Was Found
			//printf("Nothing was found\n");
			return 0;
		}
		else // Error with found segments
			return ELF_SEGMENTS_NOT_CONTINUOUS;
	}
	
	/* Getting Segment Size/Settings */
	u32 vAddr = 0;
	u32 memorySize = 0;
	for(int i = 0; i < ContinuousSegmentNum; i++){
		if (i==0){
			vAddr = ContinuousSegments[i]->vAddr;
		}
		else{ // Add rounded size from previous segment
			u32 padding = ContinuousSegments[i]->vAddr - (vAddr + memorySize);
			memorySize += padding;
		}

		memorySize += ContinuousSegments[i]->header->sizeInMemory;

		if(IsBss(&ContinuousSegments[i]->sections[ContinuousSegments[i]->sectionNum-1]))
			memorySize -= ContinuousSegments[i]->sections[ContinuousSegments[i]->sectionNum-1].size;
	}
	
	// For Check
#ifdef DEBUG
	printf("Address: 0x%x\n",vAddr);
	printf("Size:    0x%x\n",memorySize);
#endif

	out->address = vAddr;
	out->size = memorySize;
	out->maxPageNum = SizeToPage(memorySize,elf);
	out->data = malloc(memorySize);
	
	/* Writing Segment to Buffer */
	//vAddr = 0;
	//memorySize = 0;
	for(int i = 0; i < ContinuousSegmentNum; i++){
		/*
		if (i==0)
			vAddr = ContinuousSegments[i]->vAddr;
		
		else{
			u32 num = ContinuousSegments[i]->vAddr - (vAddr + memorySize);
			memorySize += num;
		}
		*/
		//u32 size = 0;
		for (int j = 0; j < ContinuousSegments[i]->sectionNum; j++){
			elf_section_entry *section = &ContinuousSegments[i]->sections[j];
			if (!IsBss(section)){				
				u8 *pos = (out->data + (section->address - ContinuousSegments[i]->vAddr));
				memcpy(pos,section->ptr,section->size);
				//size += section->size;
			}

			//else if (j == (ContinuousSegments[i]->sectionNum-1))
				//memorySize -= section->size;
			//'else
				//size += section->size;
		}
	}

	free(ContinuousSegments);
	return 0;
}


elf_segment** GetContinuousSegments(u16 *ContinuousSegmentNum, elf_context *elf, char **names, u32 nameNum)
{
	u16 SegmentNum = 0;
	elf_segment **Segments = GetSegments(&SegmentNum, elf, names, nameNum);
	if (Segments == NULL || SegmentNum == 0){ // No Segments for the names were found
		//printf("Not Found Segment\n");
		return NULL;
	}

	if (SegmentNum == 1){ //Return as there is no need to check
		*ContinuousSegmentNum = SegmentNum;
		return Segments;
	}

	u32 vAddr = Segments[0]->vAddr + Segments[0]->header->sizeInMemory;
	for (int i = 1; i < SegmentNum; i++){
		if (Segments[i]->vAddr != (u32)align(vAddr,Segments[i]->header->alignment)){ //Each Segment must start after each other
			fprintf(stderr,"[ELF ERROR] %s segment and %s segment are not continuous\n", Segments[i]->name, Segments[i - 1]->name);
			free(Segments);
			*ContinuousSegmentNum = 0xffff; // Signify to function that an error occured
			return NULL;
		}
	}
	*ContinuousSegmentNum = SegmentNum;
	return Segments;
}


elf_segment** GetSegments(u16 *SegmentNum, elf_context *elf, char **names, u32 nameNum)
{
	if (names == NULL)
	{
		return NULL;
	}

	elf_segment **Segments = calloc(nameNum,sizeof(elf_segment*)); 
	*SegmentNum = 0; // There can be a max of nameNum Segments, however, they might not all exist
	for (int i = 0; i < nameNum; i++){
		for(int j = 0; j < elf->activeSegments; j++){
			if(strcmp(names[i],elf->segments[j].name) == 0){ // If there is a match, store Segment data pointer & increment index
				Segments[*SegmentNum] = &elf->segments[j];
				*SegmentNum = *SegmentNum + 1;
			}
		}
	}
	return Segments;
}

// ELF Functions

int GetElfContext(elf_context *elf, u8 *elfFile)
{
	if(u8_to_u32(elfFile,BE) != ELF_MAGIC) return NOT_ELF_FILE;
	
	elf->Is64bit = (elfFile[4] == elf_64_bit);
	elf->IsLittleEndian = (elfFile[5] == elf_little_endian);
	
	int result = ReadElfHdr(elf,elfFile);
	if(result) return result;

	result = GetElfSectionEntries(elf,elfFile);
	if(result) return result;

	result = GetElfProgramEntries(elf,elfFile);
	if(result) return result;

	result = CreateElfSegments(elf,elfFile);
	if(result) return result;

	return 0;
}

int GetElfSectionEntries(elf_context *elf, u8 *elfFile)
{
	elf->sections = calloc(elf->sectionTableEntryCount,sizeof(elf_section_entry));
	if(!elf->sections) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		elf->sections[i].name = GetELFSectionEntryName(i,elf,elfFile);
		elf->sections[i].type = GetELFSectionEntryType(i,elf,elfFile);
		elf->sections[i].flags = GetELFSectionEntryFlags(i,elf,elfFile);
		elf->sections[i].ptr = GetELFSectionEntry(i,elf,elfFile);
		elf->sections[i].offsetInFile = GetELFSectionEntryFileOffset(i,elf,elfFile);
		elf->sections[i].size = GetELFSectionEntrySize(i,elf,elfFile);
		elf->sections[i].address = GetELFSectionEntryAddress(i,elf,elfFile);
		elf->sections[i].alignment = GetELFSectionEntryAlignment(i,elf,elfFile);
	}
	return 0;
}

int GetElfProgramEntries(elf_context *elf, u8 *elfFile)
{
	elf->programHeaders = calloc(elf->programTableEntryCount,sizeof(elf_program_entry));
	if(!elf->programHeaders) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	for(int i = 0; i < elf->programTableEntryCount; i++){
		elf->programHeaders[i].type = GetELFProgramEntryType(i,elf,elfFile);
		elf->programHeaders[i].flags = GetELFProgramEntryFlags(i,elf,elfFile);
		elf->programHeaders[i].ptr = GetELFProgramEntry(i,elf,elfFile);
		elf->programHeaders[i].offsetInFile = GetELFProgramEntryFileOffset(i,elf,elfFile);
		elf->programHeaders[i].sizeInFile = GetELFProgramEntryFileSize(i,elf,elfFile);
		elf->programHeaders[i].physicalAddress = GetELFProgramEntryPAddress(i,elf,elfFile);
		elf->programHeaders[i].virtualAddress = GetELFProgramEntryVAddress(i,elf,elfFile);
		elf->programHeaders[i].sizeInMemory = GetELFProgramEntryMemorySize(i,elf,elfFile);
		elf->programHeaders[i].alignment = GetELFProgramEntryAlignment(i,elf,elfFile);
	}

	return 0;
}

void PrintElfContext(elf_context *elf, u8 *elfFile)
{
	printf("[ELF] Basic Details\n");
	printf(" Class:  %s\n",elf->Is64bit ? "64-bit" : "32-bit");
	printf(" Data:   %s\n",elf->IsLittleEndian ? "Little Endian" : "Big Endian");
	printf("[ELF] Program Table Data\n");
	printf(" Offset: 0x%"PRIx64"\n",elf->programTableOffset);
	printf(" Size:   0x%x\n",elf->programTableEntrySize);
	printf(" Count:  0x%x\n",elf->programTableEntryCount);
	printf("[ELF] Section Table Data\n");
	printf(" Offset: 0x%"PRIx64"\n",elf->sectionTableOffset);
	printf(" Size:   0x%x\n",elf->sectionTableEntrySize);
	printf(" Count:  0x%x\n",elf->sectionTableEntryCount);
	printf(" Label index: 0x%x\n",elf->sectionHeaderNameEntryIndex);
	for(int i = 0; i < elf->activeSegments; i++){
		printf(" Segment [%d][%s]\n",i,elf->segments[i].name);
		printf(" > Size :     0x%"PRIx64"\n",elf->segments[i].header->sizeInFile);
		printf(" > Address :  0x%"PRIx64"\n",elf->segments[i].vAddr);
		printf(" > Sections : %d\n",elf->segments[i].sectionNum);  
		for(int j = 0; j < elf->segments[i].sectionNum; j++)
			printf("    > Section [%d][%s]\n",j,elf->segments[i].sections[j].name);
		
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

int ReadElfHdr(elf_context *elf, u8 *elfFile)
{
	if(elf->Is64bit){
		elf_64_hdr *hdr = (elf_64_hdr*)elfFile;

		u16 Architecture = u8_to_u16(hdr->targetArchitecture,elf->IsLittleEndian);
		u16 Type = u8_to_u16(hdr->type,elf->IsLittleEndian);
		if(Architecture != elf_arm) return NOT_ARM_ELF;
		if(Type != elf_executeable) return NON_EXECUTABLE_ELF;

		elf->programTableOffset = u8_to_u64(hdr->programHeaderTableOffset,elf->IsLittleEndian);
		elf->programTableEntrySize = u8_to_u16(hdr->programHeaderEntrySize,elf->IsLittleEndian);
		elf->programTableEntryCount = u8_to_u16(hdr->programHeaderEntryCount,elf->IsLittleEndian);

		elf->sectionTableOffset = u8_to_u64(hdr->sectionHeaderTableOffset,elf->IsLittleEndian);
		elf->sectionTableEntrySize = u8_to_u16(hdr->sectionTableEntrySize,elf->IsLittleEndian);
		elf->sectionTableEntryCount = u8_to_u16(hdr->sectionHeaderEntryCount,elf->IsLittleEndian);

		elf->sectionHeaderNameEntryIndex = u8_to_u16(hdr->sectionHeaderNameEntryIndex,elf->IsLittleEndian);
	}
	else{
		elf_32_hdr *hdr = (elf_32_hdr*)elfFile;

		u16 Architecture = u8_to_u16(hdr->targetArchitecture,elf->IsLittleEndian);
		u16 Type = u8_to_u16(hdr->type,elf->IsLittleEndian);
		if(Architecture != elf_arm) return NOT_ARM_ELF;
		if(Type != elf_executeable) return NON_EXECUTABLE_ELF;

		elf->programTableOffset = u8_to_u32(hdr->programHeaderTableOffset,elf->IsLittleEndian);
		elf->programTableEntrySize = u8_to_u16(hdr->programHeaderEntrySize,elf->IsLittleEndian);
		elf->programTableEntryCount = u8_to_u16(hdr->programHeaderEntryCount,elf->IsLittleEndian);

		elf->sectionTableOffset = u8_to_u32(hdr->sectionHeaderTableOffset,elf->IsLittleEndian);
		elf->sectionTableEntrySize = u8_to_u16(hdr->sectionTableEntrySize,elf->IsLittleEndian);
		elf->sectionTableEntryCount = u8_to_u16(hdr->sectionHeaderEntryCount,elf->IsLittleEndian);

		elf->sectionHeaderNameEntryIndex = u8_to_u16(hdr->sectionHeaderNameEntryIndex,elf->IsLittleEndian);
	}
	return 0;
}

/* Section Hdr Functions */

u8* GetELFSectionHeader(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return NULL;

	return (elfFile + elf->sectionTableOffset + elf->sectionTableEntrySize*index);
}

u8* GetELFSectionEntry(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return NULL;

	return (u8*) (elfFile + GetELFSectionEntryFileOffset(index,elf,elfFile));
}

char* GetELFSectionEntryName(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	u64 NameIndex = 0;
	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		NameIndex = u8_to_u64(shdr->sh_name,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		NameIndex = u8_to_u32(shdr->sh_name,elf->IsLittleEndian);
	}

	u8 *NameTable = GetELFSectionEntry(elf->sectionHeaderNameEntryIndex,elf,elfFile);
	
	return (char*)(NameTable+NameIndex);
}

u64 GetELFSectionEntryType(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u64(shdr->sh_type,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u32(shdr->sh_type,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryFlags(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u64(shdr->sh_flags,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u32(shdr->sh_flags,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryAddress(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u64(shdr->sh_addr,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u32(shdr->sh_addr,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryFileOffset(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u64(shdr->sh_offset,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u32(shdr->sh_offset,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntrySize(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u64(shdr->sh_size,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u32(shdr->sh_size,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryAlignment(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u64(shdr->sh_addralign,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(index,elf,elfFile);
		return u8_to_u32(shdr->sh_addralign,elf->IsLittleEndian);
	}

	return 0;
}


u16 GetElfSectionIndexFromName(char *name, elf_context *elf, u8 *elfFile)
{
	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		if(strcmp(name,elf->sections[i].name) == 0) return i;
	}
	return 0; // Assuming 0 is always empty
}

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

/* ProgramHeader Functions */

u8* GetELFProgramHeader(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return NULL;

	return (elfFile + elf->programTableOffset + elf->programTableEntrySize*index);
}

u8* GetELFProgramEntry(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return NULL;

	return (u8*) (elfFile + GetELFProgramEntryFileOffset(index,elf,elfFile));

	return NULL;
}

u64 GetELFProgramEntryType(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_type,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_type,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFlags(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_flags,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_flags,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFileSize(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_filesz,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_filesz,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFileOffset(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_offset,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_offset,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryMemorySize(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_memsz,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_memsz,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryVAddress(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_vaddr,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_vaddr,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryPAddress(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_paddr,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_paddr,elf->IsLittleEndian);
	}

	return 0;
}


u64 GetELFProgramEntryAlignment(u16 index, elf_context *elf, u8 *elfFile)
{
	if(index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u64(phdr->p_align,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(index,elf,elfFile);
		return u8_to_u32(phdr->p_align,elf->IsLittleEndian);
	}

	return 0;
}

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

int CreateElfSegments(elf_context *elf, u8 *elfFile)
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

			printf("new segment\n");

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

					printf("first section name: %s (vaddr = 0x%llx, size = 0x%llx)\n", elf->sections[curr].name, elf->sections[curr].address, elf->sections[curr].size);


					foundFirstSection = true;
					segment.vAddr = elf->sections[curr].address;
					segment.name = elf->sections[curr].name;

					AddSegmentSection(&segment, &elf->sections[curr]);
					size = elf->sections[curr].size;
				}
				else {

					printf("follw section name: %s (vaddr = 0x%llx, size = 0x%llx)\n", elf->sections[curr].name, elf->sections[curr].address, elf->sections[curr].size);

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

bool IsIgnoreSection(elf_section_entry info)
{
	printf("%s:0x%x,0x%x\n", info.name, info.type, info.flags);

	return (info.type != SHT_PROGBITS && info.type != SHT_NOBITS && info.type != SHT_INIT_ARRAY && info.type != SHT_FINI_ARRAY && info.type != SHT_ARM_EXIDX);
}
