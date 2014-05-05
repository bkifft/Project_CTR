#include "lib.h"
#include "ncch.h"
#include "elf_hdr.h"
#include "elf.h"
#include "blz.h"

int ImportPlainRegionFromFile(ncch_settings *ncchset);
int ImportExeFsCodeBinaryFromFile(ncch_settings *ncchset);

u32 GetPageSize(ncch_settings *ncchset);
u32 SizeToPage(u32 memorySize, ElfContext *elf);

int GetBSS_SizeFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset);
int ImportPlainRegionFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset);
int CreateExeFsCode(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset);
int CreateCodeSegmentFromElf(CodeSegment *out, ElfContext *elf, u8 *ElfFile, char **Names, u32 NameNum);
ElfSegment** GetContinuousSegments(u16 *ContinuousSegmentNum, ElfContext *elf, char **Names, u32 NameNum);
ElfSegment** GetSegments(u16 *SegmentNum, ElfContext *elf, char **Names, u32 NameNum);

// ELF Functions
int GetElfContext(ElfContext *elf, u8 *ElfFile);
int GetElfSectionEntries(ElfContext *elf, u8 *ElfFile);
int GetElfProgramEntries(ElfContext *elf, u8 *ElfFile);
#ifdef DEBUG
void PrintElfContext(ElfContext *elf, u8 *ElfFile);
#endif
int ReadElfHdr(ElfContext *elf, u8 *ElfFile);

int CreateElfSegments(ElfContext *elf, u8 *ElfFile);
bool IsIgnoreSection(ElfSectionEntry info);

/* ELF Section Entry Functions */
u8* GetELFSectionHeader(u16 Index, ElfContext *elf, u8 *ElfFile);
u8* GetELFSectionEntry(u16 Index, ElfContext *elf, u8 *ElfFile);
char* GetELFSectionEntryName(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryType(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryAddress(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntrySize(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFSectionEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile);

u16 GetElfSectionIndexFromName(char *Name, ElfContext *elf, u8 *ElfFile);

bool IsBss(ElfSectionEntry *Section);
bool IsData(ElfSectionEntry *Section);
bool IsRO(ElfSectionEntry *Section);
bool IsText(ElfSectionEntry *Section);

/* ELF Program Entry Functions */
u8* GetELFProgramHeader(u16 Index, ElfContext *elf, u8 *ElfFile);
u8* GetELFProgramEntry(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryType(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryFileSize(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryMemorySize(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryVAddress(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryPAddress(u16 Index, ElfContext *elf, u8 *ElfFile);
u64 GetELFProgramEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile);


int BuildExeFsCode(ncch_settings *ncchset)
{
	int result = 0;
	if(ncchset->options.IsCfa)
		return result;
	if(ncchset->componentFilePtrs.plainregion){ // Import PlainRegion from file
		result = ImportPlainRegionFromFile(ncchset);
		if(result) return result;
	}
	if(!ncchset->options.IsBuildingCodeSection){ // Import ExeFs Code from file and return
		result = ImportExeFsCodeBinaryFromFile(ncchset);
		return result;
	}

#ifdef DEBUG
	printf("[DEBUG] Import ELF\n");
#endif
	/* Import ELF */
	u8 *ElfFile = malloc(ncchset->componentFilePtrs.elfSize);
	if(!ElfFile) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}
	ReadFile_64(ElfFile,ncchset->componentFilePtrs.elfSize,0,ncchset->componentFilePtrs.elf);

#ifdef DEBUG
	printf("[DEBUG] Create ELF Context\n");
#endif
	/* Create ELF Context */
	ElfContext *elf = calloc(1,sizeof(ElfContext));
	if(!elf) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		free(ElfFile); 
		return MEM_ERROR;
	}
	
	result = GetElfContext(elf,ElfFile);
	if(result) goto finish;

	/* Setting Page Size */
	elf->pageSize = GetPageSize(ncchset);

	if(!ncchset->componentFilePtrs.plainregion){
		result = ImportPlainRegionFromElf(elf,ElfFile,ncchset);
		if(result) goto finish;
	}

#ifdef DEBUG
	PrintElfContext(elf,ElfFile);
#endif

#ifdef DEBUG
	printf("[DEBUG] Create ExeFs Code\n");
#endif
	result = CreateExeFsCode(elf,ElfFile,ncchset);
	if(result) goto finish;
#ifdef DEBUG
	printf("[DEBUG] Get BSS Size\n");
#endif
	result = GetBSS_SizeFromElf(elf,ElfFile,ncchset);
	if(result) goto finish;

finish:
	if(result){
		if(result == NOT_ELF_FILE) fprintf(stderr,"[ELF ERROR] Not ELF File\n");
		else if(result == NOT_ARM_ELF) fprintf(stderr,"[ELF ERROR] Not ARM ELF\n");
		else if(result == NON_EXECUTABLE_ELF) fprintf(stderr,"[ELF ERROR] Not Executeable ELF\n");
		else if(result == NOT_FIND_BSS_SIZE) fprintf(stderr,"[ELF ERROR] BSS Size Could not be found\n");
		else if(result == NOT_FIND_CODE_SECTIONS) fprintf(stderr,"[ELF ERROR] Failed to retrieve code sections from ELF\n");
		else fprintf(stderr,"[ELF ERROR] Failed to process ELF file (%d)\n",result);
	}
#ifdef DEBUG
	printf("[DEBUG] Free Segment Header/Sections\n");
#endif
	for(int i = 0; i < elf->activeSegments; i++){
#ifdef DEBUG
	printf("[DEBUG] %d\n",i);
#endif
		free(elf->segments[i].sections);
	}
#ifdef DEBUG
	printf("[DEBUG] Free others\n");
#endif
	free(ElfFile);
	free(elf->sections);
	free(elf->programHeaders);
	free(elf->segments);
	free(elf);
	return result;	
}

int ImportPlainRegionFromFile(ncch_settings *ncchset)
{
	ncchset->sections.plainRegion.size = align(ncchset->componentFilePtrs.plainregionSize,ncchset->options.mediaSize);
	ncchset->sections.plainRegion.buffer = malloc(ncchset->sections.plainRegion.size);
	if(!ncchset->sections.plainRegion.buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	ReadFile_64(ncchset->sections.plainRegion.buffer,ncchset->componentFilePtrs.plainregionSize,0,ncchset->componentFilePtrs.plainregion);
	return 0;
}

int ImportExeFsCodeBinaryFromFile(ncch_settings *ncchset)
{
	u32 size = ncchset->componentFilePtrs.codeSize;
	u8 *buffer = malloc(size);
	if(!buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	ReadFile_64(buffer,size,0,ncchset->componentFilePtrs.code);

	ncchset->exefsSections.code.size = ncchset->componentFilePtrs.codeSize;
	ncchset->exefsSections.code.buffer = malloc(ncchset->exefsSections.code.size);
	if(!ncchset->exefsSections.code.buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	ReadFile_64(ncchset->exefsSections.code.buffer,ncchset->exefsSections.code.size,0,ncchset->componentFilePtrs.code);
	if(ncchset->options.CompressCode){
		u32 new_len;
		ncchset->exefsSections.code.buffer = BLZ_Code(buffer,size,&new_len,BLZ_NORMAL);
		ncchset->exefsSections.code.size = new_len;
		free(buffer);
	}
	else{
		ncchset->exefsSections.code.size = size;
		ncchset->exefsSections.code.buffer = buffer;
	}
	return 0;
}

u32 GetPageSize(ncch_settings *ncchset)
{
	if(ncchset->rsfSet->Option.PageSize)
		return strtoul(ncchset->rsfSet->Option.PageSize,NULL,10);
	return 0x1000;
}

u32 SizeToPage(u32 memorySize, ElfContext *elf)
{
	return align(memorySize,elf->pageSize)/elf->pageSize;
}


int GetBSS_SizeFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset)
{
	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		if(IsBss(&elf->sections[i])) {
			ncchset->codeDetails.bssSize = elf->sections[i].size;
			return 0;
		}
	}
	return NOT_FIND_BSS_SIZE;
}

int ImportPlainRegionFromElf(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset) // Doesn't work same as N makerom
{
	if(!ncchset->rsfSet->PlainRegionNum) return 0;
	u16 *Index = calloc(ncchset->rsfSet->PlainRegionNum,sizeof(u16));

	/* Getting Index Values for each section */
	for(int i = 0; i < ncchset->rsfSet->PlainRegionNum; i++){
		Index[i] = GetElfSectionIndexFromName(ncchset->rsfSet->PlainRegion[i],elf,ElfFile);
	}

	// Eliminating Duplicated Sections
	for(int i = ncchset->rsfSet->PlainRegionNum - 1; i >= 0; i--){
		for(int j = i-1; j >= 0; j--){
			if(Index[i] == Index[j]) Index[i] = 0;
		}
	}

	/* Calculating Total Size of Data */
	u64 TotalSize = 0;
	for(int i = 0; i < ncchset->rsfSet->PlainRegionNum; i++){
		TotalSize += elf->sections[Index[i]].size;
	}
	
	/* Creating Output Buffer */
	ncchset->sections.plainRegion.size = align(TotalSize,ncchset->options.mediaSize);
	ncchset->sections.plainRegion.buffer = malloc(ncchset->sections.plainRegion.size);
	if(!ncchset->sections.plainRegion.buffer) {fprintf(stderr,"[ELF ERROR] Not enough memory\n"); return MEM_ERROR;}
	memset(ncchset->sections.plainRegion.buffer,0,ncchset->sections.plainRegion.size);

	/* Storing Sections */
	u64 pos = 0;
	for(int i = 0; i < ncchset->rsfSet->PlainRegionNum; i++){
		memcpy((ncchset->sections.plainRegion.buffer+pos),elf->sections[Index[i]].ptr,elf->sections[Index[i]].size);
		pos += elf->sections[Index[i]].size;
	}
	return 0;
}

int CreateExeFsCode(ElfContext *elf, u8 *ElfFile, ncch_settings *ncchset)
{
	/* Getting Code Segments */
	CodeSegment Text;
	memset(&Text,0,sizeof(CodeSegment));
	CodeSegment RO;
	memset(&RO,0,sizeof(CodeSegment));
	CodeSegment Data;
	memset(&Data,0,sizeof(CodeSegment));

	int result = CreateCodeSegmentFromElf(&Text,elf,ElfFile,ncchset->rsfSet->ExeFs.Text,ncchset->rsfSet->ExeFs.TextNum);
	if(result) return result;
	result = CreateCodeSegmentFromElf(&RO,elf,ElfFile,ncchset->rsfSet->ExeFs.ReadOnly,ncchset->rsfSet->ExeFs.ReadOnlyNum);
	if(result) return result;
	result = CreateCodeSegmentFromElf(&Data,elf,ElfFile,ncchset->rsfSet->ExeFs.ReadWrite,ncchset->rsfSet->ExeFs.ReadWriteNum);
	if(result) return result;

	/* Allocating Buffer for ExeFs Code */
	u32 size = (Text.maxPageNum + RO.maxPageNum + Data.maxPageNum)*elf->pageSize;
	u8 *code = malloc(size);

	/* Writing Code into Buffer */
	u8 *TextPos = (code + 0);
	u8 *ROPos = (code + Text.maxPageNum*elf->pageSize);
	u8 *DataPos = (code + (Text.maxPageNum + RO.maxPageNum)*elf->pageSize);
	if(Text.size) memcpy(TextPos,Text.data,Text.size);
	if(RO.size) memcpy(ROPos,RO.data,RO.size);
	if(Data.size) memcpy(DataPos,Data.data,Data.size);


	/* Compressing If needed */
	if(ncchset->options.CompressCode){
		u32 new_len;
		ncchset->exefsSections.code.buffer = BLZ_Code(code,size,&new_len,BLZ_NORMAL);
		ncchset->exefsSections.code.size = new_len;
		free(code);
	}
	else{
		ncchset->exefsSections.code.size = size;
		ncchset->exefsSections.code.buffer = code;
	}

	/* Setting CodeSegment Data and freeing original buffers */
	ncchset->codeDetails.textAddress = Text.address;
	ncchset->codeDetails.textMaxPages = Text.maxPageNum;
	ncchset->codeDetails.textSize = Text.size;
	if(Text.size) free(Text.data);

	ncchset->codeDetails.roAddress = RO.address;
	ncchset->codeDetails.roMaxPages = RO.maxPageNum;
	ncchset->codeDetails.roSize = RO.size;
	if(RO.size) free(RO.data);

	ncchset->codeDetails.rwAddress = Data.address;
	ncchset->codeDetails.rwMaxPages = Data.maxPageNum;
	ncchset->codeDetails.rwSize = Data.size;
	if(Data.size) free(Data.data);

	/* Return */
	return 0;
}

int CreateCodeSegmentFromElf(CodeSegment *out, ElfContext *elf, u8 *ElfFile, char **Names, u32 NameNum)
{
	u16 ContinuousSegmentNum = 0;
	memset(out,0,sizeof(CodeSegment));
	ElfSegment **ContinuousSegments = GetContinuousSegments(&ContinuousSegmentNum,elf,Names,NameNum);
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
			ElfSectionEntry *Section = &ContinuousSegments[i]->sections[j];
			if (!IsBss(Section)){				
				u8 *pos = (out->data + (Section->address - ContinuousSegments[i]->vAddr));
				memcpy(pos,Section->ptr,Section->size);
				//size += Section->size;
			}

			//else if (j == (ContinuousSegments[i]->sectionNum-1))
				//memorySize -= Section->size;
			//'else
				//size += Section->size;
		}
	}

	free(ContinuousSegments);
	return 0;
}


ElfSegment** GetContinuousSegments(u16 *ContinuousSegmentNum, ElfContext *elf, char **Names, u32 NameNum)
{
	u16 SegmentNum = 0;
	ElfSegment **Segments = GetSegments(&SegmentNum, elf, Names, NameNum);
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


ElfSegment** GetSegments(u16 *SegmentNum, ElfContext *elf, char **Names, u32 NameNum)
{
	if (Names == NULL)
	{
		return NULL;
	}

	ElfSegment **Segments = calloc(NameNum,sizeof(ElfSegment*)); 
	*SegmentNum = 0; // There can be a max of NameNum Segments, however, they might not all exist
	for (int i = 0; i < NameNum; i++){
		for(int j = 0; j < elf->activeSegments; j++){
			if(strcmp(Names[i],elf->segments[j].name) == 0){ // If there is a match, store Segment data pointer & increment index
				Segments[*SegmentNum] = &elf->segments[j];
				*SegmentNum = *SegmentNum + 1;
			}
		}
	}
	return Segments;
}

// ELF Functions

int GetElfContext(ElfContext *elf, u8 *ElfFile)
{
	if(u8_to_u32(ElfFile,BE) != ELF_MAGIC) return NOT_ELF_FILE;
	
	elf->Is64bit = (ElfFile[4] == elf_64_bit);
	elf->IsLittleEndian = (ElfFile[5] == elf_little_endian);
	
	int result = ReadElfHdr(elf,ElfFile);
	if(result) return result;

	result = GetElfSectionEntries(elf,ElfFile);
	if(result) return result;

	result = GetElfProgramEntries(elf,ElfFile);
	if(result) return result;

	result = CreateElfSegments(elf,ElfFile);
	if(result) return result;

	return 0;
}

int GetElfSectionEntries(ElfContext *elf, u8 *ElfFile)
{
	elf->sections = calloc(elf->sectionTableEntryCount,sizeof(ElfSectionEntry));
	if(!elf->sections) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		elf->sections[i].name = GetELFSectionEntryName(i,elf,ElfFile);
		elf->sections[i].type = GetELFSectionEntryType(i,elf,ElfFile);
		elf->sections[i].flags = GetELFSectionEntryFlags(i,elf,ElfFile);
		elf->sections[i].ptr = GetELFSectionEntry(i,elf,ElfFile);
		elf->sections[i].offsetInFile = GetELFSectionEntryFileOffset(i,elf,ElfFile);
		elf->sections[i].size = GetELFSectionEntrySize(i,elf,ElfFile);
		elf->sections[i].address = GetELFSectionEntryAddress(i,elf,ElfFile);
		elf->sections[i].alignment = GetELFSectionEntryAlignment(i,elf,ElfFile);
	}
	return 0;
}

int GetElfProgramEntries(ElfContext *elf, u8 *ElfFile)
{
	elf->programHeaders = calloc(elf->programTableEntryCount,sizeof(ElfProgramEntry));
	if(!elf->programHeaders) {
		fprintf(stderr,"[ELF ERROR] Not enough memory\n"); 
		return MEM_ERROR;
	}

	for(int i = 0; i < elf->programTableEntryCount; i++){
		elf->programHeaders[i].type = GetELFProgramEntryType(i,elf,ElfFile);
		elf->programHeaders[i].flags = GetELFProgramEntryFlags(i,elf,ElfFile);
		elf->programHeaders[i].ptr = GetELFProgramEntry(i,elf,ElfFile);
		elf->programHeaders[i].offsetInFile = GetELFProgramEntryFileOffset(i,elf,ElfFile);
		elf->programHeaders[i].sizeInFile = GetELFProgramEntryFileSize(i,elf,ElfFile);
		elf->programHeaders[i].physicalAddress = GetELFProgramEntryPAddress(i,elf,ElfFile);
		elf->programHeaders[i].virtualAddress = GetELFProgramEntryVAddress(i,elf,ElfFile);
		elf->programHeaders[i].sizeInMemory = GetELFProgramEntryMemorySize(i,elf,ElfFile);
		elf->programHeaders[i].alignment = GetELFProgramEntryAlignment(i,elf,ElfFile);
	}

	return 0;
}

#ifdef DEBUG
void PrintElfContext(ElfContext *elf, u8 *ElfFile)
{
	printf("[+] Basic Details\n");
	printf(" Class:  %s\n",elf->Is64bit ? "64-bit" : "32-bit");
	printf(" Data:   %s\n",elf->IsLittleEndian ? "Little Endian" : "Big Endian");
	printf("\n[+] Program Table Data\n");
	printf(" Offset: 0x%lx\n",elf->programTableOffset);
	printf(" Size:   0x%x\n",elf->programTableEntrySize);
	printf(" Count:  0x%x\n",elf->programTableEntryCount);
	printf("\n[+] Section Table Data\n");
	printf(" Offset: 0x%lx\n",elf->sectionTableOffset);
	printf(" Size:   0x%x\n",elf->sectionTableEntrySize);
	printf(" Count:  0x%x\n",elf->sectionTableEntryCount);
	printf(" Lable Index: 0x%x\n",elf->sectionHeaderNameEntryIndex);
	for(int i = 0; i < elf->activeSegments; i++){
		printf(" Segment [%d][%s]\n",i,elf->segments[i].name);
		printf(" > Size :     0x%x\n",elf->segments[i].header->sizeInFile);
		printf(" > Address :  0x%x\n",elf->segments[i].vAddr);
		printf(" > Sections : %d\n",elf->segments[i].sectionNum);  
		for(int j = 0; j < elf->segments[i].sectionNum; j++){
			printf("    > Section [%d][%s]\n",j,elf->segments[i].sections[j].name);
		}
		
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
#endif

int ReadElfHdr(ElfContext *elf, u8 *ElfFile)
{
	if(elf->Is64bit){
		elf_64_hdr *hdr = (elf_64_hdr*)ElfFile;

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
		elf_32_hdr *hdr = (elf_32_hdr*)ElfFile;

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

u8* GetELFSectionHeader(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return NULL;

	return (ElfFile + elf->sectionTableOffset + elf->sectionTableEntrySize*Index);
}

u8* GetELFSectionEntry(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return NULL;

	return (u8*) (ElfFile + GetELFSectionEntryFileOffset(Index,elf,ElfFile));
}

char* GetELFSectionEntryName(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	u64 NameIndex = 0;
	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		NameIndex = u8_to_u64(shdr->sh_name,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		NameIndex = u8_to_u32(shdr->sh_name,elf->IsLittleEndian);
	}

	u8 *NameTable = GetELFSectionEntry(elf->sectionHeaderNameEntryIndex,elf,ElfFile);
	
	return (char*)(NameTable+NameIndex);
}

u64 GetELFSectionEntryType(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_type,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_type,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_flags,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_flags,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryAddress(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_addr,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_addr,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_offset,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_offset,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntrySize(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_size,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_size,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFSectionEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->sectionTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_shdr *shdr = (elf_64_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u64(shdr->sh_addralign,elf->IsLittleEndian);
	}
	else{
		elf_32_shdr *shdr = (elf_32_shdr*)GetELFSectionHeader(Index,elf,ElfFile);
		return u8_to_u32(shdr->sh_addralign,elf->IsLittleEndian);
	}

	return 0;
}


u16 GetElfSectionIndexFromName(char *Name, ElfContext *elf, u8 *ElfFile)
{
	for(int i = 0; i < elf->sectionTableEntryCount; i++){
		if(strcmp(Name,elf->sections[i].name) == 0) return i;
	}
	return 0; // Assuming 0 is always empty
}

bool IsBss(ElfSectionEntry *Section)
{
	if(Section->type == 8 && Section->flags == 3)
		return true;
	return false;
}

bool IsData(ElfSectionEntry *Section)
{
	if(Section->type == 1 && Section->flags == 3)
		return true;
	return false;
}

bool IsRO(ElfSectionEntry *Section)
{
	if(Section->type == 1 && Section->flags == 2)
		return true;
	return false;
}

bool IsText(ElfSectionEntry *Section)
{
	if(Section->type == 1 && Section->flags == 6)
		return true;
	return false;
}

/* ProgramHeader Functions */

u8* GetELFProgramHeader(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return NULL;

	return (ElfFile + elf->programTableOffset + elf->programTableEntrySize*Index);
}

u8* GetELFProgramEntry(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return NULL;

	return (u8*) (ElfFile + GetELFProgramEntryFileOffset(Index,elf,ElfFile));

	return NULL;
}

u64 GetELFProgramEntryType(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_type,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_type,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFlags(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_flags,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_flags,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFileSize(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_filesz,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_filesz,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryFileOffset(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_offset,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_offset,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryMemorySize(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_memsz,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_memsz,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryVAddress(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_vaddr,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_vaddr,elf->IsLittleEndian);
	}

	return 0;
}

u64 GetELFProgramEntryPAddress(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_paddr,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_paddr,elf->IsLittleEndian);
	}

	return 0;
}


u64 GetELFProgramEntryAlignment(u16 Index, ElfContext *elf, u8 *ElfFile)
{
	if(Index >= elf->programTableEntryCount) return 0;

	if(elf->Is64bit){
		elf_64_phdr *phdr = (elf_64_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u64(phdr->p_align,elf->IsLittleEndian);
	}
	else{
		elf_32_phdr *phdr = (elf_32_phdr*)GetELFProgramHeader(Index,elf,ElfFile);
		return u8_to_u32(phdr->p_align,elf->IsLittleEndian);
	}

	return 0;
}


int CreateElfSegments(ElfContext *elf, u8 *ElfFile)
{
	int num = 0;
	// Interate through Each Program Header
	elf->activeSegments = 0;
	elf->segments = calloc(elf->programTableEntryCount,sizeof(ElfSegment));
	ElfSegment *segment = malloc(sizeof(ElfSegment)); // Temporary Buffer
	for (int i = 0; i < elf->programTableEntryCount; i++){
		if (elf->programHeaders[i].sizeInMemory != 0 && elf->programHeaders[i].type == 1){
			memset(segment,0,sizeof(ElfSegment));

			bool foundFirstSection = false;
			u32 size = 0;
			u32 vAddr = elf->programHeaders[i].virtualAddress;
 			u32 memorySize = elf->programHeaders[i].sizeInMemory;
			//printf("Segment Size in memory: 0x%x\n",memorySize);
			//printf("Segment Alignment:      0x%x\n",elf->programHeaders[i].alignment);
			
			u16 SectionInfoCapacity = 10;
			segment->sectionNum = 0;
			segment->sections = calloc(SectionInfoCapacity,sizeof(ElfSectionEntry));

			// Itterate Through Section Headers
			for (int j = num; j < elf->sectionTableEntryCount; j++){
				if (!foundFirstSection){
					if (elf->sections[j].address != vAddr)
                        continue;
                    
					while (j < (int)elf->sections[j].size && elf->sections[j].address == vAddr && !IsIgnoreSection(elf->sections[j]))
                        j++;

					j--;

					foundFirstSection = true;
					segment->vAddr = elf->sections[j].address;
					segment->name = elf->sections[j].name;
                }

				if(segment->sectionNum < SectionInfoCapacity)
					memcpy(&segment->sections[segment->sectionNum],&elf->sections[j],sizeof(ElfSectionEntry));
				else{
					SectionInfoCapacity = SectionInfoCapacity*2;
					ElfSectionEntry *tmp = calloc(SectionInfoCapacity,sizeof(ElfSectionEntry));
					for(int k = 0; k < segment->sectionNum; k++)
						memcpy(&tmp[k],&segment->sections[k],sizeof(ElfSectionEntry));
					free(segment->sections);
					segment->sections = tmp;
					memcpy(&segment->sections[segment->sectionNum],&elf->sections[j],sizeof(ElfSectionEntry));
				}
				segment->sectionNum++;

				if(size == 0)
					size += elf->sections[j].size;
				else{
					u32 padding = elf->sections[j].address - (elf->sections[j-1].address + elf->sections[j-1].size);
					size += padding + elf->sections[j].size;
				}
					
				//printf("Section Name: %s",elf->sections[j].name);
				//printf(" 0x%lx",elf->sections[j].size);
				//printf(" (Total Size: 0x%x)\n",size);

                if (size == memorySize)
					break;

				if (size > memorySize){
					fprintf(stderr,"[ELF ERROR] Too large section size.\n Segment size = 0x%x\n Section Size = 0x%x\n", memorySize, size);
					return ELF_SEGMENT_SECTION_SIZE_MISMATCH;
				}
            }
			if(segment->sectionNum){
				segment->header = &elf->programHeaders[i];
				memcpy(&elf->segments[elf->activeSegments],segment,sizeof(ElfSegment));
				elf->activeSegments++;
			}
			else{
				free(segment->sections);
				free(segment);
				fprintf(stderr,"[ELF ERROR] Program Header Has no corresponding Sections, ELF Cannot be proccessed\n");
				return ELF_SEGMENTS_NOT_FOUND;
			}
		}
	}

	free(segment);
	return 0;
}

bool IsIgnoreSection(ElfSectionEntry info)
{
	if (info.address)
		return false;

	if (info.type != 1 && info.type != 0)
		return true;

	char IgnoreSectionNames[7][20] = { ".debug_abbrev", ".debug_frame", ".debug_info", ".debug_line", ".debug_loc", ".debug_pubnames", ".comment" };
	for (int i = 0; i < 7; i++){
		if (strcmp(IgnoreSectionNames[i],info.name) == 0)
			return true;
	}
	return false;

}
