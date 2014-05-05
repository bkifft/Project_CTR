#include "lib.h"
#include "ncch.h"
#include "titleid.h"

u32 SetPIDCategoryFromName(char *Category);
u32 SetPIDCategoryFromFlags(char **CategoryFlags, u32 FlagNum);
u32 SetPIDCategoryFromFlag(u32 Category, u32 Flag, char *FlagName);
u32 SetPIDUniqueId(char *UniqueIdStr);
u16 SetTitleVariation(u16 Category, rsf_settings *yaml_set);

u64 ConvertTwlIdToCtrId(u64 pgid)
{
	return 0x0004800000000000 | (pgid & 0x00007FFFFFFFFFFF);
}

int GetProgramID(u64 *dest, rsf_settings *yaml, bool IsForExheader)
{
	if(yaml->TitleInfo.Category && yaml->TitleInfo.CategoryFlags){
		fprintf(stderr,"[ID ERROR] Can not set \"Cateory\" and \"CategoryFlags\" at the same time.\n");
		return PID_BAD_YAML_SET;
	}
	u16 Type = 0x0004;
	u32 m_Category = 0;
	u32 UniqueId = 0;
	u16 m_Variation = 0;

	// Getting Category
	if(yaml->TitleInfo.Category) 
		m_Category = SetPIDCategoryFromName(yaml->TitleInfo.Category);
	else if(yaml->TitleInfo.CategoryFlags) 
		m_Category = SetPIDCategoryFromFlags(yaml->TitleInfo.CategoryFlags,yaml->TitleInfo.CategoryFlagsNum);
	if(IsForExheader && yaml->TitleInfo.TargetCategory)
		m_Category = SetPIDCategoryFromName(yaml->TitleInfo.TargetCategory);
	if(m_Category == PID_INVALID_CATEGORY) // Error occured
		return PID_BAD_YAML_SET;

	// Getting UniqueId
	if(yaml->TitleInfo.UniqueId) UniqueId = SetPIDUniqueId(yaml->TitleInfo.UniqueId);
	else{
		fprintf(stderr,"[ID ERROR] ParameterNotFound: \"TitleInfo/UniqueId\"\n");
		return PID_BAD_YAML_SET;
	}

	m_Variation = SetTitleVariation(m_Category,yaml);
	if(m_Variation == PID_INVALID_VARIATION) // Error occured
		return PID_BAD_YAML_SET;

	u16 Category = (u16)m_Category;
	u8 Variation = (u8)m_Variation;

	u64 ProgramID = 0;
	ProgramID |= (u64)Variation<<0;
	ProgramID |= (u64)UniqueId<<8;
	ProgramID |= (u64)Category<<32;
	ProgramID |= (u64)Type<<48;

	*dest = ProgramID;

	return 0;
}

int GetUniqueID(u32 *dest, rsf_settings *yaml)
{
	if(yaml->TitleInfo.UniqueId) *dest = 0xffffff & SetPIDUniqueId(yaml->TitleInfo.UniqueId);
	else{
		fprintf(stderr,"[ID ERROR] ParameterNotFound: \"TitleInfo/UniqueId\"\n");
		return PID_BAD_YAML_SET;
	}
	return 0;
}

u32 SetPIDCategoryFromName(char *Category)
{
	if(strcmp(Category,"Application") == 0) return PROGRAM_ID_CATEGORY_APPLICATION;
	else if(strcmp(Category,"SystemApplication") == 0) return PROGRAM_ID_CATEGORY_SYSTEM_APPLICATION;
	else if(strcmp(Category,"Applet") == 0) return PROGRAM_ID_CATEGORY_APPLET;
	else if(strcmp(Category,"Firmware") == 0) return PROGRAM_ID_CATEGORY_FIRMWARE;
	else if(strcmp(Category,"Base") == 0) return PROGRAM_ID_CATEGORY_BASE;
	else if(strcmp(Category,"DlpChild") == 0) return PROGRAM_ID_CATEGORY_DLP_CHILD;
	else if(strcmp(Category,"Demo") == 0) return PROGRAM_ID_CATEGORY_DEMO;
	else if(strcmp(Category,"Contents") == 0) return PROGRAM_ID_CATEGORY_CONTENTS;
	else if(strcmp(Category,"SystemContents") == 0) return PROGRAM_ID_CATEGORY_SYSTEM_CONTENT;
	else if(strcmp(Category,"SharedContents") == 0) return PROGRAM_ID_CATEGORY_SHARED_CONTENT;
	else if(strcmp(Category,"AddOnContents") == 0) return PROGRAM_ID_CATEGORY_ADD_ON_CONTENTS;
	else if(strcmp(Category,"Patch") == 0) return PROGRAM_ID_CATEGORY_PATCH;
	else if(strcmp(Category,"AutoUpdateContents") == 0) return PROGRAM_ID_CATEGORY_AUTO_UPDATE_CONTENT;
	else {
		fprintf(stderr,"[ID ERROR] Invalid Category: \"%s\"\n",Category);
		return PID_INVALID_CATEGORY;
	}
}

u32 SetPIDCategoryFromFlags(char **CategoryFlags, u32 FlagNum)
{
	u32 Category = 0;
	for(u32 i = 0; i < FlagNum; i++){
		if(strcmp(CategoryFlags[i],"Normal") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_NORMAL,"Normal");
		else if(strcmp(CategoryFlags[i],"DlpChild") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_DLP_CHILD,"DlpChild");
		else if(strcmp(CategoryFlags[i],"Demo") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_DEMO,"Demo");
		else if(strcmp(CategoryFlags[i],"Contents") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_CONTENTS,"Contents");
		else if(strcmp(CategoryFlags[i],"AddOnContents") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_ADD_ON_CONTENTS,"AddOnContents");
		else if(strcmp(CategoryFlags[i],"Patch") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_PATCH,"Patch");
		else if(strcmp(CategoryFlags[i],"CannotExecution") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_CANNOT_EXECUTION,"CannotExecution");
		else if(strcmp(CategoryFlags[i],"System") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_SYSTEM,"System");
		else if(strcmp(CategoryFlags[i],"RequireBatchUpdate") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_REQUIRE_BATCH_UPDATE,"RequireBatchUpdate");
		else if(strcmp(CategoryFlags[i],"NotRequireUserApproval") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_NOT_REQUIRE_USER_APPROVAL,"NotRequireUserApproval");
		else if(strcmp(CategoryFlags[i],"NotRequireRightForMount") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_NOT_REQUIRE_RIGHT_FOR_MOUNT,"NotRequireRightForMount");
		else if(strcmp(CategoryFlags[i],"CanSkipConvertJumpId") == 0)
			Category = SetPIDCategoryFromFlag(Category,PROGRAM_ID_CATEGORY_FLAG_CAN_SKIP_CONVERT_JUMP_ID,"CanSkipConvertJumpId");
		
		else {
			fprintf(stderr,"[ID ERROR] Invalid CategoryFlag: \"%s\"\n",CategoryFlags[i]);
			return PID_INVALID_CATEGORY;
		}

		if(Category == PID_INVALID_CATEGORY) return PID_INVALID_CATEGORY;
	}
	return Category;
}

u32 SetPIDCategoryFromFlag(u32 Category, u32 Flag, char *FlagName)
{
	if(!Flag) return Category;
	if((Category & Flag) == Flag){
		fprintf(stderr,"[ID ERROR] Failed to set \"%s\" for category. CategoryFlag was already set.\n",FlagName);
		return PID_INVALID_CATEGORY;
	}
	return Category |= Flag;
}

u32 SetPIDUniqueId(char *UniqueIdStr)
{
	return 0xffffff & strtoull(UniqueIdStr,NULL,0);
}

u16 SetTitleVariation(u16 Category, rsf_settings *yaml_set)
{
	if(IsDemo(Category)){
		if(yaml_set->TitleInfo.DemoIndex){
			u16 DemoIndex = strtol(yaml_set->TitleInfo.DemoIndex,NULL,10);
			if(DemoIndex > 255 || DemoIndex == 0){
				fprintf(stderr,"[ID ERROR] Invalid demo index \"%d\"\n",DemoIndex);
				return PID_INVALID_VARIATION;
			}
			return DemoIndex;
		}
		else{
			fprintf(stderr,"[ID ERROR] ParameterNotFound: \"TitleInfo/DemoIndex\"\n");
			return PID_INVALID_VARIATION;
		}
	}
	
	else if(IsDlpChild(Category)){
		if(yaml_set->TitleInfo.ChildIndex){
			u16 ChildIndex = strtol(yaml_set->TitleInfo.ChildIndex,NULL,10);
			if(ChildIndex > 255){
				fprintf(stderr,"[ID ERROR] Invalid child index \"%d\"\n",ChildIndex);
				return PID_INVALID_VARIATION;
			}
			return ChildIndex;
		}
		else
			return 0;
	}
	else if(IsAddOnContent(Category)){
		if(yaml_set->TitleInfo.Variation){ // Might Rename to DataTitleIndex
			u16 DataTitleIndex = strtol(yaml_set->TitleInfo.Variation,NULL,10);
			if(DataTitleIndex > 255){
				fprintf(stderr,"[ID ERROR] Invalid variation \"%d\"\n",DataTitleIndex);
				return PID_INVALID_VARIATION;
			}
			return DataTitleIndex;
		}
		else
			return 0;
	}
	else if(IsContents(Category)){
		if(yaml_set->TitleInfo.ContentsIndex){
			u16 ContentsIndex = strtol(yaml_set->TitleInfo.ContentsIndex,NULL,10);
			if(ContentsIndex > 255){
				fprintf(stderr,"[ID ERROR] Invalid content index \"%d\"\n",ContentsIndex);
				return PID_INVALID_VARIATION;
			}
			return ContentsIndex;
		}
		else
			return 0;
	}
	else{
		if(yaml_set->TitleInfo.Version){
			u16 Version = strtol(yaml_set->TitleInfo.Version,NULL,10);
			if(Version > 255){
				fprintf(stderr,"[ID ERROR] Invalid Version \"%d\"\n",Version);
				return PID_INVALID_VARIATION;
			}
			return Version;
		}
		else
			return 0;
	}
	return PID_INVALID_VARIATION;
}

bool IsDemo(u16 Category)
{
	return Category == PROGRAM_ID_CATEGORY_DEMO;
}

bool IsSystem(u16 Category)
{
	return (Category & PROGRAM_ID_CATEGORY_FLAG_SYSTEM) == PROGRAM_ID_CATEGORY_FLAG_SYSTEM;
}

bool IsDlpChild(u16 Category)
{
	return Category == PROGRAM_ID_CATEGORY_DLP_CHILD;
}

bool IsPatch(u16 Category)
{
	return Category == PROGRAM_ID_CATEGORY_PATCH;
}

bool IsContents(u16 Category)
{
	return (Category & PROGRAM_ID_CATEGORY_FLAG_CONTENTS) == PROGRAM_ID_CATEGORY_FLAG_CONTENTS;
}

bool IsAddOnContent(u16 Category)
{
	return Category == PROGRAM_ID_CATEGORY_ADD_ON_CONTENTS;
}