#include "lib.h"
#include "yamlsettings.h"

void EvaluateRSF(rsf_settings *rsf, ctr_yaml_context *ctx)
{
	u32 start_level = ctx->Level-1;
	
	/* Check Group Key for Validity */
	CHECK_Group:
	//printf("RSF Found: %s\n",GetYamlString(ctx));
	if(cmpYamlValue("Option",ctx)) {FinishEvent(ctx); GET_Option(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("AccessControlInfo",ctx)) {FinishEvent(ctx); GET_AccessControlInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("SystemControlInfo",ctx)) {FinishEvent(ctx); GET_SystemControlInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("BasicInfo",ctx)) {FinishEvent(ctx); GET_BasicInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("Rom",ctx)) {FinishEvent(ctx); GET_Rom(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("ExeFs",ctx)) {FinishEvent(ctx); GET_ExeFs(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("PlainRegion",ctx)) {FinishEvent(ctx); GET_PlainRegion(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("TitleInfo",ctx)) {FinishEvent(ctx); GET_TitleInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("CardInfo",ctx)) {FinishEvent(ctx); GET_CardInfo(ctx,rsf); goto GET_NextGroup;}
	else if(cmpYamlValue("CommonHeaderKey",ctx)) {FinishEvent(ctx); GET_CommonHeaderKey(ctx,rsf); goto GET_NextGroup;}

	// If not recognised escape:
	fprintf(stderr,"[RSF ERROR] Unrecognised Key: '%s'\n",GetYamlString(ctx)); 
	FinishEvent(ctx); 
	ctx->error = YAML_BAD_GROUP_HEADER; 
	return;
		
	/* Get Next Group and call check */
	GET_NextGroup:
	// If done return
	if(ctx->done || ctx->error) return;
	
	// Recursively getting events until done or has value
	if(!ctx->event.type) GetEvent(ctx);
	if(ctx->Level <= start_level) return; // No longer in RSF Domain
	while(!EventIsScalar(ctx)){
		if(ctx->done || ctx->error) return;
		if(ctx->Level <= start_level) return; // No longer in RSF Domain
		FinishEvent(ctx);
		GetEvent(ctx);		
	}
	goto CHECK_Group;
}

void GET_Option(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("AllowUnalignedSection",ctx)) rsf->Option.AllowUnalignedSection = SetBoolYAMLValue("AllowUnalignedSection",ctx);
		if(cmpYamlValue("MediaFootPadding",ctx)) rsf->Option.MediaFootPadding = SetBoolYAMLValue("MediaFootPadding",ctx);
		//else if(cmpYamlValue("NoPadding",ctx)) rsf->Option.NoPadding = SetBoolYAMLValue("NoPadding",ctx);
		else if(cmpYamlValue("EnableCrypt",ctx)) rsf->Option.EnableCrypt = SetBoolYAMLValue("EnableCrypt",ctx);
		else if(cmpYamlValue("EnableCompress",ctx)) rsf->Option.EnableCompress = SetBoolYAMLValue("EnableCompress",ctx);
		else if(cmpYamlValue("FreeProductCode",ctx)) rsf->Option.FreeProductCode = SetBoolYAMLValue("FreeProductCode",ctx);
		else if(cmpYamlValue("UseOnSD",ctx)) rsf->Option.UseOnSD = SetBoolYAMLValue("UseOnSD",ctx);
		else if(cmpYamlValue("PageSize",ctx)) SetSimpleYAMLValue(&rsf->Option.PageSize,"PageSize",ctx,0);
		//else if(cmpYamlValue("AppendSystemCall",ctx)) rsf->Option.AppendSystemCallNum = SetYAMLSequence(&rsf->Option.AppendSystemCall,"AppendSystemCall",ctx);
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_AccessControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("DisableDebug",ctx)) rsf->AccessControlInfo.DisableDebug = SetBoolYAMLValue("DisableDebug",ctx);
		else if(cmpYamlValue("EnableForceDebug",ctx)) rsf->AccessControlInfo.EnableForceDebug = SetBoolYAMLValue("EnableForceDebug",ctx);
		else if(cmpYamlValue("CanWriteSharedPage",ctx)) rsf->AccessControlInfo.CanWriteSharedPage = SetBoolYAMLValue("CanWriteSharedPage",ctx);
		else if(cmpYamlValue("CanUsePrivilegedPriority",ctx)) rsf->AccessControlInfo.CanUsePrivilegedPriority = SetBoolYAMLValue("CanUsePrivilegedPriority",ctx);
		else if(cmpYamlValue("CanUseNonAlphabetAndNumber",ctx)) rsf->AccessControlInfo.CanUseNonAlphabetAndNumber = SetBoolYAMLValue("CanUseNonAlphabetAndNumber",ctx);
		else if(cmpYamlValue("PermitMainFunctionArgument",ctx)) rsf->AccessControlInfo.PermitMainFunctionArgument = SetBoolYAMLValue("PermitMainFunctionArgument",ctx);
		else if(cmpYamlValue("CanShareDeviceMemory",ctx)) rsf->AccessControlInfo.CanShareDeviceMemory = SetBoolYAMLValue("CanShareDeviceMemory",ctx);
		else if(cmpYamlValue("UseOtherVariationSaveData",ctx)) rsf->AccessControlInfo.UseOtherVariationSaveData = SetBoolYAMLValue("UseOtherVariationSaveData",ctx);
		else if(cmpYamlValue("UseExtSaveData",ctx)) rsf->AccessControlInfo.UseExtSaveData = SetBoolYAMLValue("UseExtSaveData",ctx);
		else if(cmpYamlValue("UseExtendedSaveDataAccessControl",ctx)) rsf->AccessControlInfo.UseExtendedSaveDataAccessControl = SetBoolYAMLValue("UseExtendedSaveDataAccessControl",ctx);
		else if(cmpYamlValue("RunnableOnSleep",ctx)) rsf->AccessControlInfo.RunnableOnSleep = SetBoolYAMLValue("RunnableOnSleep",ctx);
		else if(cmpYamlValue("SpecialMemoryArrange",ctx)) rsf->AccessControlInfo.SpecialMemoryArrange = SetBoolYAMLValue("SpecialMemoryArrange",ctx);
		
		
		//else if(cmpYamlValue("ProgramId",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ProgramId,"ProgramId",ctx,0); 
		else if(cmpYamlValue("IdealProcessor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.IdealProcessor,"IdealProcessor",ctx,0); 
		else if(cmpYamlValue("Priority",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.Priority,"Priority",ctx,0); 
		else if(cmpYamlValue("MemoryType",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.MemoryType,"MemoryType",ctx,0); 
		else if(cmpYamlValue("SystemMode",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemMode,"SystemMode",ctx,0); 
		else if(cmpYamlValue("CoreVersion",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.CoreVersion,"CoreVersion",ctx,0); 
		else if(cmpYamlValue("HandleTableSize",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.HandleTableSize,"HandleTableSize",ctx,0); 
		else if(cmpYamlValue("SystemSaveDataId1",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemSaveDataId1,"SystemSaveDataId1",ctx,0); 
		else if(cmpYamlValue("SystemSaveDataId2",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.SystemSaveDataId2,"SystemSaveDataId2",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId1",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId1,"OtherUserSaveDataId1",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId2",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId2,"OtherUserSaveDataId2",ctx,0); 
		else if(cmpYamlValue("OtherUserSaveDataId3",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.OtherUserSaveDataId3,"OtherUserSaveDataId3",ctx,0); 
		else if(cmpYamlValue("ExtSaveDataId",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ExtSaveDataId,"ExtSaveDataId",ctx,0); 
		else if(cmpYamlValue("AffinityMask",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.AffinityMask,"AffinityMask",ctx,0); 
		else if(cmpYamlValue("DescVersion",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.DescVersion,"DescVersion",ctx,0); 
		//else if(cmpYamlValue("CryptoKey",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.CryptoKey,"CryptoKey",ctx,0); 
		else if(cmpYamlValue("ResourceLimitCategory",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ResourceLimitCategory,"ResourceLimitCategory",ctx,0); 		
		else if(cmpYamlValue("ReleaseKernelMajor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ReleaseKernelMajor,"ReleaseKernelMajor",ctx,0);
		else if(cmpYamlValue("ReleaseKernelMinor",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.ReleaseKernelMinor,"ReleaseKernelMinor",ctx,0); 
		else if(cmpYamlValue("MaxCpu",ctx)) SetSimpleYAMLValue(&rsf->AccessControlInfo.MaxCpu,"MaxCpu",ctx,0); 

		
		else if(cmpYamlValue("MemoryMapping",ctx)) rsf->AccessControlInfo.MemoryMappingNum = SetYAMLSequence(&rsf->AccessControlInfo.MemoryMapping,"MemoryMapping",ctx);
		else if(cmpYamlValue("IORegisterMapping",ctx)) rsf->AccessControlInfo.IORegisterMappingNum = SetYAMLSequence(&rsf->AccessControlInfo.IORegisterMapping,"IORegisterMapping",ctx);
		else if(cmpYamlValue("FileSystemAccess",ctx)) rsf->AccessControlInfo.FileSystemAccessNum = SetYAMLSequence(&rsf->AccessControlInfo.FileSystemAccess,"FileSystemAccess",ctx);
		else if(cmpYamlValue("IoAccessControl",ctx)) rsf->AccessControlInfo.IoAccessControlNum = SetYAMLSequence(&rsf->AccessControlInfo.IoAccessControl,"IoAccessControl",ctx);
		else if(cmpYamlValue("InterruptNumbers",ctx)) rsf->AccessControlInfo.InterruptNumbersNum = SetYAMLSequence(&rsf->AccessControlInfo.InterruptNumbers,"InterruptNumbers",ctx);
		else if(cmpYamlValue("SystemCallAccess",ctx)) rsf->AccessControlInfo.SystemCallAccessNum = SetYAMLSequenceFromMapping(&rsf->AccessControlInfo.SystemCallAccess,"SystemCallAccess",ctx,false);
		else if(cmpYamlValue("ServiceAccessControl",ctx)) rsf->AccessControlInfo.ServiceAccessControlNum = SetYAMLSequence(&rsf->AccessControlInfo.ServiceAccessControl,"ServiceAccessControl",ctx);
		//else if(cmpYamlValue("StorageId",ctx)) rsf->AccessControlInfo.StorageIdNum = SetYAMLSequence(&rsf->AccessControlInfo.StorageId,"StorageId",ctx);
		else if(cmpYamlValue("AccessibleSaveDataIds",ctx)) rsf->AccessControlInfo.AccessibleSaveDataIdsNum = SetYAMLSequence(&rsf->AccessControlInfo.AccessibleSaveDataIds,"AccessibleSaveDataIds",ctx);

		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_SystemControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("AppType",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.AppType,"AppType",ctx,0);
		else if(cmpYamlValue("StackSize",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.StackSize,"StackSize",ctx,0);
		else if(cmpYamlValue("RemasterVersion",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.RemasterVersion,"RemasterVersion",ctx,0);
		else if(cmpYamlValue("JumpId",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.JumpId,"JumpId",ctx,0);
		else if(cmpYamlValue("SaveDataSize",ctx)) SetSimpleYAMLValue(&rsf->SystemControlInfo.SaveDataSize,"SaveDataSize",ctx,0);
		else if(cmpYamlValue("Dependency",ctx)) rsf->SystemControlInfo.DependencyNum = SetYAMLSequenceFromMapping(&rsf->SystemControlInfo.Dependency,"Dependency",ctx,false);
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_BasicInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		if(cmpYamlValue("Title",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.Title,"Title",ctx,0);
		else if(cmpYamlValue("CompanyCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.CompanyCode,"CompanyCode",ctx,0);
		else if(cmpYamlValue("ProductCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.ProductCode,"ProductCode",ctx,0);
		else if(cmpYamlValue("ContentType",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.ContentType,"ContentType",ctx,0);
		else if(cmpYamlValue("Logo",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.Logo,"Logo",ctx,0);
		//else if(cmpYamlValue("BackupMemoryType",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.BackupMemoryType,"BackupMemoryType",ctx,0);
		//else if(cmpYamlValue("InitialCode",ctx)) SetSimpleYAMLValue(&rsf->BasicInfo.InitialCode,"InitialCode",ctx,0);
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_Rom(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("HostRoot",ctx)) SetSimpleYAMLValue(&rsf->Rom.HostRoot,"HostRoot",ctx,0);
		//else if(cmpYamlValue("Padding",ctx)) SetSimpleYAMLValue(&rsf->Rom.Padding,"Padding",ctx,0);
		
		else if(cmpYamlValue("DefaultReject",ctx)) rsf->Rom.DefaultRejectNum = SetYAMLSequence(&rsf->Rom.DefaultReject,"DefaultReject",ctx);
		else if(cmpYamlValue("Reject",ctx)) rsf->Rom.RejectNum = SetYAMLSequence(&rsf->Rom.Reject,"Reject",ctx);
		else if(cmpYamlValue("Include",ctx)) rsf->Rom.IncludeNum = SetYAMLSequence(&rsf->Rom.Include,"Include",ctx);
		else if(cmpYamlValue("File",ctx)) rsf->Rom.FileNum = SetYAMLSequence(&rsf->Rom.File,"File",ctx);
		
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_ExeFs(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("Text",ctx)) rsf->ExeFs.TextNum = SetYAMLSequence(&rsf->ExeFs.Text,"Text",ctx);
		else if(cmpYamlValue("ReadOnly",ctx)) rsf->ExeFs.ReadOnlyNum = SetYAMLSequence(&rsf->ExeFs.ReadOnly,"ReadOnly",ctx);
		else if(cmpYamlValue("ReadWrite",ctx)) rsf->ExeFs.ReadWriteNum = SetYAMLSequence(&rsf->ExeFs.ReadWrite,"ReadWrite",ctx);
		
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_PlainRegion(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	rsf->PlainRegionNum = SetYAMLSequence(&rsf->PlainRegion,"PlainRegion",ctx);
}

void GET_TitleInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("Category",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Category,"Category",ctx,0);
		//else if(cmpYamlValue("Platform",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Platform,"Platform",ctx,0);
		else if(cmpYamlValue("UniqueId",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.UniqueId,"UniqueId",ctx,0);
		else if(cmpYamlValue("Version",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Version,"Version",ctx,0);
		else if(cmpYamlValue("ContentsIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.ContentsIndex,"ContentsIndex",ctx,0);
		else if(cmpYamlValue("Variation",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Variation,"Variation",ctx,0);
		//else if(cmpYamlValue("Use",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.Use,"Use",ctx,0);
		else if(cmpYamlValue("ChildIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.ChildIndex,"ChildIndex",ctx,0);
		else if(cmpYamlValue("DemoIndex",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.DemoIndex,"DemoIndex",ctx,0);
		else if(cmpYamlValue("TargetCategory",ctx)) SetSimpleYAMLValue(&rsf->TitleInfo.TargetCategory,"TargetCategory",ctx,0);
		
		else if(cmpYamlValue("CategoryFlags",ctx)) rsf->TitleInfo.CategoryFlagsNum = SetYAMLSequence(&rsf->TitleInfo.CategoryFlags,"CategoryFlags",ctx);
		
		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_CardInfo(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("WritableAddress",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.WritableAddress,"WritableAddress",ctx,0);
		else if(cmpYamlValue("CardType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CardType,"CardType",ctx,0);
		else if(cmpYamlValue("CryptoType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CryptoType,"CryptoType",ctx,0);
		else if(cmpYamlValue("CardDevice",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.CardDevice,"CardDevice",ctx,0);
		else if(cmpYamlValue("MediaType",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.MediaType,"MediaType",ctx,0);
		else if(cmpYamlValue("MediaSize",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.MediaSize,"MediaSize",ctx,0);
		else if(cmpYamlValue("BackupWriteWaitTime",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.BackupWriteWaitTime,"BackupWriteWaitTime",ctx,0);
		else if(cmpYamlValue("SaveCrypto",ctx)) SetSimpleYAMLValue(&rsf->CardInfo.SaveCrypto,"SaveCrypto",ctx,0);

		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}

void GET_CommonHeaderKey(ctr_yaml_context *ctx, rsf_settings *rsf)
{
	/* Checking That Group is in a map */
	if(!CheckMappingEvent(ctx)) return;
	u32 InitLevel = ctx->Level;
	/* Checking each child */
	GetEvent(ctx);
	rsf->CommonHeaderKey.Found = true;
	while(ctx->Level == InitLevel){
		if(ctx->error || ctx->done) return;
		// Handle childs
		
		if(cmpYamlValue("D",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.D,"D",ctx,0); 
		else if(cmpYamlValue("P",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.P,"P",ctx,0); 
		else if(cmpYamlValue("Q",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.Q,"Q",ctx,0); 
		else if(cmpYamlValue("DP",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.DP,"DP",ctx,0); 
		else if(cmpYamlValue("DQ",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.DQ,"DQ",ctx,0); 
		else if(cmpYamlValue("InverseQ",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.InverseQ,"InverseQ",ctx,0); 
		else if(cmpYamlValue("Modulus",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.Modulus,"Modulus",ctx,0); 
		else if(cmpYamlValue("Exponent",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.Exponent,"Exponent",ctx,0); 
		else if(cmpYamlValue("Signature",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.AccCtlDescSign,"Signature",ctx,0); 
		else if(cmpYamlValue("Descriptor",ctx)) SetSimpleYAMLValue(&rsf->CommonHeaderKey.AccCtlDescBin,"Descriptor",ctx,0);

		else{
			fprintf(stderr,"[RSF ERROR] Unrecognised key '%s'\n",GetYamlString(ctx));
			ctx->error = YAML_UNKNOWN_KEY;
			FinishEvent(ctx);
			return;
		}
		// Finish event start next
		FinishEvent(ctx);
		GetEvent(ctx);
	}
	FinishEvent(ctx);
}