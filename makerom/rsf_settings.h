#pragma once

void EvaluateRSF(rsf_settings *rsf, ctr_yaml_context *ctx);

void GET_Option(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_AccessControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_SystemControlInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_BasicInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_Rom(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_ExeFs(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_PlainRegion(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_TitleInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_CardInfo(ctr_yaml_context *ctx, rsf_settings *rsf);
void GET_CommonHeaderKey(ctr_yaml_context *ctx, rsf_settings *rsf);

void free_RsfSettings(rsf_settings *set);