#include "lib.h"
#include "cia.h"

u64 GetCiaCertOffset(cia_hdr *hdr)
{
	u64 hdrSize = u8_to_u32(hdr->hdrSize,LE);
	return align(hdrSize,CIA_ALIGN_SIZE);
}

u64 GetCiaCertSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->certChainSize,LE);
}

u64 GetTikOffset(cia_hdr *hdr)
{
	u64 certOffset = GetCiaCertOffset(hdr);
	u64 certSize = GetCiaCertSize(hdr);
	return align(certOffset + certSize,CIA_ALIGN_SIZE);
}

u64 GetTikSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->tikSize,LE);
}

u64 GetTmdOffset(cia_hdr *hdr)
{
	u64 tikOffset = GetTikOffset(hdr);
	u64 tikSize = GetTikSize(hdr);
	return align(tikOffset + tikSize,CIA_ALIGN_SIZE);
}

u64 GetTmdSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->tmdSize,LE);
}

u64 GetContentOffset(cia_hdr *hdr)
{
	u64 tmdOffset = GetTmdOffset(hdr);
	u64 tmdSize = GetTmdSize(hdr);
	return align(tmdOffset + tmdSize,CIA_ALIGN_SIZE);
}

u64 GetContentSize(cia_hdr *hdr)
{
	return u8_to_u64(hdr->contentSize,LE);
}

u64 GetMetaOffset(cia_hdr *hdr)
{
	u64 contentOffset = GetContentOffset(hdr);
	u64 contentSize = GetContentSize(hdr);
	return align(contentOffset + contentSize,CIA_ALIGN_SIZE);
}

u64 GetMetaSize(cia_hdr *hdr)
{
	return u8_to_u32(hdr->metaSize,LE);
}