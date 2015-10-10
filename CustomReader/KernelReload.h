#ifndef _KERNELRELOAD_H_
#define _KERNELRELOAD_H_
#include "Utils.h"
#include "FileSystem.h"
#include "Fixrelocation.h"
#include "Tools.h"
char NtosModuleName[260];

BOOL GetNtosInformation(WCHAR** pKernelFullPath,
	ULONG* ulKernelBase, 
	ULONG* ulKernelSize);
BOOL GetNtosInfo(WCHAR **pKernelFullPath,ULONG *ulKernelBase, ULONG *ulKernelSize);

BOOL PeReload(WCHAR* wszFullPath,
	DWORD ulKernelBase,
	BYTE** ulReloadImageBase,
	PDRIVER_OBJECT DeviceObject);
#endif
