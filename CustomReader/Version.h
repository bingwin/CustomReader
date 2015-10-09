#pragma once
#include "Utils.h"

typedef enum WIN_VER_DETAIL {
	WINDOWS_VERSION_NONE,       //  0
	WINDOWS_VERSION_2K,
	WINDOWS_VERSION_XP,
	WINDOWS_VERSION_2K3,
	WINDOWS_VERSION_2K3_SP1_SP2,
	WINDOWS_VERSION_VISTA_2008,
	WINDOWS_VERSION_7_7600_UP,
	WINDOWS_VERSION_7_7000
} WIN_VER_DETAIL;

typedef struct tagStructOffset{
	/*EPROCESS结构相关偏移*/
	ULONG EProcessImageFileName;
	ULONG EProcessUniqueProcessId;
	ULONG EProcessActiveProcessLinks;
	ULONG EProcessDebugPort;
	ULONG EProcessObjectTable;
	ULONG EProcessVadRoot;
	ULONG EProcessThreadListHead;//   : _LIST_ENTRY
    /*FILEOBJECT 结构相关偏移*/
    ULONG FileObjectSize;


}STRUCT_OFFSET,*PSTRUCT_OFFSET;

WIN_VER_DETAIL GetWindowsVersion();

VOID InitStructOffset();