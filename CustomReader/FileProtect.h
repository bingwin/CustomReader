#pragma once
#include "Utils.h"
/*zwcreatefile 函数指针*/
typedef NTSTATUS (__stdcall  *PFN_ZWCREATEFILE)(
    __out PHANDLE  FileHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in_opt PLARGE_INTEGER  AllocationSize,
    __in ULONG  FileAttributes,
    __in ULONG  ShareAccess,
    __in ULONG  CreateDisposition,
    __in ULONG  CreateOptions,
    __in_opt PVOID  EaBuffer,
    __in ULONG  EaLength
    );


/*保护本目录内的文件不被访问*/
BOOL startFileProtect();
VOID stopFileProtect();

BOOL HookNtfsCreate();
VOID RestoreNtfsCreate();