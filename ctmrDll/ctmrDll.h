#pragma once

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID,*PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS (NTAPI *PFN_ZWDEVICEIOCONTROLFILE)(
      HANDLE           FileHandle,
      HANDLE           Event,
      PVOID  ApcRoutine,
      PVOID            ApcContext,
     PIO_STATUS_BLOCK IoStatusBlock,
      ULONG            IoControlCode,
      PVOID            InputBuffer,
      ULONG            InputBufferLength,
     PVOID            OutputBuffer,
      ULONG            OutputBufferLength
    );
/*ZwOpenProcess函数指针*/
typedef NTSTATUS (NTAPI *PFN_ZWOPENPROCESS)(
	    PHANDLE            ProcessHandle,
	    ACCESS_MASK        DesiredAccess,
	    POBJECT_ATTRIBUTES ObjectAttributes,
	    PCLIENT_ID         ClientId);
/*zwreadvirtualmemory 指针*/
typedef NTSTATUS (NTAPI *PFN_ZWREADVIRTUALMEMORY)(	
	 HANDLE 	ProcessHandle,
	 PVOID 	    BaseAddress,
	 PVOID 	    Buffer,
	 SIZE_T 	NumberOfBytesToRead,
	 PSIZE_T 	NumberOfBytesRead );

typedef NTSTATUS (NTAPI *PFN_ZWWRITEVIRTUALMEMORY)(
	 HANDLE 	ProcessHandle,
	 PVOID 	    BaseAddress,
	 PVOID 	    Buffer,
	 SIZE_T 	NumberOfBytesToWrite,
	 PSIZE_T 	NumberOfBytesWritten );

//
//完成customreader的初始化工作，包括R3的ntdll改造、R0驱动的加载和通信测试
//
BOOL __stdcall InitCustomReader(); 

//
//在程序结束时卸载R3的hook、卸载内核中的驱动程序
//
void __stdcall UnloadCustomReader();
