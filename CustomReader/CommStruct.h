#pragma once

#define  MAX_BUFFER_LENGTH      260
//typedef unsigned char  BOOL, *PBOOL;
//
//通信相关结构
//
#pragma pack(push)
#pragma pack(1)
typedef struct tagCOMMTEST{

    DWORD success;//结构体里面尽量不要使用 bool值
}COMMTEST,*PCOMMTEST;

typedef struct tagNAMEINFO{
    DWORD dwPid;
    char ProcessName[MAX_BUFFER_LENGTH];
}NAMEINFO,*PNAMEINFO;

//
//读内存函数需要的信息
//
//HANDLE 	    ProcessHandle,
//PVOID 	    BaseAddress,
//PVOID 	    Buffer,
//SIZE_T 	    NumberOfBytesToRead,
//PSIZE_T 	NumberOfBytesRead
typedef struct tagREADMEM_INFO{
    char   ProcessName[MAX_BUFFER_LENGTH];
    UCHAR  Buffer[MAX_BUFFER_LENGTH * 2];
    PVOID  BaseAddress;
    DWORD  NumberOfBytesToRead;
    DWORD  NumberOfBytesRead;
    DWORD  ProcessId;
}READMEM_INFO,*PREADMEM_INFO;

/*写内存函数需要的信息*/
    //HANDLE 	    ProcessHandle,
    //PVOID 	    BaseAddress,
    //PVOID 	    Buffer,
    //SIZE_T 	    NumberOfBytesToWrite,
    //PSIZE_T 	NumberOfBytesWritten
typedef struct tagWRITEMEM_INFO{
    char   ProcessName[MAX_BUFFER_LENGTH];
    UCHAR  Buffer[MAX_BUFFER_LENGTH * 2];
    PVOID  BaseAddress;
    DWORD  NumberOfBytesToWrite;
    DWORD  NumberOfBytesWritten;
    DWORD  ProcessId;
}WRITEMEM_INFO,*PWRITEMEM_INFO;
#pragma pack(pop)
//#pragma pack()