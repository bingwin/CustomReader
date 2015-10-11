#ifndef _UTILS_H_
#define _UTILS_H_

#include <ntddk.h>
#include <ntimage.h>

typedef unsigned char  BOOL, *PBOOL;
typedef unsigned char  BYTE, *PBYTE;
typedef unsigned long  DWORD, *PDWORD;
typedef unsigned short WORD, *PWORD;

typedef unsigned int    UINT;

typedef struct _AUX_ACCESS_DATA {
    PPRIVILEGE_SET PrivilegesUsed;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK AccessesToAudit;
    ACCESS_MASK MaximumAuditMask;
    //ULONG Unknown[41];
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
    PVOID EntryPointActivationContext;

    PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION  // 系统模块信息
{
    ULONG  Reserved[2];  
    ULONG  Base;        
    ULONG  Size;         
    ULONG  Flags;        
    USHORT Index;       
    USHORT Unknown;     
    USHORT LoadCount;   
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];   
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _tagSysModuleList {          //模块链结构
    ULONG ulCount;
    SYSTEM_MODULE_INFORMATION smi[1];
} MODULES, *PMODULES;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	/*
	* Table containing cServices elements of pointers to service handler
	* functions, indexed by service ID.
	*/
	PULONG   ServiceTable;
	/*
	* Table that counts how many times each service is used. This table
	* is only updated in checked builds.
	*/
	PULONG  CounterTable;
	/*
	* Number of services contained in this table.
	*/
	ULONG   TableSize;
	/*
	* Table containing the number of bytes of parameters the handler
	* function takes.
	*/
	PUCHAR  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
/*声明系统描述表*/
extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;

typedef struct _KAPC_STATE             // 5 elements, 0x18 bytes (sizeof) 
{                                                                         
    /*0x000*/     struct _LIST_ENTRY ApcListHead[2];                                    
    /*0x010*/     PVOID   Process;                                            
    /*0x014*/     UINT8   KernelApcInProgress;                                     
    /*0x015*/     UINT8   KernelApcPending;                                        
    /*0x016*/     UINT8   UserApcPending;                                                                               
}KAPC_STATE, *PKAPC_STATE; 

PCHAR PsGetProcessImageFileName(PEPROCESS Eprocess);

NTKERNELAPI				
    NTSTATUS
    ObCreateObject(
    IN KPROCESSOR_MODE ProbeMode,
    IN POBJECT_TYPE ObjectType,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN KPROCESSOR_MODE OwnershipMode,
    IN OUT PVOID ParseContext OPTIONAL,
    IN ULONG ObjectBodySize,
    IN ULONG PagedPoolCharge,
    IN ULONG NonPagedPoolCharge,
    OUT PVOID *Object
    );

NTKERNELAPI
    NTSTATUS
    SeCreateAccessState(
    PACCESS_STATE AccessState,
    PAUX_ACCESS_DATA AuxData,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping
    );

NTKERNELAPI                                                     
    NTSTATUS                                                        
    ObReferenceObjectByHandle(                                      
    IN HANDLE Handle,                                           
    IN ACCESS_MASK DesiredAccess,                               
    IN POBJECT_TYPE ObjectType OPTIONAL,                        
    IN KPROCESSOR_MODE AccessMode,                              
    OUT PVOID *Object,                                          
    OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
    );                                                          
NTKERNELAPI                                                     
    NTSTATUS                                                        
    ObOpenObjectByPointer(                                          
    IN PVOID Object,                                            
    IN ULONG HandleAttributes,                                  
    IN PACCESS_STATE PassedAccessState OPTIONAL,                
    IN ACCESS_MASK DesiredAccess OPTIONAL,                      
    IN POBJECT_TYPE ObjectType OPTIONAL,                        
    IN KPROCESSOR_MODE AccessMode,                              
    OUT PHANDLE Handle                                          
    ); 

NTSTATUS __stdcall ZwQuerySystemInformation(

    IN ULONG SystemInformationClass,

    PVOID SystemInformation,

    ULONG SystemInformationLength,

    PULONG ReturnLength
    );

//VOID NTAPI KeStackAttachProcess	(IN PKPROCESS 	Process,OUT PKAPC_STATE 	ApcState );	
//VOID NTAPI KeUnstackDetachProcess(IN PKAPC_STATE ApcState)	;

typedef VOID (NTAPI *PFN_KESTACKATTACHPROCESS)(IN PKPROCESS 	Process,OUT PKAPC_STATE 	ApcState );	
typedef VOID (NTAPI *PFN_KEUNSTACKDETACHPROCESS)(IN PKAPC_STATE ApcState)	;
#endif//_UTILS_H_