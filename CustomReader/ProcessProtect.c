#include "ProcessProtect.h"
#include "HookEngine.h"
#include "LogSystem.h"
#include "Tools.h"

HOOKINFO gObReferenceObjectByHandleInfo;
HOOKINFO gObOpenObjectByPointerInfo;
HOOKINFO gNtQueryVirtualMemoryInfo;

extern PEPROCESS ProtectProcess;
extern HANDLE CsrssHandle;
extern DWORD GameProcessId;
extern PSERVICE_DESCRIPTOR_TABLE ReloadKeServiceDescriptorTable;

__declspec(naked)VOID ObReferenceObjectByHandleZone()
{
    NOP_PROC;
    __asm jmp [gObReferenceObjectByHandleInfo.retAddress];
}

NTSTATUS
    __stdcall
    NewObReferenceObjectByHandle (
     HANDLE Handle,
     ACCESS_MASK DesiredAccess,
     POBJECT_TYPE ObjectType,
     KPROCESSOR_MODE AccessMode,
     PVOID *Object,
     POBJECT_HANDLE_INFORMATION HandleInformation
    )
{
    NTSTATUS status;
    PEPROCESS GameProcess;
    PEPROCESS tmpProcess;
    POBJECT_HEADER ObjectHeader;
    PFN_OBREFERENCEOBJECTBYHANDLE pfnObReferenceObjectByHandle;
    pfnObReferenceObjectByHandle = (PFN_OBREFERENCEOBJECTBYHANDLE)ObReferenceObjectByHandleZone;


    /*是否是查询内存函数调用*/
    if (PsGetCurrentProcess() == ProtectProcess){
        if (Handle == FAKE_HANDLE){
            if (ObjectType == *PsProcessType){
                status = LookupProcessByProcessId(GameProcessId,&GameProcess);
                if(NT_SUCCESS(status)){

                    ObjectHeader = OBJECT_TO_OBJECT_HEADER(GameProcess);
                    /*手动增加引用计数*/
                    InterlockedIncrement(&ObjectHeader->PointerCount);
                    LogPrint("get process!\r\n");
                    *Object = GameProcess;
                    return status;
                }
            }
        }
    }

    /*不是我的进程在使用则调用原始的函数，也有可能是上面的PsLookup执行失败了*/
    status = pfnObReferenceObjectByHandle(Handle,
        DesiredAccess,
        ObjectType,
        AccessMode,
        Object,
        HandleInformation
        );
    if (!NT_SUCCESS(status)){
        return status;
    }

    if (isGameProcess()){

        if (ObjectType == *PsProcessType){

            if ((PEPROCESS)*Object == ProtectProcess){

                LogPrint("Game Open My Process[2]!\r\n");

                ObDereferenceObject(*Object);

//                 status = LookupProcessByName("Tencentdl.exe",&tmpProcess);
// 
//                 if (NT_SUCCESS(status)){
// 
//                     (PEPROCESS)*Object = tmpProcess;
// 
//                     ObjectHeader = OBJECT_TO_OBJECT_HEADER(tmpProcess);
// 
//                     /*手动增加引用计数*/
//                     InterlockedIncrement(&ObjectHeader->PointerCount);
// 
//                     return status;
//                 }

                return STATUS_UNSUCCESSFUL;
            }
        }
    }
    return status;
}


BOOL HookObReferenceObjectByHandle()
{
    BOOL bRetOk = FALSE;
    ULONG ulObReferenceObjectByHandleAddr;
    ulObReferenceObjectByHandleAddr = (ULONG)GetExportedFunctionAddr(L"ObReferenceObjectByHandle");
    if (ulObReferenceObjectByHandleAddr == 0)
        return FALSE;

    gObReferenceObjectByHandleInfo.originAddress = ulObReferenceObjectByHandleAddr;
    gObReferenceObjectByHandleInfo.targetAddress = (ULONG)NewObReferenceObjectByHandle;
    gObReferenceObjectByHandleInfo.hookZone      = (PVOID)ObReferenceObjectByHandleZone;
    
    bRetOk = setInlineHook(&gObReferenceObjectByHandleInfo);
    if(!bRetOk)
        LogPrint("HookObReferenceObjectByHandle->setInlineHook failed\r\n");
    return bRetOk;
}

VOID UnhookObReferenceObjectByHandle()
{
    removeInlineHook(&gObReferenceObjectByHandleInfo);
}


__declspec(naked)VOID ObOpenObjectByPointerZone()
{
    NOP_PROC;
    __asm jmp [gObOpenObjectByPointerInfo.retAddress];
}
NTSTATUS   __stdcall
NewObOpenObjectByPointer(                          
     PVOID Object,                                 
     ULONG HandleAttributes,                       
     PACCESS_STATE PassedAccessState,              
     ACCESS_MASK DesiredAccess,                    
     POBJECT_TYPE ObjectType,                      
     KPROCESSOR_MODE AccessMode,                   
     PHANDLE Handle                                
    )
{
    NTSTATUS status;
    PFN_OBJOPENOBJECTBYPOINTER pfnObOpenObjectByPointer;
    PEPROCESS tmpProcess;

    pfnObOpenObjectByPointer = (PFN_OBJOPENOBJECTBYPOINTER)ObOpenObjectByPointerZone;

    if(isGameProcess()){

        if (ObjectType == *PsProcessType){

            if ((PEPROCESS)Object == ProtectProcess){

                LogPrint("Game Open My Process![1]\r\n");

                status = LookupProcessByName("Tencentdl.exe",&tmpProcess);

                if (NT_SUCCESS(status)){

                   status = pfnObOpenObjectByPointer(tmpProcess,
                        HandleAttributes,
                        PassedAccessState,
                        DesiredAccess,
                        ObjectType,
                        AccessMode,
                        Handle);

                   return status;
                }
                else{

                    status = LookupProcessByName("TenioDL.exe",&tmpProcess);

                    if (NT_SUCCESS(status)){

                        status = pfnObOpenObjectByPointer(tmpProcess,
                            HandleAttributes,
                            PassedAccessState,
                            DesiredAccess,
                            ObjectType,
                            AccessMode,
                            Handle);

                        return status;
                    }
                }
                //return STATUS_UNSUCCESSFUL;
            }
        }
    }

    return pfnObOpenObjectByPointer(Object,
        HandleAttributes,
        PassedAccessState,
        DesiredAccess,
        ObjectType,
        AccessMode,
        Handle);
}

BOOL HookObOpenObjectByPointer()
{
    BOOL bRetOk = FALSE;
    ULONG ulObOpenObjectByPointerAddr;
    ulObOpenObjectByPointerAddr = (ULONG)GetExportedFunctionAddr(L"ObOpenObjectByPointer");
    if (ulObOpenObjectByPointerAddr == 0)
        return FALSE;

    gObOpenObjectByPointerInfo.originAddress = ulObOpenObjectByPointerAddr;
    gObOpenObjectByPointerInfo.targetAddress = (ULONG)NewObOpenObjectByPointer;
    gObOpenObjectByPointerInfo.hookZone      = (PVOID)ObOpenObjectByPointerZone;

    bRetOk = setInlineHook(&gObOpenObjectByPointerInfo);
    if(!bRetOk)
        LogPrint("HookObOpenObjectByPointer->setInlineHook failed\r\n");
    return bRetOk;
}

VOID UnhookObOpenObjectByPointer()
{
    removeInlineHook(&gObOpenObjectByPointerInfo);
}


__declspec(naked) VOID NtQueryVirtualMemoryZone()
{
    NOP_PROC;
    __asm jmp [gNtQueryVirtualMemoryInfo.retAddress]
}

NTSTATUS __stdcall
    NewNtQueryVirtualMemory(
    __in HANDLE ProcessHandle,
    __in PVOID BaseAddress,
    __in MEMORY_INFORMATION_CLASS MemoryInformationClass,
    __out_bcount(MemoryInformationLength) PVOID MemoryInformation,
    __in SIZE_T MemoryInformationLength,
    __out_opt PSIZE_T ReturnLength
    )
{
    NTSTATUS status;
    PFN_NTQUERYVIRTUALMEMORY pfnOrinNtQueryVirtualMemory = (PFN_NTQUERYVIRTUALMEMORY)NtQueryVirtualMemoryZone;

    status = pfnOrinNtQueryVirtualMemory(ProcessHandle,BaseAddress,MemoryInformationClass,MemoryInformation,MemoryInformationLength,ReturnLength);
    if (!NT_SUCCESS(status)){
        LogPrint("query failed,code: 0x%x\r\n",status);
    }
    else{
        LogPrint("NewNtQueryVirtualMemory ok!\r\n");
    }
    return status;
}

BOOL HookNtQueryVirtualMemory()
{
    ULONG oriNtQueryVirtualMemoryAddr = ReloadKeServiceDescriptorTable->ServiceTable[178];
    gNtQueryVirtualMemoryInfo.originAddress = oriNtQueryVirtualMemoryAddr;
    gNtQueryVirtualMemoryInfo.targetAddress = (ULONG)NewNtQueryVirtualMemory;
    gNtQueryVirtualMemoryInfo.hookZone      = NtQueryVirtualMemoryZone;

    return setInlineHook(&gNtQueryVirtualMemoryInfo);
}

VOID UnhookNtQueryVirtualMemory()
{
    removeInlineHook(&gNtQueryVirtualMemoryInfo);
}



BOOL StartProcessProtect()
{
    if (!HookObReferenceObjectByHandle())
        return FALSE;
    if (!HookObOpenObjectByPointer()){
        UnhookObReferenceObjectByHandle();
        return FALSE;
    }
    //if (!HookNtQueryVirtualMemory()){
    //    UnhookObReferenceObjectByHandle();
    //    UnhookObOpenObjectByPointer();
    //    return FALSE;
    //}

    return TRUE;
}
VOID StopProcessProtect()
{
    UnhookObReferenceObjectByHandle();
    UnhookObOpenObjectByPointer();
    //UnhookNtQueryVirtualMemory();
}