#include "ProcessProtect.h"
#include "HookEngine.h"
#include "LogSystem.h"
#include "Tools.h"

HOOKINFO gObReferenceObjectByHandleInfo;
HOOKINFO gObOpenObjectByPointerInfo;

extern PEPROCESS ProtectProcess;
extern HANDLE CsrssHandle;
extern DWORD GameProcessId;

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
    PFN_OBREFERENCEOBJECTBYHANDLE pfnObReferenceObjectByHandle;
    pfnObReferenceObjectByHandle = (PFN_OBREFERENCEOBJECTBYHANDLE)ObReferenceObjectByHandleZone;

    /*先判断是不是我的进程在使用游戏进程的句柄*/
    if (PsGetCurrentProcess() == ProtectProcess){
        if (Handle == CsrssHandle){

            /*证明是自己要操作游戏进程内存*/
            DWORD dwGamePid = GameProcessId;
            if (ObjectType == *PsProcessType){
                /*为什么使用PsLookupProcessByProcessId而不是我自己的函数，因为这个函数也会增加引用计数，
                相当于模拟了ObReferenceObjectByHandle，caller在后面还会减少引用计数*/
                status  = PsLookupProcessByProcessId((HANDLE)dwGamePid,&GameProcess);
                if(NT_SUCCESS(status)){
                    //LogPrint("csrss eprocess!\r\n");
                    *Object = GameProcess;
                    return STATUS_SUCCESS;
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
                LogPrint("Game Open My Process!\r\n");
                ObDereferenceObject(*Object);
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

    pfnObOpenObjectByPointer = (PFN_OBJOPENOBJECTBYPOINTER)ObOpenObjectByPointerZone;
    if(isGameProcess()){
        if (ObjectType == *PsProcessType){
            if ((PEPROCESS)Object == ProtectProcess){
                LogPrint("Game Open My Process\r\n");
                return STATUS_UNSUCCESSFUL;
            }
        }
    }

    return pfnObOpenObjectByPointer(Object,
        HandleAttributes,
        PassedAccessState,
        DesiredAccess,
        ObjectType,
        AccessMode,Handle);
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

BOOL StartProcessProtect()
{
    if (!HookObReferenceObjectByHandle())
        return FALSE;
    if (!HookObOpenObjectByPointer())
        return FALSE;
    return TRUE;
}
VOID StopProcessProtect()
{
    UnhookObReferenceObjectByHandle();
    UnhookObOpenObjectByPointer();
}