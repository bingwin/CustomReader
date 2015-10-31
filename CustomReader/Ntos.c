#include "Ntos.h"
#include "Tools.h"

extern PDRIVER_OBJECT gMyDriverObject;
/*原始内核的基址*/
ULONG gNtosModuleBase;
BYTE *gReloadModuleBase;
ULONG gNtosModuleSize;

//
//三个函数在SSDT表中的索引号
//
PFN_KESTACKATTACHPROCESS gReloadKeStackAttackProcess;
PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;
//PFN_PSLOOKUPPROCESSBYPROCESSID gReloadPsLookupProcessByProcessId;


PSERVICE_DESCRIPTOR_TABLE ReloadKeServiceDescriptorTable;

/* 重载ntos模块 */
NTSTATUS ReloadNtos()
{
    WCHAR *szNtosFilePath           = NULL;
    PFN_KESTACKATTACHPROCESS pfnKeStackAttackProcess;
    PFN_KEUNSTACKDETACHPROCESS pfnKeUnstackDetachProcess;
    //PVOID PsLookupProcessByProcessIdAddr;

    //PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
    //NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!GetNtosInfo(&szNtosFilePath,&gNtosModuleBase,&gNtosModuleSize)){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        return STATUS_UNSUCCESSFUL;
    }
    if (!PeReload(szNtosFilePath,gNtosModuleBase,&gReloadModuleBase,gMyDriverObject)){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        if (gReloadModuleBase)
            ExFreePool(gReloadModuleBase);
        return STATUS_UNSUCCESSFUL;
    }

    /*初始化重载内核的服务描述表，但不进行重定位，表里面还是指向原始内核*/
    ReloadKeServiceDescriptorTable                  = (PSERVICE_DESCRIPTOR_TABLE)((ULONG)KeServiceDescriptorTable-gNtosModuleBase + (ULONG)gReloadModuleBase);
    ReloadKeServiceDescriptorTable->TableSize       = KeServiceDescriptorTable->TableSize;
    ReloadKeServiceDescriptorTable->ServiceTable    = (PULONG)((ULONG)gReloadModuleBase + (ULONG)KeServiceDescriptorTable->ServiceTable - gNtosModuleBase);

    pfnKeStackAttackProcess   = (PFN_KESTACKATTACHPROCESS)GetExportedFunctionAddr(L"KeStackAttachProcess");
    pfnKeUnstackDetachProcess = (PFN_KEUNSTACKDETACHPROCESS)GetExportedFunctionAddr(L"KeUnstackDetachProcess");
    //PsLookupProcessByProcessIdAddr = GetExportedFunctionAddr(L"PsLookupProcessByProcessId");
    if (!pfnKeStackAttackProcess || !pfnKeUnstackDetachProcess ){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        if (gReloadModuleBase)
            ExFreePool(gReloadModuleBase);
        return STATUS_UNSUCCESSFUL;
    }
    gReloadKeStackAttackProcess   = (PFN_KESTACKATTACHPROCESS)((ULONG)pfnKeStackAttackProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
    gReloadKeUnstackDetachProcess = (PFN_KEUNSTACKDETACHPROCESS)((ULONG)pfnKeUnstackDetachProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
    //gReloadPsLookupProcessByProcessId = (PFN_PSLOOKUPPROCESSBYPROCESSID)((ULONG)PsLookupProcessByProcessIdAddr - gNtosModuleBase + (ULONG)gReloadModuleBase);
    if (szNtosFilePath){
        ExFreePool(szNtosFilePath);
    }
    return STATUS_SUCCESS;
}

//
//释放reloadntos
//
VOID FreeNtos()
{
    if (gReloadModuleBase){
        ExFreePool(gReloadModuleBase);
    }
}
