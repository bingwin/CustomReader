#include "Ntos.h"

extern PDRIVER_OBJECT gMyDriverObject;
/*原始内核的基址*/
ULONG gNtosModuleBase;
BYTE *gReloadModuleBase;

extern PFN_KESTACKATTACHPROCESS gReloadKeStackAttachProcess;
extern PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;

//
//三个函数在SSDT表中的索引号
//
//ULONG gZwOpenProcessIndex;
//ULONG gZwReadVirtualMemoryIndex;
//ULONG gZwWriteVirtualMemoryIndex;

/* 重载ntos模块 */
NTSTATUS ReloadNtos()
{
    WCHAR *szNtosFilePath           = NULL;
    ULONG ulNtosModuleSize          = 0;
    BYTE *pKeStackAttachProcess     = NULL;
    BYTE * pKeUnstackDetachProcess  = NULL;
    //PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
    //NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!GetNtosInfo(&szNtosFilePath,&gNtosModuleBase,&ulNtosModuleSize)){
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
    pKeStackAttachProcess           = GetExportedFunctionAddr(L"KeStackAttachProcess");
    pKeUnstackDetachProcess         = GetExportedFunctionAddr(L"KeUnstackDetachProcess");
    if(!pKeStackAttachProcess || !pKeUnstackDetachProcess){
        if (szNtosFilePath)
            ExFreePool(szNtosFilePath);
        if (gReloadModuleBase)
            ExFreePool(gReloadModuleBase);
        return STATUS_UNSUCCESSFUL;
    }
    /*初始化两个切换函数*/
    gReloadKeStackAttachProcess     = (PFN_KESTACKATTACHPROCESS)((ULONG)pKeStackAttachProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
    gReloadKeUnstackDetachProcess   = (PFN_KEUNSTACKDETACHPROCESS)((ULONG)pKeUnstackDetachProcess - gNtosModuleBase + (ULONG)gReloadModuleBase);
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
