#include "Ntos.h"

extern PDRIVER_OBJECT gMyDriverObject;
/*原始内核的基址*/
ULONG gNtosModuleBase;
BYTE *gReloadModuleBase;
PSERVICE_DESCRIPTOR_TABLE gServiceTable = NULL;

//
//三个函数在SSDT表中的索引号
//
ULONG gZwOpenProcessIndex;
ULONG gZwReadVirtualMemoryIndex;
ULONG gZwWriteVirtualMemoryIndex;

/* 重载ntos模块 */
NTSTATUS ReloadNtos()
{
    WCHAR *szNtosFilePath   = NULL;
    ULONG ulNtosModuleSize  = 0;
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
    gServiceTable               = (PSERVICE_DESCRIPTOR_TABLE)((ULONG)gReloadModuleBase + (ULONG)KeServiceDescriptorTable - gNtosModuleBase);
    gServiceTable->TableSize    = KeServiceDescriptorTable->TableSize;
    gServiceTable->ServiceTable = (PULONG)((ULONG)gReloadModuleBase + (ULONG)KeServiceDescriptorTable->ServiceTable - gNtosModuleBase);
    if (szNtosFilePath){
        ExFreePool(szNtosFilePath);
    }
    return STATUS_SUCCESS;
}
