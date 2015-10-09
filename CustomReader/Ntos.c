#include "Ntos.h"

extern PDRIVER_OBJECT gMyDriverObject;

/* 重载ntos模块 */
NTSTATUS ReloadNtos(PDRIVER_OBJECT   DriverObject)
{
    //PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
    //NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (!GetNtosInformation(&SystemKernelFilePath,&SystemKernelModuleBase,&SystemKernelModuleSize)){
        if (SystemKernelFilePath){
            ExFreePool(SystemKernelFilePath);
        }
        return STATUS_UNSUCCESSFUL;
    }
    if (!PeReload(SystemKernelFilePath,SystemKernelModuleBase,&ReloadNtosImageBase,gMyDriverObject)){
        if (SystemKernelFilePath){
            ExFreePool(SystemKernelFilePath);
        }
        if (ReloadNtosImageBase){
            ExFreePool(ReloadNtosImageBase);
        }
        return STATUS_UNSUCCESSFUL;
    }
    ReloadServiceTable = GetOriginServiceTableFromReloadModule(SystemKernelModuleBase,(ULONG)ReloadNtosImageBase);

    /* ReloadShadowServiceTable 只是用来copy前7个字节到我们的函数中去 */
    //g_pOriginShadowTable =(PSERVICE_DESCRIPTOR_TABLE)ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE));
    //if (g_pOriginShadowTable)
    //{
    //	RtlZeroMemory((PVOID)g_pOriginShadowTable,sizeof(SERVICE_DESCRIPTOR_TABLE));
    //	if (pShadowTable)
    //	{
    //		g_pOriginShadowTable->TableSize = pShadowTable[1].TableSize;
    //		g_pOriginShadowTable->ArgumentTable = pShadowTable[1].ArgumentTable;
    //		g_pOriginShadowTable->CounterTable = pShadowTable[1].CounterTable;
    //		g_pOriginShadowTable->ServiceTable = pShadowTable[1].ServiceTable;
    //	}
    //}
    //这个申请的内核路径到底释放不是放呢？
    if (SystemKernelFilePath){
        ExFreePool(SystemKernelFilePath);
    }
    //ntos重定位之后，reload模块中的ssdt表保存的还是原始表 

    return STATUS_SUCCESS;
}
