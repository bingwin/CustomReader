//
//  [10/7/2015 13:04:57 vvLinker]
//
#include "LogSystem.h"
#include "Utils.h"
#include "Tools.h"
#include "Version.h"
#include "Ntos.h"
#include "CtrlCmd.h"
#include "CommStruct.h"
#include "FileProtect.h"


#define CommDeviceName			L"\\Device\\ReaderDevice"
#define CommSymLink				L"\\??\\ReaderSymLink"


PDRIVER_OBJECT gMyDriverObject;

extern PFN_KESTACKATTACHPROCESS gReloadKeStackAttackProcess;
extern PFN_KEUNSTACKDETACHPROCESS gReloadKeUnstackDetachProcess;

NTSTATUS __stdcall MyReadVirtualMemory(	
    ULONG 	    ProcessId,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    NTSTATUS status         = STATUS_UNSUCCESSFUL;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;


        /*这个函数肯定是用户层调用的*/
        if (((PCHAR)BaseAddress + NumberOfBytesToRead < (PCHAR)BaseAddress) ||
            ((PCHAR)Buffer + NumberOfBytesToRead < (PCHAR)Buffer) ||
            ((PVOID)((PCHAR)BaseAddress + NumberOfBytesToRead) > MM_HIGHEST_USER_ADDRESS)
            //buffer在这里肯定大于 8000000了
            /*((PVOID)((PCHAR)Buffer + NumberOfBytesToRead) > MM_HIGHEST_USER_ADDRESS)*/) {

                return STATUS_ACCESS_VIOLATION;
        }


    if (NumberOfBytesToRead != 0){
        status = LookupProcessByProcessId(ProcessId,&targetProcess);
        if (status == STATUS_SUCCESS){
            gReloadKeStackAttackProcess((PKPROCESS)targetProcess,&apcState);
            __try{
                ProbeForRead(BaseAddress,NumberOfBytesToRead,1);
                RtlCopyMemory(Buffer,BaseAddress,NumberOfBytesToRead);

            }__except(EXCEPTION_EXECUTE_HANDLER){
                gReloadKeUnstackDetachProcess(&apcState);
                return GetExceptionCode();
            }

            gReloadKeUnstackDetachProcess(&apcState);
        }
    }

    *NumberOfBytesRead = NumberOfBytesToRead;
    return status;
}

NTSTATUS __stdcall MyWriteVirtualMemory(
    ULONG       ProcessId,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToWrite,
    PSIZE_T 	NumberOfBytesWritten )
{
    NTSTATUS status         = STATUS_UNSUCCESSFUL;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;

    if (((PCHAR)BaseAddress + NumberOfBytesToWrite < (PCHAR)BaseAddress) ||
        ((PCHAR)Buffer + NumberOfBytesToWrite < (PCHAR)Buffer) ||
        ((PVOID)((PCHAR)BaseAddress + NumberOfBytesToWrite) > MM_HIGHEST_USER_ADDRESS)
        /*((PVOID)((PCHAR)Buffer + NumberOfBytesToWrite) > MM_HIGHEST_USER_ADDRESS)*/) {

            return STATUS_ACCESS_VIOLATION;
    }


    if (NumberOfBytesToWrite != 0){
        status = LookupProcessByProcessId(ProcessId,&targetProcess);

        if (status == STATUS_SUCCESS){
            gReloadKeStackAttackProcess((PKPROCESS)targetProcess,&apcState);
            __try{
                ProbeForWrite(BaseAddress,NumberOfBytesToWrite,1);
                RtlCopyMemory(BaseAddress,Buffer,NumberOfBytesToWrite);

            }__except(EXCEPTION_EXECUTE_HANDLER){
                gReloadKeUnstackDetachProcess(&apcState);
                return GetExceptionCode();
            }

            gReloadKeUnstackDetachProcess(&apcState);
        }
    }

    *NumberOfBytesWritten = NumberOfBytesToWrite;
    return status;
}

//
//删除device
//
VOID DeleteComm(IN PDRIVER_OBJECT pDriverObj)
{
    PDEVICE_OBJECT		pDevObj			= NULL;
    UNICODE_STRING		uniSymLinkName	= {0};

    pDevObj = pDriverObj->DeviceObject;
    if (pDevObj != NULL){
        /*删除符号链接*/
        RtlInitUnicodeString(&uniSymLinkName,CommSymLink);
        IoDeleteSymbolicLink(&uniSymLinkName);

        /*删除设备*/
        IoDeleteDevice(pDevObj);
        pDevObj = NULL;
        LogPrint("DeleteCommDevice ok!\r\n");
    }

}

//
//建立R3与R0的通信
//
NTSTATUS SetupComm(PDRIVER_OBJECT pDriverObj)
{
    NTSTATUS			ntStatus		= STATUS_UNSUCCESSFUL;	
    UNICODE_STRING		uniDeviceName	= {0};
    UNICODE_STRING		uniSymLinkName	= {0};
    PDEVICE_OBJECT		pDevObj			= NULL;

    /*创建设备*/
    RtlInitUnicodeString(&uniDeviceName,CommDeviceName);
    ntStatus = IoCreateDevice(pDriverObj,
        0,
        &uniDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        TRUE,
        &pDevObj);
    if (!NT_SUCCESS(ntStatus)){
        LogPrint("IoCreateDevice failed...\r\n");
        return ntStatus;
    }
    /*配置设备*/
    pDevObj->Flags |= DO_BUFFERED_IO;

    /*创建符号链接*/
    RtlInitUnicodeString(&uniSymLinkName,CommSymLink);
    ntStatus = IoCreateSymbolicLink(&uniSymLinkName,&uniDeviceName);
    if(!NT_SUCCESS(ntStatus)){
        LogPrint("IoCreateSymbolicLink failed...\r\n");
        IoDeleteDevice(pDevObj);
        return ntStatus;
    }
    LogPrint("CreateCommDevice ok!\r\n");
    /*创建成功，注册派遣例程*/
    return STATUS_SUCCESS;
}

//
//驱动卸载函数
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	LogPrint("DriverUnload called...\r\n");
	DeleteComm(pDriverObj);
    stopFileProtect();
    FreeNtos();
}
//
//通用的派遣
//

NTSTATUS CommDispatcher (IN PDEVICE_OBJECT DeviceObject,IN PIRP pIrp)
{

    pIrp->IoStatus.Status       = STATUS_SUCCESS;
    pIrp->IoStatus.Information  = 0;
    IoCompleteRequest(pIrp,IO_NO_INCREMENT);
    return STATUS_SUCCESS;

}
NTSTATUS UserCmdDispatcher (IN PDEVICE_OBJECT DeviceObject,IN PIRP pIrp)
{
    NTSTATUS status				= STATUS_SUCCESS;
    PIO_STACK_LOCATION stack	= NULL;
    ULONG cbin					= 0;
    ULONG cbout					= 0;
    ULONG cmd					= 0;
    ULONG info					= 0;
    stack	= IoGetCurrentIrpStackLocation(pIrp);
    /*输入缓冲区大小*/
    cbin    = stack->Parameters.DeviceIoControl.InputBufferLength;
    /*输出缓冲区大小*/
    cbout   = stack->Parameters.DeviceIoControl.OutputBufferLength;
    //得到命令码
    cmd		= stack->Parameters.DeviceIoControl.IoControlCode;
    switch(cmd){
    case FC_COMM_TEST:
        {
            PCOMMTEST pCommTest = (PCOMMTEST)pIrp->AssociatedIrp.SystemBuffer;

            pCommTest->success  = TRUE;
            /*在这里开启文件保护*/
            startFileProtect();
            info = cbout;
        }
        break;
    case FC_GET_NAME_BY_ID:
        {
            PNAMEINFO pni       = (PNAMEINFO)pIrp->AssociatedIrp.SystemBuffer;
            status              = LookupNameByProcessId(pni->dwPid,pni->ProcessName);
            if (NT_SUCCESS(status))
                info = cbout;
            else
                info = 0;
        }
        break;
    case FC_READ_PROCESS_MEMORY:
        {
            PREADMEM_INFO pri   = (PREADMEM_INFO)pIrp->AssociatedIrp.SystemBuffer;
            status  = MyReadVirtualMemory(pri->ProcessId,
                pri->BaseAddress,
                pri->Buffer,
                pri->NumberOfBytesToRead,
                &pri->NumberOfBytesRead);
            info = (status == STATUS_SUCCESS) ? cbout : 0;
        }
        break;
    case FC_WRITE_PROCESS_MEMORY:
        {
            PWRITEMEM_INFO pwi  = (PWRITEMEM_INFO)pIrp->AssociatedIrp.SystemBuffer;
                status  = MyWriteVirtualMemory(pwi->ProcessId,
                    pwi->BaseAddress,
                    pwi->Buffer,
                    pwi->NumberOfBytesToWrite,
                    &pwi->NumberOfBytesWritten);
            info = NT_SUCCESS(status) ? cbout : 0;
    }
        break;
    default:
        status  = STATUS_INVALID_VARIANT;
        break;
    }
    /*设置irp完成状态*/
    pIrp->IoStatus.Status      = status;
    /*设置irp请求的操作数*/
    pIrp->IoStatus.Information = info;
    //结束irp请求
    IoCompleteRequest(pIrp,IO_NO_INCREMENT);
    return status;
}
//
//驱动入口函数
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj,PUNICODE_STRING pRegisterPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

    gMyDriverObject = pDriverObj;
	/*注册驱动卸载函数*/
	pDriverObj->DriverUnload                            = DriverUnload;
    pDriverObj->MajorFunction[IRP_MJ_CREATE]            = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_CLOSE]             = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_READ]              = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_WRITE]             = CommDispatcher;
    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]    = UserCmdDispatcher;

    //DbgBreakPoint();
	/*初始化系统版本和相关结构的偏移硬编码*/
	InitStructOffset();

	/*初始化通信*/
    status = SetupComm(pDriverObj);
    if (!NT_SUCCESS(status)){
        return status;
    }

    /*重载Ntos*/
    status = ReloadNtos();
    if(!NT_SUCCESS(status)){
        DeleteComm(pDriverObj);
        return status;
    }

	return STATUS_SUCCESS;
}