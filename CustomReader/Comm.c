#include "Comm.h"

#define CommDeviceName			L"\\Device\\ReaderDevice"
#define CommSymLink				L"\\??\\ReaderSymLink"
//
//创建一个用于通信的Device
//
NTSTATUS CreateCommDevice(IN PDRIVER_OBJECT pDriverObj)
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
	return ntStatus;
}
//
//删除device
//
VOID DeleteCommDevice(IN PDRIVER_OBJECT pDriverObj)
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
//用户命令派遣
//
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
			info = cbout;
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
//建立R3与R0的通信
//
NTSTATUS SetupComm(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS ntStatus		= STATUS_UNSUCCESSFUL;
	if (pDriverObj == NULL)
		return STATUS_UNSUCCESSFUL;

	ntStatus = CreateCommDevice(pDriverObj);
	if (!NT_SUCCESS(ntStatus)){
		return ntStatus;
	}
	LogPrint("CreateCommDevice ok!\r\n");
	/*创建成功，注册派遣例程*/
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UserCmdDispatcher;

	return STATUS_SUCCESS;
}