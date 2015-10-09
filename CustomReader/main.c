//
//  [10/7/2015 13:04:57 vvLinker]
//
#include "LogSystem.h"
#include "Utils.h"
#include "Version.h"
#include "Comm.h"

PDRIVER_OBJECT gMyDriverObject;
//
//驱动卸载函数
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	LogPrint("DriverUnload called...\r\n");
	DeleteCommDevice(pDriverObj);
}
//
//驱动入口函数
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj,PUNICODE_STRING pRegisterPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

    gMyDriverObject = pDriverObj;
	/*注册驱动卸载函数*/
	pDriverObj->DriverUnload = DriverUnload;

	DbgBreakPoint();
	/*初始化系统版本和相关结构的偏移硬编码*/
	InitStructOffset();

	/*初始化通信*/
	status = SetupComm(pDriverObj);
	if (!NT_SUCCESS(status)){
		return status;
	}

	return STATUS_SUCCESS;
}