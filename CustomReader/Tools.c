#include "Tools.h"
#include "Version.h"
#include "LogSystem.h"
extern STRUCT_OFFSET gStructOffset;
extern WIN_VER_DETAIL gWinVersion;

#define GAME_PROCESS_COUNT  (4)
char GameProcessName[GAME_PROCESS_COUNT][20]={"TenSafe_1.exe","DNF.exe","TASLogin.exe","Client.exe"};
//
//根据PID 查找匹配 进程名
//
NTSTATUS LookupNameByProcessId(
    IN DWORD ProcessId,
    OUT CHAR * szProcessName
    )
{ 
    NTSTATUS status                 = STATUS_UNSUCCESSFUL;
    ULONG ulCount                   = 0;
    PLIST_ENTRY	pActiveProcessList  = NULL;
    ULONG ulCurrentProcess          = 0;
    ULONG ulNextProcess             = 0;
    ULONG ulPid                     = 0;
    PCHAR szImageName               = NULL;  

    if (KeGetCurrentIrql() > PASSIVE_LEVEL){
        return STATUS_UNSUCCESSFUL;
    }

    ulCurrentProcess    = (ULONG)PsGetCurrentProcess();
    ulNextProcess       = ulCurrentProcess;
    __try{
        do {
            if ((ulCount >= 1) && (ulNextProcess == ulCurrentProcess)){
                status = STATUS_NOT_FOUND;
                break;
            }
            /*进程PID对比查找*/
            ulPid       = *(ULONG *)(ulCurrentProcess + gStructOffset.EProcessUniqueProcessId);
            if (ulPid == ProcessId){
                /*拷贝进程名*/
                szImageName = PsGetProcessImageFileName((PEPROCESS)ulCurrentProcess);
                /*为什么是 16？，因为EPROCESS中那个成员就是个 char[16]的数组*/
                RtlCopyMemory(szProcessName,szImageName,16);
                status  = STATUS_SUCCESS;
                break;
            }
            pActiveProcessList = (PLIST_ENTRY)(ulCurrentProcess + gStructOffset.EProcessActiveProcessLinks);
            ulCurrentProcess   = (ULONG)pActiveProcessList->Flink - gStructOffset.EProcessActiveProcessLinks;
            ulCount++;
        } while (TRUE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_NOT_FOUND;
    }
    return status;
}

NTSTATUS LookupProcessByProcessId(
    IN DWORD ProcessId,
    OUT PEPROCESS *Eprocess
    )
{
    NTSTATUS status                 = STATUS_UNSUCCESSFUL;
    ULONG ulCount                   = 0;
    PLIST_ENTRY	pActiveProcessList  = NULL;
    ULONG ulCurrentProcess          = 0;
    ULONG ulNextProcess             = 0;
    ULONG ulPid                     = 0; 

    if (KeGetCurrentIrql() > PASSIVE_LEVEL){
        return STATUS_UNSUCCESSFUL;
    }

    ulCurrentProcess    = (ULONG)PsGetCurrentProcess();
    ulNextProcess       = ulCurrentProcess;
    __try{
        do {
            if ((ulCount >= 1) && (ulNextProcess == ulCurrentProcess)){
                status = STATUS_NOT_FOUND;
                break;
            }
            /*进程PID对比查找*/
            ulPid       = *(ULONG *)(ulCurrentProcess + gStructOffset.EProcessUniqueProcessId);
            if (ulPid == ProcessId){
                *Eprocess = (PEPROCESS)ulCurrentProcess;
                status  = STATUS_SUCCESS;
                break;
            }
            pActiveProcessList = (PLIST_ENTRY)(ulCurrentProcess + gStructOffset.EProcessActiveProcessLinks);
            ulCurrentProcess   = (ULONG)pActiveProcessList->Flink - gStructOffset.EProcessActiveProcessLinks;
            ulCount++;
        } while (TRUE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_NOT_FOUND;
    }
    return status;
}

//
//根据进程名找到进程对象
//
NTSTATUS LookupProcessByName(IN CHAR *ProcessName,OUT PEPROCESS *Eprocess)
{
    NTSTATUS status                 = STATUS_UNSUCCESSFUL;
    ULONG ulCount                   = 0;
    PLIST_ENTRY	pActiveProcessList  = NULL;
    ULONG ulCurrentProcess          = 0;
    ULONG ulNextProcess             = 0;
    CHAR szImageName[100]; 
    CHAR *szProcessName             = NULL;

    ulCurrentProcess    = (ULONG)PsGetCurrentProcess();
    ulNextProcess       = ulCurrentProcess;
    __try{

        memset(szImageName,0,sizeof(szImageName));
        memcpy(szImageName,ProcessName,16);
        do {
            if ((ulCount >= 1) && (ulNextProcess == ulCurrentProcess)){
                status = STATUS_NOT_FOUND;
                break;
            }
            /*进程名对比查找*/
            szProcessName   = PsGetProcessImageFileName((PEPROCESS)ulCurrentProcess);
            if (_stricmp(szProcessName,szImageName) == 0){
                
                *Eprocess   = (PEPROCESS)ulCurrentProcess;
                status      = STATUS_SUCCESS;
                break;
            }
            pActiveProcessList = (PLIST_ENTRY)(ulCurrentProcess + gStructOffset.EProcessActiveProcessLinks);
            ulCurrentProcess   = (ULONG)pActiveProcessList->Flink - gStructOffset.EProcessActiveProcessLinks;
            ulCount++;
        } while (TRUE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER){
        status = STATUS_NOT_FOUND;
    }
    return status;
}

BYTE* GetExportedFunctionAddr(WCHAR *FunctionName)
{
    UNICODE_STRING uniFunctionName = {0};
    RtlInitUnicodeString(&uniFunctionName,FunctionName);
    return (BYTE*)MmGetSystemRoutineAddress(&uniFunctionName);
}


__inline ULONG CR4()
{
	// mov eax, cr4
	__asm _emit 0x0F __asm _emit 0x20 __asm _emit 0xE0
}
VALIDITY_CHECK_STATUS MmIsAddressValidExNotPae(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS  Return = VCS_INVALID;
	MMPTE* Pde;
	MMPTE* Pte;
	MMPTE pte;

	Pde = MiGetPdeAddress(Pointer);

	//KdPrint(("PDE is 0x%08x\n", Pde));
	if( Pde->u.Hard.Valid )
	{
		//KdPrint(("PDE entry is valid, PTE PFN=%08x\n", Pde->u.Hard.PageFrameNumber));

		Pte = MiGetPteAddress(Pointer);

		//KdPrint(("PTE is 0x%08x\n", Pte));
		if( Pte->u.Hard.Valid )
		{
			//KdPrint(("PTE entry is valid, PFN=%08x\n", Pte->u.Hard.PageFrameNumber));
			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			//KdPrint(("Got invalid PTE [%08x]: Proto=%d,Transition=%d,Protection=0x%x,PageFilePFN=0x%x\n",
			//	pte.u.Long,
			//	pte.u.Soft.Prototype,
			//	pte.u.Soft.Transition,
			//	pte.u.Soft.Protection,
			//	pte.u.Soft.PageFileHigh));

			if( pte.u.Long )
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					//KdPrint(("PTE entry is not valid, points to prototype PTE.\n"));

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page. Consider it invalid.
						//

						//KdPrint(("PTE entry is not valid, points to transition page.\n"));

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						//KdPrint(("PTE entry is not valid, points to demand-zero page.\n"));

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							//KdPrint(("PTE entry is not valid, VA is paged out (PageFile offset=%08x)\n",
							//	pte.u.Soft.PageFileHigh));

							Return = VCS_PAGEDOUT;
						}
						else
						{
							//KdPrint(("PTE entry is not valid, Refault\n"));
						}
					}
				}
			}
			else
			{
				//KdPrint(("PTE entry is completely invalid\n"));
			}
		}
	}
	else
	{
		//KdPrint(("PDE entry is not valid\n"));
	}

	return Return;
}
VALIDITY_CHECK_STATUS MmIsAddressValidExPae(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS Return = VCS_INVALID;
	MMPTE_PAE* Pde;
	MMPTE_PAE* Pte;
	MMPTE_PAE pte;

	Pde = MiGetPdeAddressPae(Pointer);

	//KdPrint(("PDE is at 0x%08x\n", Pde));
	if( Pde->u.Hard.Valid )
	{
		//KdPrint(("PDE entry is valid, PTE PFN=%08x\n", Pde->u.Hard.PageFrameNumber));

		if( Pde->u.Hard.LargePage != 0 )
		{
			//
			// This is a large 2M page
			//

			//KdPrint(("! PDE points to large 2M page\n"));

			Pte = Pde;
		}
		else
		{
			//
			// Small 4K page
			//

			// Get its PTE
			Pte  = MiGetPteAddressPae(Pointer);
		}

		//KdPrint(("PTE is at 0x%08x\n", Pte));
		if( Pte->u.Hard.Valid )
		{
			//KdPrint(("PTE entry is valid, PFN=%08x\n", Pte->u.Hard.PageFrameNumber));

			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			//KdPrint(("Got invalid PTE [%08x%08x]\n", pte.u.Long.HighPart, pte.u.Long.LowPart));

			if( pte.u.Long.LowPart == 0 )
			{
				//KdPrint(("PTE entry is completely invalid (page is not committed or is within VAD tree)\n"));
			}
			else
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					// 					//KdPrint(("PTE entry is not valid, points to prototype PTE. Protection=%x[%s], ProtoAddress=%x\n",
					// 						(ULONG)pte.u.Proto.Protection,
					// 						MiPageProtectionString((UCHAR)pte.u.Proto.Protection),
					// 						(ULONG)pte.u.Proto.ProtoAddress));

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page.
						//

						// 						//KdPrint(("PTE entry is not valid, points to transition page. PFN=%x, Protection=%x[%s]\n",
						// 							(ULONG)pte.u.Trans.PageFrameNumber,
						// 							(ULONG)pte.u.Trans.Protection,
						// 							MiPageProtectionString((UCHAR)pte.u.Trans.Protection)));

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						// 						//KdPrint(("PTE entry is not valid, points to demand-zero page. Protection=%x[%s]\n",
						// 							(ULONG)pte.u.Soft.Protection,
						// 							MiPageProtectionString((UCHAR)pte.u.Soft.Protection)));

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							// 							//KdPrint(("PTE entry is not valid, VA is paged out. PageFile Offset=%08x, Protection=%x[%s]\n",
							// 								(ULONG)pte.u.Soft.PageFileHigh,
							// 								(ULONG)pte.u.Soft.Protection,
							// 								MiPageProtectionString((UCHAR)pte.u.Soft.Protection)));

							Return = VCS_PAGEDOUT;
						}
						else
						{
							//KdPrint(("PTE entry is not valid, Refault\n"));
						}
					}
				}
			}
		}
	}
	else
	{
		//KdPrint(("PDE entry is not valid\n"));
	}

	return Return;
}
VALIDITY_CHECK_STATUS MiIsAddressValidEx(
	IN PVOID Pointer
	)
{
	if( CR4() & PAE_ON ) {
		return MmIsAddressValidExPae(Pointer);
	}
	else {
		return MmIsAddressValidExNotPae(Pointer);
	}
}
BOOL MmIsAddressValidEx(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS MmRet;
	ULONG ulTry;

	if (!ARGUMENT_PRESENT(Pointer) ||
		!Pointer){
		return FALSE;
	}
	/*
	//VCS_TRANSITION、VCS_PAGEDOUT内存居然是这样子~~擦~

	lkd> dd f8ad5ad8
	f8ad5ad8  ???????? ???????? ???????? ????????
	f8ad5ae8  ???????? ???????? ???????? ????????
	f8ad5af8  ???????? ???????? ???????? ????????
	f8ad5b08  ???????? ???????? ???????? ????????
	f8ad5b18  ???????? ???????? ???????? ????????
	f8ad5b28  ???????? ???????? ???????? ????????
	f8ad5b38  ???????? ???????? ???????? ????????
	f8ad5b48  ???????? ???????? ???????? ????????
	*/
	MmRet = MiIsAddressValidEx(Pointer);
	if (MmRet != VCS_VALID){
		return FALSE;
	}
	return TRUE;
}
/************************************************************************/
//对源地址的数据进行安全拷贝，再对拷贝后的数据进行操作
//
/************************************************************************/
NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size)
{
	PMDL  pSrcMdl, pDstMdl;
	PUCHAR pSrcAddress, pDstAddress;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	ULONG r;
	BOOL bInit = FALSE;

	pSrcMdl = IoAllocateMdl(SrcAddr, Size, FALSE, FALSE, NULL);
	if (MmIsAddressValidEx(pSrcMdl))
	{
		MmBuildMdlForNonPagedPool(pSrcMdl);
		pSrcAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pSrcMdl, NormalPagePriority);
		if (MmIsAddressValidEx(pSrcAddress))
		{
			pDstMdl = IoAllocateMdl(DstAddr, Size, FALSE, FALSE, NULL);
			if (MmIsAddressValidEx(pDstMdl))
			{
				__try
				{
					MmProbeAndLockPages(pDstMdl, KernelMode, IoWriteAccess);
					pDstAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pDstMdl, NormalPagePriority);
					if (MmIsAddressValidEx(pDstAddress))
					{
						RtlZeroMemory(pDstAddress,Size);
						RtlCopyMemory(pDstAddress, pSrcAddress, Size);
						st = STATUS_SUCCESS;
					}
					MmUnlockPages(pDstMdl);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{                 
					if (pDstMdl) MmUnlockPages(pDstMdl);

					if (pDstMdl) IoFreeMdl(pDstMdl);

					if (pSrcMdl) IoFreeMdl(pSrcMdl);

					return GetExceptionCode();
				}
				IoFreeMdl(pDstMdl);
			}
		}            
		IoFreeMdl(pSrcMdl);
	}
	return st;
}

//
//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放
//
NTSTATUS querySymbolicLink(
    IN PUNICODE_STRING SymbolicLinkName,
    OUT PUNICODE_STRING LinkTarget
    )                                  
{
    OBJECT_ATTRIBUTES	oa		= {0};
    NTSTATUS			status	= 0;
    HANDLE				handle	= NULL;

    InitializeObjectAttributes(
        &oa, 
        SymbolicLinkName,
        OBJ_CASE_INSENSITIVE,
        0, 
        0);

    status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
    if (!NT_SUCCESS(status))
        return status;

    LinkTarget->MaximumLength = MAX_PATH * sizeof(WCHAR);
    LinkTarget->Length = 0;
    LinkTarget->Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength,'ILVV');
    if (!LinkTarget->Buffer){
        ZwClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);
    status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
    ZwClose(handle);

    if (!NT_SUCCESS(status))
        ExFreePool(LinkTarget->Buffer);

    return status;
}

//输入\\Device\\harddiskvolume1
//输出C:盘符
//DosName.Buffer的内存记得释放

NTSTATUS __stdcall
    queryVolumeByDeviceName(
    IN PUNICODE_STRING device,
    OUT PUNICODE_STRING volume
    )

    /*++

    Routine Description:

    This routine returns a valid DOS path for the given device object.
    This caller of this routine must call ExFreePool on DosName->Buffer
    when it is no longer needed.

    Arguments:

    VolumeDeviceObject - Supplies the volume device object.
    DosName - Returns the DOS name for the volume
    Return Value:

    NTSTATUS

    --*/

{
    NTSTATUS				status					= 0;
    UNICODE_STRING			driveLetterName			= {0};
    WCHAR					driveLetterNameBuf[128] = {0};
    WCHAR					c						= L'\0';
    WCHAR					DriLetter[3]			= {0};
    UNICODE_STRING			linkTarget				= {0};

    for (c = L'A'; c <= L'Z'; c++){

        RtlInitEmptyUnicodeString(&driveLetterName,driveLetterNameBuf,sizeof(driveLetterNameBuf));
        RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
        DriLetter[0] = c;
        DriLetter[1] = L':';
        DriLetter[2] = 0;
        RtlAppendUnicodeToString(&driveLetterName,DriLetter);

        status = querySymbolicLink(&driveLetterName, &linkTarget);
        if (!NT_SUCCESS(status))
            continue;

        if (RtlEqualUnicodeString(&linkTarget, device, TRUE)){
            ExFreePool(linkTarget.Buffer);
            break;
        }
        ExFreePool(linkTarget.Buffer);
    }

    if (c <= L'Z'){
        volume->Buffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, 3*sizeof(WCHAR), 'ILVV');
        if (!volume->Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        volume->MaximumLength  = 6;
        volume->Length         = 4;
        *volume->Buffer        = c;
        *(volume->Buffer+ 1)   = ':';
        *(volume->Buffer+ 2)   = 0;

        return STATUS_SUCCESS;
    }

    return status;
} 

//c:\\windows\\hi.txt<--\\device\\harddiskvolume1\\windows\\hi.txt
BOOL __stdcall convertDevicePathToDosPath(IN WCHAR *devicePath,OUT WCHAR *dosPath)
{
    UNICODE_STRING		uniDevicePath   = {0};
    UNICODE_STRING		uniDosPath      = {0};
    UNICODE_STRING		uniVolume       = {0};//盘符

    WCHAR				*pPath          = NULL;
    ULONG				i               = 0;
    ULONG				ulSepNum        = 0;


    if (dosPath == NULL ||
        devicePath == NULL || 
        _wcsnicmp(devicePath, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume"))!=0)
        return FALSE;

    uniDosPath.Buffer        = dosPath;
    uniDosPath.Length        = 0;
    uniDosPath.MaximumLength = sizeof(WCHAR)*MAX_PATH;

    while(devicePath[i]!=L'\0'){

        if (devicePath[i] == L'\0')
            break;
        if (devicePath[i] == L'\\')
            ulSepNum++;
        if (ulSepNum == 3){
            devicePath[i] = UNICODE_NULL;
            pPath = &devicePath[i+1];
            break;
        }
        i++;
    }

    if (pPath == NULL)
        return FALSE;

    RtlInitUnicodeString(&uniDevicePath, devicePath);

    if (!NT_SUCCESS(queryVolumeByDeviceName(&uniDevicePath, &uniVolume)))
        return FALSE;

    RtlCopyUnicodeString(&uniDosPath, &uniVolume);
    RtlAppendUnicodeToString(&uniDosPath, L"\\");
    RtlAppendUnicodeToString(&uniDosPath, pPath);

    ExFreePool(uniVolume.Buffer);

    return TRUE;
}
//
//查询盘符对应的设备名，buffer由调用者提供
// C -> \\device\\harddiskvolume1
//
NTSTATUS __stdcall queryDeviceNameByVolume(WCHAR volume, WCHAR * device, USHORT size)
{
    WCHAR symLinkName[7]            = L"\\??\\C:";
    UNICODE_STRING uniSymLinkName   = {0};
    UNICODE_STRING uniDeviceName    = {0};
    UNICODE_STRING uniTargetDevice  = {0};    
    NTSTATUS status                 = STATUS_UNSUCCESSFUL;

    RtlInitUnicodeString(&uniSymLinkName, symLinkName);

    symLinkName[4] = volume;

    uniTargetDevice.Buffer        = device;
    uniTargetDevice.Length        = 0;
    uniTargetDevice.MaximumLength = size;

    status = querySymbolicLink(&uniSymLinkName, &uniDeviceName);
    if (NT_SUCCESS(status)){
        RtlCopyUnicodeString(&uniTargetDevice, &uniDeviceName);
        ExFreePool(uniDeviceName.Buffer);
    }
    return status;

}

//\\??\\c:\\windows\\hi.txt-->\\device\\harddiskvolume1\\windows\\hi.txt
BOOL __stdcall convertSymLinkPathToDevicePath(WCHAR * symPath, WCHAR * devicePath)
{
    UNICODE_STRING uniVolume = {0};
    WCHAR volume[MAX_PATH]   = L"";
    WCHAR tmp[MAX_PATH]      = L"";
    WCHAR chVolume           = L'\0';
    WCHAR * pPath            = NULL;
    int i = 0;


    RtlStringCbCopyW(tmp, MAX_PATH * sizeof(WCHAR), symPath);

    for(i = 1; i < MAX_PATH - 1; i++){
        if(tmp[i] == L':'){
            pPath    = &tmp[(i + 1) % MAX_PATH];
            chVolume = tmp[i - 1];
            break;
        }
    }

    if(pPath == NULL)
        return FALSE;

    if(chVolume == L'?'){
        uniVolume.Length        = 0;
        uniVolume.MaximumLength = MAX_PATH * sizeof(WCHAR);
        uniVolume.Buffer        = devicePath;
        RtlAppendUnicodeToString(&uniVolume, L"\\Device\\HarddiskVolume?");
        RtlAppendUnicodeToString(&uniVolume, pPath);
        return TRUE;
    }
    else if(queryDeviceNameByVolume(chVolume, volume, MAX_PATH * sizeof(WCHAR))){
        uniVolume.Length = 0;
        uniVolume.MaximumLength = MAX_PATH * sizeof(WCHAR);
        uniVolume.Buffer = devicePath;
        RtlAppendUnicodeToString(&uniVolume, volume);
        RtlAppendUnicodeToString(&uniVolume, pPath);
        return TRUE;
    }

    return FALSE;
}

//
//获取当前应用程序映像全路径，调用者用完之后需要free buffer
//以\Device\HarddiskVolumeX\开始
//
NTSTATUS getCurrentProcessFullDevicePath(OUT PUNICODE_STRING *path)
{
    NTSTATUS status;
    KIRQL currentIrql;
    PFN_ZWQUERYINFORMATINPROCESS pfnZwQueryInformationProcess;
    ULONG retLength;
    PVOID buffer;
    currentIrql = KeGetCurrentIrql();
    if(currentIrql != PASSIVE_LEVEL)
        return STATUS_UNSUCCESSFUL;

    pfnZwQueryInformationProcess = (PFN_ZWQUERYINFORMATINPROCESS)GetExportedFunctionAddr(L"ZwQueryInformationProcess");
    if(!pfnZwQueryInformationProcess)
        return STATUS_UNSUCCESSFUL;

    status = pfnZwQueryInformationProcess(ZwCurrentProcess(),
        ProcessImageFileName,
        NULL,
        0,
        &retLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH){
        LogPrint("ZwQueryInformationProcess->(status != STATUS_INFO_LENGTH_MISMATCH)\r\n");
        return status;
    }
    /*获取到了buffer的长度*/
    buffer = ExAllocatePoolWithTag(PagedPool,retLength,'ILVV');
    if (!buffer){
        LogPrint("getCurrentProcessFullPathName->ExAllocatePoolWithTag failed\r\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = pfnZwQueryInformationProcess(ZwCurrentProcess(),
        ProcessImageFileName,
        buffer,
        retLength,
        &retLength);
    if (!NT_SUCCESS(status)){
        ExFreePool(buffer);
        LogPrint("ZwQueryInformationProcess failed,error: 0x%8x\r\n",status);
        return status;
    }
    *path = (PUNICODE_STRING)buffer;
    return status;
}

//
//获取当前程序dos全路径
//
BOOL __stdcall getCurrentProcessFullDosPath(OUT WCHAR *dosPath)
{
    NTSTATUS status;
    PUNICODE_STRING uniDevicePath = NULL;
    status = getCurrentProcessFullDevicePath(&uniDevicePath);
    if (!NT_SUCCESS(status))
        return FALSE;
    /*转换为dos path*/
    if(!convertDevicePathToDosPath(uniDevicePath->Buffer,dosPath)){
        ExFreePool((PVOID)uniDevicePath);
        return FALSE;
    }
    ExFreePool((PVOID)uniDevicePath);
    return TRUE;
}

//
//从进程全路径中获取进程所在的目录名，去除 \ImageName
//
BOOL getCurrentProcessDirectory(IN PUNICODE_STRING fullPathName,OUT WCHAR *fullPath)
{
    WCHAR *first;
    WCHAR *last;
    first = fullPathName->Buffer;
    last  = fullPathName->Buffer + fullPathName->Length / sizeof(WCHAR) - 1;

    while(*last != L'\\' && last != first)
        last--;
    if (*last == L'\\' && last != first){
        //把 \\ 之前的字符串copy出去
        ULONG length = (ULONG)last - (ULONG)first;
        RtlCopyMemory(fullPath,first,length);
        return TRUE;
    }
    return FALSE;
}

BOOL isGameProcess()
{
    BOOL retOk               = FALSE;
    int i;
    PCHAR currentProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (currentProcessName){
        for (i = 0; i < GAME_PROCESS_COUNT; i++){
            if (_stricmp(currentProcessName,GameProcessName[i]) == 0){
                retOk = TRUE;
                break;
            }
        }
    }
    return retOk;
}


//
//
//
//PVOID GetMmCopyVirtualMemoryAddress(BYTE *NtReadVirtualMemoryAddress)
//{
    /*区分xp和win7*/
    //if (gWinVersion == WINDOWS_VERSION_XP){
//nt!NtReadVirtualMemory+0xb8:
//805aa93e 8d45d8          lea     eax,[ebp-28h]
//805aa941 50              push    eax
//805aa942 ff75e0          push    dword ptr [ebp-20h]
//805aa945 56              push    esi
//805aa946 ff7510          push    dword ptr [ebp+10h]
//805aa949 ff7744          push    dword ptr [edi+44h]
//805aa94c ff750c          push    dword ptr [ebp+0Ch]
//805aa94f ff75dc          push    dword ptr [ebp-24h]
//805aa952 e891feffff      call    nt!MmCopyVirtualMemory (805aa7e8)
//805aa957 8945e4          mov     dword ptr [ebp-1Ch],eax
//805aa95a 8b4ddc          mov     ecx,dword ptr [ebp-24h]
//805aa95d e83092f7ff      call    nt!ObfDereferenceObject (80523b92)
    //}
    //else if (gWinVersion == WINDOWS_VERSION_7_7600_UP || gWinVersion == WINDOWS_VERSION_7_7000){
        //特征码 : 6a 20 33 c0 50 50 6a 01 50 56 e8
        //会搜出 两个来，第一个就是
    //}
    //BYTE *p;
    //ULONG i;
    //ULONG ulFunctionSize;
    //PVOID Address   = NULL;
    //p               = NtReadVirtualMemoryAddress;
    //ulFunctionSize  = SizeOfProc(p);
    //if (ulFunctionSize <= 0){
    //    return NULL;
    //}

    //for (i = 0;i<ulFunctionSize;i++,p++){
    //    if (*(p - 1) == 0xe8 &&
    //        *(p - 3) == 0x75 &&
    //        *(p - 4) == 0xff &&
    //        *(p - 6) == 0x75 &&
    //        *(p - 7) == 0xff ){
    //            Address =(PVOID)((ULONG)(p - 1) +*(ULONG*)p +5);
    //            break;
    //    }
    //}
    //return Address;
//}

BOOLEAN ValidateUnicodeString(PUNICODE_STRING usStr)
{
    ULONG i;

    __try
    {
        if (!MmIsAddressValid(usStr))
        {
            return FALSE;
        }
        if (usStr->Buffer == NULL || usStr->Length == 0)
        {
            return FALSE;
        }
        for (i = 0; i < usStr->Length; i++)
        {
            if (!MmIsAddressValid((PUCHAR)usStr->Buffer + i))
            {
                return FALSE;
            }
        }

    }__except(EXCEPTION_EXECUTE_HANDLER){

    }
    return TRUE;
}

BOOL myRtlStrUnicodeString(PUNICODE_STRING src,PUNICODE_STRING sub)
{
    PWSTR p1;
    PWSTR pSrcTail;
    PWSTR pSubTail;
    ULONG srcLength;
    ULONG subLength;
    if(!src || !sub)
        return FALSE;
    if (src->Length == 0){
        return FALSE;
    }
    if(sub->Length == 0)
        return TRUE;

    p1 = src->Buffer;
    srcLength = src->Length >> 1;
    subLength = sub->Length >> 1;
    pSrcTail  = src->Buffer + srcLength - 1;
    pSubTail  = sub->Buffer + subLength - 1;

    while(p1 <= pSrcTail){
        PWSTR s1;
        PWSTR s2;
        s1 = p1;
        s2 = sub->Buffer;
        while(s1 <= pSrcTail && s2 <= pSubTail && !(*s1 - * s2)){
            s1++;
            s2++;
        }
        if (s2 > pSubTail){
            return TRUE;
        }
        p1++;
    }
    return FALSE;
}