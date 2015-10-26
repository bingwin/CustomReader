#include "FileProtect.h"
#include "Tools.h"
#include "HookEngine.h"
#include "LogSystem.h"

HOOKINFO NtCreateFileHookInfo = {0};
WCHAR ProtectDirectory[260]   = {0};
const WCHAR FakeDirectory[260] = L"\\??\\c:\\windows\\system32\\csrss.exe";

PDRIVER_DISPATCH gOriginNtfsCreateDispatch;
PDRIVER_DISPATCH gOriginNtfsReadDispatch;


__declspec(naked) void ZwCreateFileHookZone()
{
    NOP_PROC;
    __asm jmp [NtCreateFileHookInfo.retAddress];
}
/*代理函数*/
NTSTATUS __stdcall 
    NewZwCreateFile(
    __out PHANDLE  FileHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __out PIO_STATUS_BLOCK  IoStatusBlock,
    __in_opt PLARGE_INTEGER  AllocationSize,
    __in ULONG  FileAttributes,
    __in ULONG  ShareAccess,
    __in ULONG  CreateDisposition,
    __in ULONG  CreateOptions,
    __in_opt PVOID  EaBuffer,
    __in ULONG  EaLength
    )
{
    NTSTATUS status = STATUS_ACCESS_DENIED;
    UNICODE_STRING uniFakeDir = {0};
    PFN_ZWCREATEFILE pfnZwCreateFile = (PFN_ZWCREATEFILE)ZwCreateFileHookZone;
    if (isGameProcess()){
        //LogPrint("Current Process is GameProcess\r\n");
        /*通过 ObjectAttributes 解析文件路径*/
        if (ObjectAttributes){
            if (ObjectAttributes->ObjectName){
                /*跟保护路径进行对比*/
                if (wcsstr(ObjectAttributes->ObjectName->Buffer,ProtectDirectory)){
//                     RtlInitUnicodeString(&uniFakeDir,FakeDirectory);
//                     RtlZeroMemory(ObjectAttributes->ObjectName->Buffer,ObjectAttributes->Length);
//                     ObjectAttributes->ObjectName->Length = 0;
//                     RtlCopyUnicodeString(ObjectAttributes->ObjectName,&uniFakeDir);

                    LogPrint("GameProcess access my file!\r\n");
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }
    }
    return pfnZwCreateFile(FileHandle,
                            DesiredAccess,
                            ObjectAttributes,
                            IoStatusBlock,
                            AllocationSize,
                            FileAttributes,
                            ShareAccess,
                            CreateDisposition,
                            CreateOptions,
                            EaBuffer,EaLength);
}

//
//
//
BOOL HookNtCreateFile()
{
    BOOL bRetOk = FALSE;

    ULONG ulNtCreateFileAddr;
    ulNtCreateFileAddr = (ULONG)GetExportedFunctionAddr(L"NtCreateFile");

    if(ulNtCreateFileAddr == 0)
        return FALSE;
    /*填充结构体*/
    NtCreateFileHookInfo.originAddress = ulNtCreateFileAddr;
    NtCreateFileHookInfo.targetAddress = (ULONG)NewZwCreateFile;
    NtCreateFileHookInfo.hookZone      = ZwCreateFileHookZone;

    bRetOk = setInlineHook(&NtCreateFileHookInfo);
    if (!bRetOk)
        LogPrint("HookNtCreateFile failed\r\n");
    return bRetOk;
}


VOID UnhookNtCreateFile()
{

    removeInlineHook(&NtCreateFileHookInfo);

}




//
//要替换的ntfs的create函数
//
NTSTATUS __stdcall NtfsCreateDispatch(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    //变量的声明
    NTSTATUS status                     = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION IoStackLocation  = NULL;
    PFILE_OBJECT FileObject             = NULL;
    UNICODE_STRING ProtectDir           = {0};

    if (KeGetCurrentIrql() == PASSIVE_LEVEL){
        if (isGameProcess()){
            //进入到这个例程之后，因为我们是要关注文件
            IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

            if (!IoStackLocation){
                //我们就直接调用原始
                //这里就是刚才为什么要保存原始函数的原因
                goto _FunctionRet;
            }
            //取出这个文件对象成员
            //我们关心的是  +0x030 FileName         : _UNICODE_STRING
            FileObject = IoStackLocation->FileObject;
            if (FileObject == NULL){
                //如果文件对象为空，那么我们就直接返回原始函数
                goto _FunctionRet;
            }
            if (ValidateUnicodeString(&FileObject->FileName)){
                //查找是否时我们的目录
                RtlInitUnicodeString(&ProtectDir,ProtectDirectory);
                if (myRtlStrUnicodeString(&FileObject->FileName,&ProtectDir)){
                    //返回 失败
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
    }
_FunctionRet:
    //调用原始函数
    status = gOriginNtfsCreateDispatch(DeviceObject,Irp);
    return status;

}

NTSTATUS __stdcall NtfsReadDispatch(
    IN PDEVICE_OBJECT		DeviceObject,
    IN PIRP					Irp
    )
{
    //变量的声明
    NTSTATUS status                     = STATUS_UNSUCCESSFUL;
    PIO_STACK_LOCATION IoStackLocation  = NULL;
    PFILE_OBJECT FileObject             = NULL;
    UNICODE_STRING ProtectDir           = {0};

    if (KeGetCurrentIrql() == PASSIVE_LEVEL){
        if (isGameProcess()){
            //进入到这个例程之后，因为我们是要关注文件
            IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

            if (!IoStackLocation){
                //我们就直接调用原始
                //这里就是刚才为什么要保存原始函数的原因
                goto _FunctionRet;
            }
            //取出这个文件对象成员
            //我们关心的是  +0x030 FileName         : _UNICODE_STRING
            FileObject = IoStackLocation->FileObject;
            if (FileObject == NULL){
                //如果文件对象为空，那么我们就直接返回原始函数
                goto _FunctionRet;
            }
            if (ValidateUnicodeString(&FileObject->FileName)){
                //查找是否时我们的目录
                RtlInitUnicodeString(&ProtectDir,ProtectDirectory);
                if (myRtlStrUnicodeString(&FileObject->FileName,&ProtectDir)){
                    //返回 失败
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
    }
_FunctionRet:
    //调用原始函数
    status = gOriginNtfsReadDispatch(DeviceObject,Irp);
    return status;

}

BOOL HookNtfsCreateRead()
{
    NTSTATUS status;
    UNICODE_STRING uniNtfsName = {0};
    PDRIVER_OBJECT NtfsDriverObject;

    RtlInitUnicodeString(&uniNtfsName,L"\\FileSystem\\Ntfs");
    status = ObReferenceObjectByName(&uniNtfsName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
        		NULL,
		0,
		*IoDriverObjectType, //这个参数指明DriverObject
		KernelMode,				//内核模式
		NULL,
		(PVOID*)&NtfsDriverObject);
    if (!NT_SUCCESS(status)){
        LogPrint("HookNtfsCreate->ObReferenceObjectByName failed,status:0x%x\r\n",status);
        return FALSE;
    }

    /*替换create函数*/
    gOriginNtfsCreateDispatch = NtfsDriverObject->MajorFunction[IRP_MJ_CREATE];
    gOriginNtfsReadDispatch   = NtfsDriverObject->MajorFunction[IRP_MJ_READ];
    NtfsDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)NtfsCreateDispatch;
    NtfsDriverObject->MajorFunction[IRP_MJ_READ]   = (PDRIVER_DISPATCH)NtfsReadDispatch;
    ObDereferenceObject(NtfsDriverObject);
    return TRUE;
}


VOID RestoreNtfsCreateRead()
{
    NTSTATUS status;
    UNICODE_STRING uniNtfsName = {0};
    PDRIVER_OBJECT NtfsDriverObject;

    RtlInitUnicodeString(&uniNtfsName,L"\\FileSystem\\Ntfs");
    status = ObReferenceObjectByName(&uniNtfsName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
        NULL,
        0,
        *IoDriverObjectType, //这个参数指明DriverObject
        KernelMode,				//内核模式
        NULL,
        (PVOID*)&NtfsDriverObject);
    if (!NT_SUCCESS(status)){
        LogPrint("RestoreNtfsCreate->ObReferenceObjectByName failed,status:0x%x\r\n",status);
        return;
    }

    /*恢复原始函数*/
    NtfsDriverObject->MajorFunction[IRP_MJ_CREATE] = gOriginNtfsCreateDispatch;
    NtfsDriverObject->MajorFunction[IRP_MJ_READ]   = gOriginNtfsReadDispatch;
    ObDereferenceObject(NtfsDriverObject);
}

/*保护本目录内的文件不被访问，在当前进程下环境下运行*/
BOOL startFileProtect()
{
    BOOL isOk                 = FALSE;
    WCHAR dosPath[MAX_PATH]   = {0};
    WCHAR tmpDir[MAX_PATH]    = {0};
    UNICODE_STRING uniDosPath = {0};
    if (!getCurrentProcessFullDosPath(dosPath))
        return FALSE;
    LogPrint("Current dos path is %ws\r\n",dosPath);
    RtlInitUnicodeString(&uniDosPath,dosPath);
    if (!getCurrentProcessDirectory(&uniDosPath,tmpDir)){
        LogPrint("getCurrentProcessFullPath failed\r\n");
        return FALSE;
    }
    
    /*去除盘符 ，如 c: 两个字符*/
    //wcscpy(ProtectDirectory,&tmpDir[0]+2);
    wcscpy(ProtectDirectory,&tmpDir[0]);
    LogPrint("ProtectDirectory: %ws\r\n",ProtectDirectory);
    
    /*hook fsd create*/
    isOk = HookNtCreateFile();
    if (!isOk)
        LogPrint("HookNtCreateFile failed...\r\n");
    return isOk;
}

VOID stopFileProtect()
{
    UnhookNtCreateFile();
}