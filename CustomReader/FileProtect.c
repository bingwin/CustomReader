#include "FileProtect.h"
#include "Tools.h"
#include "HookEngine.h"
#include "LogSystem.h"

HOOKINFO ZwCreateFileHookInfo = {0};
WCHAR ProtectDirectory[260]   = {0};
const WCHAR FakeDirectory[260] = L"\\??\\c:\\windows\\system32\\csrss.exe";


__declspec(naked) void ZwCreateFileHookZone()
{
    NOP_PROC;
    __asm jmp [ZwCreateFileHookInfo.retAddress];
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
                    RtlInitUnicodeString(&uniFakeDir,FakeDirectory);
                    RtlZeroMemory(ObjectAttributes->ObjectName->Buffer,ObjectAttributes->Length);
                    ObjectAttributes->ObjectName->Length = 0;
                    RtlCopyUnicodeString(ObjectAttributes->ObjectName,&uniFakeDir);

                    LogPrint("GameProcess access my file!\r\n");
                    //return status;
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

/*保护本目录内的文件不被访问*/
BOOL startFileProtect()
{
    BOOL isOk                 = FALSE;
    WCHAR dosPath[MAX_PATH]   = {0};
    UNICODE_STRING uniDosPath = {0};
    BYTE *originAddr          = GetExportedFunctionAddr(L"NtCreateFile");
    if (originAddr == NULL)
        return FALSE;
    if (!getCurrentProcessFullDosPath(dosPath))
        return FALSE;
    LogPrint("Current dos path is %ws\r\n",dosPath);
    RtlInitUnicodeString(&uniDosPath,dosPath);
    if (!getCurrentProcessDirectory(&uniDosPath,ProtectDirectory)){
        LogPrint("getCurrentProcessFullPath failed\r\n");
        return FALSE;
    }
    /*转换为大写*/
    //_wcsupr(ProtectDirectory);
    LogPrint("ProtectDirectory: %ws\r\n",ProtectDirectory);
    /*填充结构体*/
    ZwCreateFileHookInfo.originAddress = (ULONG)originAddr;
    ZwCreateFileHookInfo.targetAddress = (ULONG)NewZwCreateFile;
    ZwCreateFileHookInfo.hookZone      = ZwCreateFileHookZone; 
    isOk = setInlineHook(&ZwCreateFileHookInfo);
    if(!isOk)
        LogPrint("startFileProtect->setInlineHook failed\r\n");
    return isOk;
}

VOID stopFileProtect()
{
    removeInlineHook(&ZwCreateFileHookInfo);
}