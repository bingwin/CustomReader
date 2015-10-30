// ctmrDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include "ctmrDll.h"
#include <tchar.h>
#include "resource.h"
#include <TlHelp32.h>
#include ".\\mhook-lib\\mhook.h"

/**/
#include "..\\CustomReader\\CommStruct.h"
#include "..\\CustomReader\\CtrlCmd.h"

#define STATUS_SUCCESS                          (0x00000000L) // ntsubauth
#define STATUS_UNSUCCESSFUL                     (0xC0000001L)
#define STATUS_ACCESS_DENIED                    (0xC0000022L)
/*驱动名称和驱动所在的路径*/
#define CTMR_NAME       "CtmrReader"
#define CTMR_PATH       ".\\CtmrReader.sys"

#define DEVICE_NAME     "\\\\.\\ReaderSymLink"

/*假的句柄值*/
#define FAKE_HANDLE         (0x87654321)
//关注的进程
DWORD gGamePid = 0;

HANDLE gGameHandle = INVALID_HANDLE_VALUE;

/*加密之后的*/
const char GameProcessName[20] = "ITM6n俻";
//char gProcessName[MAX_PATH+1];

PFN_ZWDEVICEIOCONTROLFILE pfnOriZwDeviceIoControlFile;
PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;
PFN_ZWQUERYVIRTUALMEMORY pfnOriZwQueryVirtualMemory;
//
//三个函数在SSDT表中的索引号
//
DWORD gZwOpenProcessIndex;
DWORD gZwReadVirtualMemoryIndex;
DWORD gZwWriteVirtualMemoryIndex;
DWORD gZwDeviceIoControlFileIndex;
DWORD gZwQueryVirtualMemoryIndex;

//
//通过进程名获取进程id
//
DWORD GetProcessIdByName(wchar_t * wszName);

BOOL __stdcall MyDeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode,
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
    );

/*xp下*/
//mov     eax, 115h       ; NtWriteVirtualMemory
//mov     edx, 7FFE0300h
//call    dword ptr [edx]
//retn    14h

/*WIN7 32下*/
//mov     eax, 18Fh       ; NtWriteVirtualMemory
//mov     edx, 7FFE0300h
//call    dword ptr [edx]
//retn    14h

inline void __cdecl DbgPrint(PCSTR format, ...) {
    va_list	args;
    va_start(args, format);
    int len = _vscprintf(format, args);
    if (len > 0) {
        len += (1 + 2);
        PSTR buf = (PSTR) malloc(len);
        if (buf) {
            len = vsprintf_s(buf, len, format, args);
            if (len > 0) {
                while (len && isspace(buf[len-1])) len--;
                buf[len++] = '\r';
                buf[len++] = '\n';
                buf[len] = 0;
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}
//
//简单的加密解密字符串函数
//
void SimpleEncryptString(const char *src,int len,char *dest)
{
    int i;
    for (i = 0; i < len; i++){
        *(dest+i) = *(src+i) + i + 5;
    }
}

void SimpleDecryptString(const char *src,int len,char *dest)
{
    int i;
    for (i = 0; i < len; i++){
        *(dest+i) = *(src+i) - i - 5;
    }
}

//
//释放指定的资源ID到指定的文件
//
BOOL _stdcall ReleaseResToFile(const char * lpszFilePath, DWORD dwResID, const char * resType)
{
    HMODULE hMod = GetModuleHandle(_T("ctmrDll.dll"));
    if (!hMod){
        OutputDebugStringA("GetModuleHandleW failed\r\n");
        return false;
    }
    HRSRC hSRC = FindResourceA(hMod, MAKEINTRESOURCEA(dwResID), resType);
    if (!hSRC){
        DbgPrint("FindResourceA failed : %d\r\n",GetLastError());
        return false;
    }
    DWORD dwSize    = 0;
    dwSize          = SizeofResource(hMod,hSRC);
    HGLOBAL hGloba  = LoadResource(hMod,hSRC);
    if (!hGloba){
        return false;
    }
    LPVOID lpBuffer = LockResource(hGloba);
    if (!lpBuffer){
        OutputDebugStringA("LockResource failed\r\n");
        return false;
    }
    HANDLE hFile    = CreateFileA(lpszFilePath,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE){
        OutputDebugStringA("CreateFileA failed\r\n");
        return false;
    }
    DWORD dwWriteReturn;
    if (!WriteFile(hFile,
        lpBuffer,
        dwSize,
        &dwWriteReturn,
        NULL))
    {
        OutputDebugStringA("WriteFile failed\r\n");
        CloseHandle(hFile);
        return false;
    }
    OutputDebugStringA("WriteFile ok!\r\n");
    CloseHandle(hFile);
    return true;
}
//
//加载驱动
//
BOOL _stdcall LoadDriver(const char * lpszDriverName,const char * lpszDriverPath)
{
    char szDriverImagePath[MAX_PATH] = {0};
    BOOL bRet                        = false;

    SC_HANDLE hServiceMgr            = NULL;//SCM管理器的句柄
    SC_HANDLE hServiceDDK            = NULL;//NT驱动程序的服务句柄
    //得到完整的驱动路径
    GetFullPathNameA(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

    //打开服务控制管理器
    hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

    if( hServiceMgr == NULL ){
        //OpenSCManager失败
        OutputDebugStringA( "OpenSCManager() Failed! \r\n" );
        bRet = FALSE;
        goto BeforeLeave;
    }
    else{
        ////OpenSCManager成功
        OutputDebugStringA( "OpenSCManager() ok ! \n" );  
    }

    //创建驱动所对应的服务
    hServiceDDK = CreateServiceA( hServiceMgr,
        lpszDriverName,         //驱动程序的在注册表中的名字  
        lpszDriverName,         // 注册表驱动程序的 DisplayName 值  
        SERVICE_ALL_ACCESS,     // 加载驱动程序的访问权限  
        SERVICE_KERNEL_DRIVER,  // 表示加载的服务是驱动程序  
        SERVICE_DEMAND_START,   // 注册表驱动程序的 Start 值  
        SERVICE_ERROR_IGNORE,   // 注册表驱动程序的 ErrorControl 值  
        szDriverImagePath,      // 注册表驱动程序的 ImagePath 值  
        NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
        NULL,  
        NULL,  
        NULL,  
        NULL);  

    DWORD dwRtn;
    //判断服务是否失败
    if( hServiceDDK == NULL ){  
        dwRtn = GetLastError();
        if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS ){  
            //由于其他原因创建服务失败
            OutputDebugStringA( "CreateService() Failed! \r\n" );  
            bRet = false;
            goto BeforeLeave;
        }  
        else{
            //服务创建失败，是由于服务已经创立过
            OutputDebugStringA( "CrateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
        }

        // 驱动程序已经加载，只需要打开  
        hServiceDDK = OpenServiceA( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
        if( hServiceDDK == NULL ){
            //如果打开服务也失败，则意味错误
            dwRtn = GetLastError();  
            OutputDebugStringA( "OpenService() Failed! \r\n" );  
            bRet = FALSE;
            goto BeforeLeave;
        }  
        else{
            OutputDebugStringA( "OpenService() ok ! \n" );
        }
    }  
    else{
        OutputDebugStringA( "CreateService() ok ! \n" );
    }

    //开启此项服务
    bRet = StartService( hServiceDDK, NULL, NULL );  
    if( !bRet ){  
        DWORD dwRtn = GetLastError();  
        if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING ){  
            DbgPrint("StartService() Failed,Err : 0x%x \r\n",dwRtn);
            bRet = false;
            goto BeforeLeave;
        }  
        else{  
            if( dwRtn == ERROR_IO_PENDING ){  
                //设备被挂住
                OutputDebugStringA( "StartService() Failed ERROR_IO_PENDING ! \r\n");
                bRet = false;
                goto BeforeLeave;
            }  
            else{  
                //服务已经开启
                OutputDebugStringA( "StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \r\n");
                bRet = false;
                goto BeforeLeave;
            }  
        }  
    }
    bRet = true;
    //离开前关闭句柄
BeforeLeave:
    if(hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if(hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}

//卸载驱动程序  
BOOL _stdcall UnloadDriver(const char * szSvrName )  
{
    BOOL bRet               = false;
    SC_HANDLE hServiceMgr   = NULL; //SCM管理器的句柄
    SC_HANDLE hServiceDDK   = NULL; //NT驱动程序的服务句柄
    SERVICE_STATUS SvrSta;
    //打开SCM管理器
    hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
    if( hServiceMgr == NULL ){
        //带开SCM管理器失败
        OutputDebugStringA( "OpenSCManager() Failed! \r\n");  
        bRet = false;
        goto BeforeLeave;
    }  
    else{
        //带开SCM管理器失败成功
        OutputDebugStringA( "OpenSCManager() ok ! \n" );  
    }
    //打开驱动所对应的服务
    hServiceDDK = OpenServiceA( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );  

    if( hServiceDDK == NULL ){
        //打开驱动所对应的服务失败
        OutputDebugStringA( "OpenService() Failed! \n");  
        bRet = false;
        goto BeforeLeave;
    }  
    else{  
        OutputDebugStringA( "OpenService() ok ! \n" );  
    }  
    //停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
    if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) ){  
        OutputDebugStringA( "ControlService() Failed!\n");  
    }  
    else{
        //打开驱动所对应的失败
        OutputDebugStringA( "ControlService() ok !\n" );  
    } 
    //动态卸载驱动程序。  
    if( !DeleteService( hServiceDDK ) )  
    {
        //卸载失败
        OutputDebugStringA( "DeleteSrevice() Failed!\n");  
    }  
    else{  
        //卸载成功
        OutputDebugStringA( "DelServer:deleteSrevice() ok !\n" );  
    }  

    bRet = true;
BeforeLeave:
    //离开前关闭打开的句柄
    if(hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if(hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;	
} 

HANDLE _stdcall OpenDevice()
{
    //测试驱动程序  
    HANDLE hDevice = CreateFileA(DEVICE_NAME,  
        GENERIC_WRITE | GENERIC_READ,  
        0,  
        NULL,  
        OPEN_EXISTING,  
        0,  
        NULL);  
    if( hDevice == INVALID_HANDLE_VALUE ){
        return NULL;
    }
    return hDevice;
} 

//
//发送csrss句柄
//
BOOL __stdcall SendOpenProcessParameter(HANDLE handle,DWORD ProcessId)
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    OPEN_PROCESS_PARAMETER opp  = {0};
    opp.dwCsrssHandle           = (DWORD)handle;
    opp.dwGamePid               = ProcessId;
    DWORD dwRet                 = 0;

    if(MyDeviceIoControl(hDevice,FC_SEND_OPEN_PROCESS_PARAMETER,&opp,sizeof(OPEN_PROCESS_PARAMETER),&opp,sizeof(OPEN_PROCESS_PARAMETER),&dwRet,NULL)){
        CloseHandle(hDevice);
        return true;
    }
    CloseHandle(hDevice);
    return false;
}

//
//通信测试函数
//
BOOL _stdcall CommTest()
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    COMMTEST ct                    = {0};
    ct.dwNtOpenProcessIndex        = gZwOpenProcessIndex;
    ct.dwNtReadVirtualMemoryIndex  = gZwReadVirtualMemoryIndex;
    ct.dwNtWriteVirtualMemoryIndex = gZwWriteVirtualMemoryIndex;
    DWORD dwRet                 = 0;
    if(MyDeviceIoControl(hDevice,FC_COMM_TEST,&ct,sizeof(COMMTEST),&ct,sizeof(COMMTEST),&dwRet,NULL)){
        if (ct.success){
            bRet = true;
        }
    }
    CloseHandle(hDevice);
    return bRet;
}

CTMR_API BOOL _cdecl IsDriverLoad()
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;

    DWORD dwRet                 = 0;
    if(MyDeviceIoControl(hDevice,FC_IS_DRIVER_LOAD,NULL,0,NULL,0,&dwRet,NULL)){
        bRet = true;
    }
    CloseHandle(hDevice);
    return bRet;
}

BOOL __stdcall avGetProcessName(NAMEINFO *pNameInfo)
{
    BOOL bRet       = false;
    DWORD dwRet     = 0;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    if (MyDeviceIoControl(hDevice,FC_GET_NAME_BY_ID,pNameInfo,sizeof(NAMEINFO),pNameInfo,sizeof(NAMEINFO),&dwRet,NULL)){
        bRet = true;
    }
    CloseHandle(hDevice);
    return bRet;
}

BOOL _stdcall avReadMemory(READMEM_INFO * PReadInfo)
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    DWORD dwRet     = 0;
    if (MyDeviceIoControl(hDevice,
        FC_READ_PROCESS_MEMORY,
        PReadInfo,
        sizeof(READMEM_INFO),
        PReadInfo,
        sizeof(READMEM_INFO),
        &dwRet,
        NULL))
    {
        bRet = true;
    }
    CloseHandle(hDevice);
    return bRet;
}

BOOL _stdcall avWriteMemory(WRITEMEM_INFO * PWriteInfo)
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;

    DWORD dwRet     = 0;
    if (MyDeviceIoControl(hDevice,
        FC_WRITE_PROCESS_MEMORY,
        PWriteInfo,
        sizeof(WRITEMEM_INFO),
        PWriteInfo,
        sizeof(WRITEMEM_INFO),
        &dwRet,
        NULL))
    {
        bRet = true;
    }
    CloseHandle(hDevice);

    return bRet;
}
//
//模拟ntdll中的函数
//
__declspec(naked) NTSTATUS NTAPI nakedZwDeviceIoControlFile(HANDLE  FileHandle,
    HANDLE           Event,
    PVOID  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
    )
{
    __asm
    {
        mov     eax, gZwDeviceIoControlFileIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    28h
    }
}

BOOL __stdcall MyDeviceIoControl(
    HANDLE       hDevice,
    DWORD        dwIoControlCode,
    LPVOID       lpInBuffer,
    DWORD        nInBufferSize,
    LPVOID       lpOutBuffer,
    DWORD        nOutBufferSize,
    LPDWORD      lpBytesReturned,
    LPOVERLAPPED lpOverlapped
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock = {0};
    status = nakedZwDeviceIoControlFile(hDevice,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize);
    if (status == STATUS_SUCCESS){
        *lpBytesReturned = ioStatusBlock.Information;
        return true;
    }
    return false;
}

__declspec(naked) NTSTATUS NTAPI  nakedZwOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId)
{
    __asm
    {
        mov     eax, gZwOpenProcessIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    10h
    }
}

__declspec(naked) NTSTATUS NTAPI nakedZwReadVirtualMemory(	
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    __asm
    {
        mov     eax, gZwReadVirtualMemoryIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    14h
    }
}

__declspec(naked) NTSTATUS NTAPI nakedZwWriteVirtualMemory(
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToWrite,
    PSIZE_T 	NumberOfBytesWritten )
{
    __asm
    {
        mov     eax, gZwWriteVirtualMemoryIndex
        mov     edx, 7FFE0300h
        call    dword ptr [edx]
        retn    14h
    }
}

//
//新的nt函数
//
NTSTATUS NTAPI  avZwOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId)
{
    LONG status;
    if (ClientId){
        if (ClientId->UniqueProcess){
            /*通过pid获取进程名字*/
            NAMEINFO ni = {0};
            ni.dwPid    = (DWORD)ClientId->UniqueProcess;
            if (avGetProcessName(&ni)){
                /*解密*/
                char DecryptString[20]={0};
                SimpleDecryptString(GameProcessName,strlen(GameProcessName),DecryptString);
                if (_stricmp(DecryptString,ni.ProcessName) == 0){
                    /*记录游戏pid*/
                    gGamePid = (DWORD)ClientId->UniqueProcess;
                    //*ProcessHandle = (HANDLE)FAKE_HANDLE;
                    //SendOpenProcessParameter((HANDLE)0,gGamePid);
                    //return STATUS_SUCCESS;
                    }
                }
            }
        }
    status = nakedZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
    if (status == STATUS_SUCCESS){
        /*记录游戏进程句柄*/
        gGameHandle = *ProcessHandle;
    }
    return status;
}

NTSTATUS NTAPI  avZwReadVirtualMemory(	
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToRead,
    PSIZE_T 	NumberOfBytesRead )
{
    char DecryptString[20] = {0};
    if (ProcessHandle == gGameHandle){

        /*如果要读取的字节大于 MAX_BUFFER * 2的话，不能读取*/
        if (NumberOfBytesToRead > PAGE_SIZE){
            return STATUS_UNSUCCESSFUL;
        }
        //要读取关注进程的内存
        PREADMEM_INFO pri = new READMEM_INFO;
        if (pri == NULL)
            return STATUS_UNSUCCESSFUL;
        /*清零*/
        memset(pri,0,sizeof(READMEM_INFO));
        SimpleDecryptString(GameProcessName,strlen(GameProcessName),DecryptString);
        strcpy_s(pri->ProcessName,MAX_BUFFER_LENGTH,DecryptString);
        pri->BaseAddress         = BaseAddress;
        pri->NumberOfBytesToRead = NumberOfBytesToRead;
        pri->ProcessId           = gGamePid;
        if (avReadMemory(pri)){
            memcpy_s(Buffer,NumberOfBytesToRead,pri->Buffer,NumberOfBytesToRead);
            *NumberOfBytesRead = pri->NumberOfBytesRead;
            delete pri;
            return STATUS_SUCCESS;
        }
    }
    return nakedZwReadVirtualMemory(ProcessHandle,BaseAddress,Buffer,NumberOfBytesToRead,NumberOfBytesRead);
}

NTSTATUS NTAPI avZwWriteVirtualMemory(
    HANDLE 	    ProcessHandle,
    PVOID 	    BaseAddress,
    PVOID 	    Buffer,
    SIZE_T 	    NumberOfBytesToWrite,
    PSIZE_T 	NumberOfBytesWritten )
{
    char DecryptString[20] = {0};
    if (ProcessHandle == gGameHandle){
        //要写入关注进程的内存
        /*如果要写入的字节大于 MAX_BUFFER * 2的话，不能写入*/
        if (NumberOfBytesToWrite > PAGE_SIZE){
            return STATUS_UNSUCCESSFUL;
        }
        //要写入关注进程的内存
        PWRITEMEM_INFO pwi = new WRITEMEM_INFO;
        if (pwi == NULL)
            return STATUS_UNSUCCESSFUL;
        SimpleDecryptString(GameProcessName,strlen(GameProcessName),DecryptString);
        /*清零*/
        memset(pwi,0,sizeof(WRITEMEM_INFO));
        strcpy_s(pwi->ProcessName,MAX_BUFFER_LENGTH,DecryptString);
        pwi->BaseAddress          = BaseAddress;
        pwi->NumberOfBytesToWrite = NumberOfBytesToWrite;
        pwi->ProcessId            = gGamePid;
        memcpy_s(pwi->Buffer,PAGE_SIZE,Buffer,NumberOfBytesToWrite);
        if (avWriteMemory(pwi)){
            *NumberOfBytesWritten = pwi->NumberOfBytesWritten;
            delete pwi;
            return STATUS_SUCCESS;
        }
    }
    return nakedZwWriteVirtualMemory(ProcessHandle,BaseAddress,Buffer,NumberOfBytesToWrite,NumberOfBytesWritten);
}
//
//通过进程名获取进程id
//
DWORD GetProcessIdByName(wchar_t * wszName)
{
    HANDLE hProcessSnap;
    DWORD dwId  = 0;;
    PROCESSENTRY32W pe32;
    //DWORD dwPriorityClass;
    wchar_t wszProcessName[MAX_PATH]={0};
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if( hProcessSnap == INVALID_HANDLE_VALUE )
        return 0;
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    if( !Process32FirstW( hProcessSnap, &pe32 ) ){
        //printError( TEXT("Process32First") ); // show cause of failure
        CloseHandle( hProcessSnap );          // clean the snapshot object
        return 0;
    }
    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do{
        wcscpy (wszProcessName,pe32.szExeFile);
        //wcscpy_s(wszProcessName,130,pe32.szExeFile);

        if (0 == wcscmp(wszProcessName,wszName)){
            dwId = pe32.th32ProcessID;
            break;
        }

        memset(wszProcessName,0,sizeof(wszProcessName));

    } while( Process32NextW( hProcessSnap, &pe32 ) );

    CloseHandle( hProcessSnap );
    return dwId;
}
//
//初始化CustomReader 
//
CTMR_API BOOL _cdecl InitCustomReader()
{
    BOOL bRet = false;

    /*获得ntdll中的相关函数的原始地址*/
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return false;
    pfnOriZwDeviceIoControlFile = (PFN_ZWDEVICEIOCONTROLFILE)GetProcAddress(hNtdll,"ZwDeviceIoControlFile");
    pfnOriZwOpenProcess         = (PFN_ZWOPENPROCESS)GetProcAddress(hNtdll,"ZwOpenProcess");
    pfnOriZwReadVirtualMemory   = (PFN_ZWREADVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwReadVirtualMemory");
    pfnOriZwWriteVirtualMemory  = (PFN_ZWWRITEVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwWriteVirtualMemory");
    /*获取索引号*/
    gZwDeviceIoControlFileIndex = *(DWORD *)((DWORD)pfnOriZwDeviceIoControlFile + 1);
    gZwOpenProcessIndex         = *(DWORD *)((DWORD)pfnOriZwOpenProcess + 1);
    gZwReadVirtualMemoryIndex   = *(DWORD *)((DWORD)pfnOriZwReadVirtualMemory + 1);
    gZwWriteVirtualMemoryIndex  = *(DWORD *)((DWORD)pfnOriZwWriteVirtualMemory + 1);
    /*释放驱动sys的资源到当前目录下*/
    if (!ReleaseResToFile(CTMR_PATH,IDR_SYS1,"SYS")){
        return false;
    }
    OutputDebugStringA("ReleaseResToFile ok!\r\n");
    Sleep(100);
    //先卸载驱动
    UnloadDriver(CTMR_NAME);
    /*加载驱动、测试通信*/
    if(!LoadDriver(CTMR_NAME,CTMR_PATH)){
        /*删除驱动文件*/
        DeleteFileA(CTMR_PATH);
        return false;
    }
    /*删除驱动文件*/
    DeleteFileA(CTMR_PATH);

    if (!CommTest()){
        //卸载驱动
        UnloadDriver(CTMR_NAME);
        return false;
    }

    /*进行R3 hook*/
//     Mhook_SetHook((PVOID*)&pfnOriZwOpenProcess,avZwOpenProcess);
//     Mhook_SetHook((PVOID*)&pfnOriZwReadVirtualMemory,avZwReadVirtualMemory);
//     Mhook_SetHook((PVOID*)&pfnOriZwWriteVirtualMemory,avZwWriteVirtualMemory);


    return bRet;
}

//
//卸载customReader
//
CTMR_API void _cdecl UnloadCustomReader()
{
    UnloadDriver(CTMR_NAME);
//     Mhook_Unhook((PVOID*)&pfnOriZwOpenProcess);
//     Mhook_Unhook((PVOID*)&pfnOriZwReadVirtualMemory);
//     Mhook_Unhook((PVOID*)&pfnOriZwWriteVirtualMemory);
}