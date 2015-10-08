// ctmrDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>
#include "resource.h"
/**/
#include "..\\CustomReader\\CommStruct.h"
#include "..\\CustomReader\\CtrlCmd.h"

/*驱动名称和驱动所在的路径*/
#define CTMR_NAME       "CtmrReader"
#define CTMR_PATH       ".\\CtmrReader.sys"

#define DEVICE_NAME     "\\\\.\\CtmrReader"


const char DefaultProcessName[10] = "DNF.exe";
char gProcessName[MAX_PATH];

PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;


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
        OutputDebugStringA("FindResourceW failed\r\n");
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
            OutputDebugStringA( "CrateService() Failed! \r\n" );  
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
        OutputDebugStringA( "CrateService() ok ! \n" );
    }

    //开启此项服务
    bRet = StartService( hServiceDDK, NULL, NULL );  
    if( !bRet ){  
        DWORD dwRtn = GetLastError();  
        if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING ){  
            OutputDebugStringA( "StartService() Failed! \r\n" );  
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
//通信测试函数
//
BOOL _stdcall CommTest()
{
    BOOL bRet       = false;
    HANDLE hDevice  = OpenDevice();
    if (hDevice == NULL)
        return false;
    COMMTEST ct     = {0};
    DWORD dwRet     = 0;
    if(DeviceIoControl(hDevice,FC_COMM_TEST,NULL,0,&ct,sizeof(COMMTEST),&dwRet,NULL)){
        if (ct.success){
            bRet = true;
        }
    }
    CloseHandle(hDevice);
    return bRet;
}
//
//初始化CustomReader 
//
BOOL _stdcall InitCustomReader(const char *ProcessName)
{
    BOOL bRet = false;
    /*初始化游戏进程名*/
    memset(gProcessName,0,MAX_PATH);
    if (ProcessName == NULL){
        //默认针对dnf
        memcpy_s(gProcessName,MAX_PATH,DefaultProcessName,strlen(DefaultProcessName)+1);
    }
    else{
        memcpy_s(gProcessName,MAX_PATH,ProcessName,strlen(ProcessName)+1);
    }

    /*获得ntdll中的相关函数的原始地址*/
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return false;
    pfnOriZwOpenProcess         = (PFN_ZWOPENPROCESS)GetProcAddress(hNtdll,"ZwOpenProcess");
    pfnOriZwReadVirtualMemory   = (PFN_ZWREADVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwReadVirtualMemory");
    pfnOriZwWriteVirtualMemory  = (PFN_ZWWRITEVIRTUALMEMORY)GetProcAddress(hNtdll,"ZwWriteVirtualMemory");

    /*释放驱动sys的资源到当前目录下*/
    if (!ReleaseResToFile(CTMR_PATH,IDR_SYS_CTMR,"SYS")){
        return false;
    }
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



    return bRet;
}

//
//卸载customReader
//
void _stdcall UnloadCustomReader()
{
    UnloadDriver(CTMR_NAME);
}