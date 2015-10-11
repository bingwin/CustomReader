// ctmrDllTest.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include "..\\ctmrDll\\ctmrDll.h"
#include <TlHelp32.h>

#pragma comment(lib,"..\\CustomReader\\Debug\\ctmrDll.lib")

//
//提升进程权限
//
BOOL PromotePrivileges()
{
    BOOL retn;      
    HANDLE hToken;      
    retn = OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken); 
    if(!retn){
        _tprintf(TEXT("OpenProcessToken failed,error code :%d\r\n"),GetLastError());
        return FALSE;
    }
    TOKEN_PRIVILEGES tp; //新特权结构体      
    LUID Luid;      
    retn = LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&Luid);      
    if(!retn)      
    {      
        _tprintf(TEXT("LookupPrivilegeValue failed,error code :%d\r\n"),GetLastError());      
        return FALSE;      
    }   
    //给TP和TP里的LUID结构体赋值      
    tp.PrivilegeCount = 1;      
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;      
    tp.Privileges[0].Luid = Luid;  

    retn = AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL); 
    if(!retn){
        _tprintf(TEXT("AdjustTokenPrivileges failed,error code :%d\r\n"),GetLastError());
        retn = FALSE;
    }
    else{
        if (ERROR_SUCCESS == GetLastError()){
            _tprintf(TEXT("AdjustTokenPrivileges success!\r\n"));
            retn = TRUE;
        }
        else{
            _tprintf(TEXT("Not adjusted all of the specified privileges!\r\n"));
            retn = FALSE;
        }
    }  
    return retn;
}
//
//通过进程名打开指定进程句柄
//
HANDLE OpenProcessByName(wchar_t * wszName)
{
    HANDLE hProcessSnap;
    HANDLE hProcess = NULL;
    PROCESSENTRY32W pe32;
    //DWORD dwPriorityClass;
    wchar_t wszProcessName[MAX_PATH]={0};
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if( hProcessSnap == INVALID_HANDLE_VALUE )
    {
        //printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
        return NULL;
    }
    pe32.dwSize = sizeof( PROCESSENTRY32W );
    if( !Process32FirstW( hProcessSnap, &pe32 ) )
    {
        //printError( TEXT("Process32First") ); // show cause of failure
        CloseHandle( hProcessSnap );          // clean the snapshot object
        return NULL;
    }
    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do
    {
        //_tprintf( TEXT("\n\n=====================================================" ));
        //_tprintf( TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile );
        //_tprintf( TEXT("\n-------------------------------------------------------" ));
        wcscpy(wszProcessName,pe32.szExeFile);
        //wcscpy_s(wszProcessName,130,pe32.szExeFile);

        if (0 == wcscmp(wszProcessName,wszName))
        {
            hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
            if(hProcess == NULL){
                _tprintf( TEXT("\n  OpenProcess failed,lasterror     = %d"), GetLastError());
            }
            else{
                // Retrieve the priority class.
                //dwPriorityClass = 0;
                _tprintf( TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID );
                _tprintf( TEXT("\n  Thread count      = %d"),   pe32.cntThreads );
                _tprintf( TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID );
                _tprintf( TEXT("\n  Priority base     = %d\r\n"), pe32.pcPriClassBase );
            }
        }
        memset(wszProcessName,0,sizeof(wszProcessName));

    } while( Process32NextW( hProcessSnap, &pe32 ) );

    CloseHandle( hProcessSnap );
    return hProcess;
}

int _tmain(int argc, _TCHAR* argv[])
{
    InitCustomReader();
    ULONG g1 = 0;
    ULONG g2 = 0;
    unsigned char buffer[100] ={0};
    if (PromotePrivileges()){
        HANDLE handle = OpenProcessByName(L"DNF.exe");
        printf("handle is : 0x%x\r\n",(DWORD)handle);
        if (handle){
            DWORD dwRet;
            if (ReadProcessMemory(handle,(LPVOID)0x417030,&g1,4,&dwRet)){
                printf("g1 : 0x%x\r\n",g1);
            }
            if (ReadProcessMemory(handle,(LPVOID)0x417034,&g2,4,&dwRet)){
                printf("g2 : 0x%x\r\n",g2);
            }
            if (ReadProcessMemory(handle,(LPVOID)0x417038,&buffer,5,&dwRet)){
                printf(", : %s\r\n",buffer);
            }

        }
    }

    system("pause");
    UnloadCustomReader();
	return 0;
}

