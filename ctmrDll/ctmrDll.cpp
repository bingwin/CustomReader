// ctmrDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>
/**/
#include "..\\CustomReader\\CommStruct.h"
#include "..\\CustomReader\\CtrlCmd.h"

const char DefaultProcessName[10] = "DNF.exe";
char gProcessName[MAX_PATH];

PFN_ZWOPENPROCESS pfnOriZwOpenProcess;
PFN_ZWREADVIRTUALMEMORY pfnOriZwReadVirtualMemory;
PFN_ZWWRITEVIRTUALMEMORY pfnOriZwWriteVirtualMemory;

//
//
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

    /*加载驱动、测试通信*/

    return bRet;
}

void _stdcall UnloadCustomReader()
{

}