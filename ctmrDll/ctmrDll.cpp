// ctmrDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "ctmrDll.h"
#include <tchar.h>


// 这是导出变量的一个示例
// CTMRDLL_API int nctmrDll=0;
// 
// 这是导出函数的一个示例。
// CTMRDLL_API int fnctmrDll(void)
// {
// 	return 42;
// }
// 
// 这是已导出类的构造函数。
// 有关类定义的信息，请参阅 ctmrDll.h
// CctmrDll::CctmrDll()
// {
// 	return;
// }
DWORD _stdcall InitFunctionAddress()
{
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtdll == NULL)
        return 0;

    return (DWORD)GetProcAddress(hNtdll,"ZwOpenProcess");
}