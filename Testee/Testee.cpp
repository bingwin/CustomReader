// Testee.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


ULONG g1 = 0x45788223;
ULONG g2 = 0xaaaaaaaa;

char sztring[50]="i am DNF.exe";

int _tmain(int argc, _TCHAR* argv[])
{
    while(true){
        system("pause");
        HANDLE handle = CreateFileA(".\\ctmrDll.dll",
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if(handle == INVALID_HANDLE_VALUE){
            DWORD dwErr = GetLastError();
            printf("LastError : 0x%x\r\n",dwErr);
            continue;
        }
        CloseHandle(handle);
    }
	return 0;
}

