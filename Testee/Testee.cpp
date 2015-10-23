// Testee.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


ULONG g1 = 0x45788223;
ULONG g2 = 0xaaaaaaaa;

//10
char sztring[50]="i DNF.exe";

int _tmain(int argc, _TCHAR* argv[])
{
    //printf("g1 : 0x%x\r\n",&g1);
    //printf("g2 : 0x%x\r\n",&g2);
    //printf("sztring : 0x%x\r\n",&sztring[0]);
    //system("pause");
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

