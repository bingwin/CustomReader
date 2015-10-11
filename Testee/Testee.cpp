// Testee.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


ULONG g1 = 0x45788223;
ULONG g2 = 0xaaaaaaaa;

char sztring[50]="i am dnf.exe";

int _tmain(int argc, _TCHAR* argv[])
{
    printf("g1 's addr : 0x%x\r\n",&g1);
    printf("g2 's addr : 0x%x\r\n",&g2);
    printf("sztring 's addr : 0x%x\r\n",&sztring[0]);
    system("pause");

    printf("修改之后 g1 : 0x%x\r\n",g1);
    printf("修改之后 g2 : 0x%x\r\n",g2);
	return 0;
}

