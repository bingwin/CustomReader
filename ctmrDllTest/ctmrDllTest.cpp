// ctmrDllTest.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include "..\\ctmrDll\\ctmrDll.h"
#pragma comment(lib,"..\\CustomReader\\Debug\\ctmrDll.lib")


int _tmain(int argc, _TCHAR* argv[])
{
    InitCustomReader("DNF.exe");
    system("pause");
    UnloadCustomReader();
	return 0;
}

