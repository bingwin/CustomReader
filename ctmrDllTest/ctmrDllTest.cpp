// ctmrDllTest.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include "..\\ctmrDll\\ctmrDll.h"
#pragma comment(lib,"..\\CustomReader\\Debug\\ctmrDll.lib")

void SimpleEncryptString(char *src,int len,char *dest)
{
    int i;
    for (i = 0; i < len; i++){
        *(dest+i) = *(src+i) + i + 5;
    }
}

void SimpleDecryptString(char *src,int len,char *dest)
{
    int i;
    for (i = 0; i < len; i++){
        *(dest+i) = *(src+i) - i - 5;
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    char src[20] ="DNF.exe";
    char dest[20] = {0};
    SimpleEncryptString(src,strlen(src),dest);
    printf("after : %s\r\n",dest);
    FILE * p = fopen("c:\\1.txt","wt");
    fprintf(p,dest);
    fclose(p);

    char src1[20] = {0};
    SimpleDecryptString(dest,strlen(dest),src1);
    printf("before : %s\r\n",src1);
	return 0;
}

