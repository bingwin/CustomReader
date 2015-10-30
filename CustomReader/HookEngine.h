#pragma once
#include "Utils.h"

typedef struct tagHOOKINFO{
    ULONG targetAddress;
    ULONG originAddress;
    PVOID hookZone;
    PVOID retAddress;
    USHORT patchLength;
}HOOKINFO,*PHOOKINFO;

/*关闭写保护*/
VOID disableWriteProtect();  

/*开启写保护*/
VOID enableWriteProtect();
//
//设置和移除inlinehook
//
BOOL setInlineHook(PHOOKINFO hookInfo);

VOID removeInlineHook(PHOOKINFO hookInfo);