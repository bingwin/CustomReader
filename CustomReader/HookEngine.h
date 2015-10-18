#pragma once
#include "Utils.h"

typedef struct tagHOOKINFO{
    ULONG targetAddress;
    ULONG originAddress;
    PVOID hookZone;
    PVOID retAddress;
    USHORT patchLength;
}HOOKINFO,*PHOOKINFO;
//
//…Ë÷√∫Õ“∆≥˝inlinehook
//
BOOL setInlineHook(PHOOKINFO hookInfo);

VOID removeInlineHook(PHOOKINFO hookInfo);