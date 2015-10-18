#include "HookEngine.h"
#include "xde.h"

/*关闭写保护*/
VOID disableWriteProtect()  
{
    __asm
    {
        cli
            mov eax,cr0
            and eax,not 10000h
            mov cr0,eax
    }
}

/*开启写保护*/
VOID enableWriteProtect()  
{
    __asm
    {
        mov eax,cr0
            or eax,10000h
            mov cr0,eax
            sti
    }
}

BOOL setInlineHook(PHOOKINFO hookInfo)
{
    BYTE jmpCode[5]         = {0xe9,0x00,0x00,0x00,0x00};
    int copyLength          = 0;//被hook的汇编指令的长度，不能破坏一条完整的指令
    int length              = 0;
    struct xde_instr instr  = {0};

    if (!hookInfo)
        return FALSE;
    while (copyLength < 5){
        length = xde_disasm((unsigned char *)(hookInfo->originAddress + copyLength),&instr);
        if (length == 0)
            return FALSE;
        copyLength += length;
    }
    /*copy的指令长度不要大于16个字节*/
    if(copyLength > 16)
        return FALSE;

    /*设置jmp指令内容*/
    *(ULONG*)&jmpCode[1]  = hookInfo->targetAddress - hookInfo->originAddress - 5;

    hookInfo->retAddress  =(PVOID)(hookInfo->originAddress + copyLength);
    hookInfo->patchLength = (USHORT)copyLength;

    disableWriteProtect();
    /*保存原始字节到HookZone*/
    RtlCopyMemory(hookInfo->hookZone,(PVOID)hookInfo->originAddress,copyLength);
    RtlFillMemory((PVOID)hookInfo->originAddress,copyLength,0x90);
    RtlCopyMemory((PVOID)hookInfo->originAddress,jmpCode,5);
    enableWriteProtect();
    return TRUE;
}

VOID removeInlineHook(PHOOKINFO hookInfo)
{
    if (hookInfo){
        if (hookInfo->patchLength > 0){
            disableWriteProtect();
            RtlCopyMemory((PVOID)hookInfo->originAddress,hookInfo->hookZone,hookInfo->patchLength);
            enableWriteProtect();
        }
    }
}