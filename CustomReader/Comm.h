#pragma once
#include "Utils.h"
#include "LogSystem.h"
#include "CtrlCmd.h"
#include "CommStruct.h"

typedef VOID (NTAPI *PFN_KESTACKATTACHPROCESS)(IN PKPROCESS 	Process,OUT PKAPC_STATE 	ApcState );	
typedef VOID (NTAPI *PFN_KEUNSTACKDETACHPROCESS)(IN PKAPC_STATE ApcState);


NTSTATUS SetupComm(PDRIVER_OBJECT pDriverObj);

VOID DeleteComm(IN PDRIVER_OBJECT pDriverObj);