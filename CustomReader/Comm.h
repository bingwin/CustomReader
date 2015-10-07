#pragma once
#include "Utils.h"
#include "LogSystem.h"
#include "CtrlCmd.h"
#include "CommStruct.h"

NTSTATUS SetupComm(PDRIVER_OBJECT pDriverObj);

VOID DeleteCommDevice(IN PDRIVER_OBJECT pDriverObj);