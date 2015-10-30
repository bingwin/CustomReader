#pragma once

//
//标准的IO控制码
//
#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)
#define  CTRL_BASE 0xa00	// 大于0x800
#define CTRL_EXPRESSION(i)   CTL_CODE(FILE_DEVICE_UNKNOWN,(CTRL_BASE+i),METHOD_BUFFERED,FILE_ANY_ACCESS)
//判断是不是控制码
//#define CTRL_SUCCESS(code) (((code) &  0x88880000) == 0x88880000)

//
//定义一系列控制码，用于R3和R0通信
//
#define FC_COMM_TEST		        CTRL_EXPRESSION(0)			//测试通信
#define FC_WRITE_PROCESS_MEMORY     CTRL_EXPRESSION(1)          //写进程内存命令
#define FC_READ_PROCESS_MEMORY      CTRL_EXPRESSION(2)          //读进程内存命令

#define FC_GET_NAME_BY_ID           CTRL_EXPRESSION(3)          //

//
//判断是不是伪句柄
//
#define  IS_MY_HANDLE(x)            ((((DWORD)(x)) & 0xc0000000) == 0xc0000000) // 1100 0000...
//
//将PID构造成我的句柄
//
#define  PID_TO_MY_HANDLE(x)        (HANDLE)((x) | 0xc0000000)

//
//伪句柄到pid转换
//
#define MY_HANDLE_TO_PID(x)         (DWORD)(((DWORD)(x)) & ~0xc0000000)
