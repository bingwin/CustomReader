#ifndef _LOGSYSTEM_H_
#define _LOGSYSTEM_H_

//#define CR_DBG

#ifdef CR_DBG

#define  LogPrint DbgPrint

#else

#define  LogPrint 

#endif

#endif //_LOGSYSTEM_H_
