#include <Windows.h>

/* Queue apc call in the same proc and to the same executer */
#define __SELF_INJECTION__
#define __LOG__
#define __LOG_BY_MESSAGE__
#define MAX_ONE_TIME_LOG_SIZE 50
//#define __USE_NT_FUNCTIONS__

#define SHARED_MEM_NAME "SelfQueuingSharedMem"

#ifdef __USE_NT_FUNCTIONS__
void __stdcall executer(LPVOID, LPVOID, LPVOID);
#else
void __stdcall executer(ULONG);
#endif