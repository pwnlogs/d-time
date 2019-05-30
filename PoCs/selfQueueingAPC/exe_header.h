#include <Windows.h>

typedef struct PROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;
typedef PROCESSENTRY32* LPPROCESSENTRY32;

typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32;
typedef THREADENTRY32*  LPTHREADENTRY32;


#define TH32CS_SNAPPROCESS			0x00000002
#define TH32CS_SNAPTHREAD			0x00000004
#define NTAPI						__stdcall
#define _NTSYSAPI					_declspec(dllimport)
#define NT_SUCCESS(Status)			((LONG)(Status) >= 0)
#define NT_ERROR(Status)			((ULONG)(Status) >> 30 == 3)