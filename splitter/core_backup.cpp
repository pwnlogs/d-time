//-----------------------------------------------------------------------------------------------------------
/*
**	malWASH - The malware engine for evading ETW and dynamic analysis - ** The splitting engine **
**
**	Version 2.0
**
**	core.cpp
**
**	This file is the core of the plugin. It's responsible for splitting the executablle into multiple
**	pieces. We assume that there are no anti dissasembly protections, or any code obfuscation. Every
**	instruction must be known at compile time.
**
**
**	Kyriakos Ispoglou (ispo) - ispo@purdue.edu
**  June 2015 
*/
//-----------------------------------------------------------------------------------------------------------
#include "malwash.h"										// all includes are here


netnode edge,												// store the relations between basic blocks
		visited;											// store the bid for each address
//-----------------------------------------------------------------------------------------------------------
/*
**  fatal(): This function is called when fatal error are occured. fatal() prints the error description and
**		terminates execution of plugin
**
**	Arguments: fmstring (char*) : A format string, containing the error description
**              ...             : maybe more arguments follow
**
**  Return Value: None.
*/
void fatal( const char *fmstring, ... )
{
	va_list args;											// our arguments
	qstring	fsbuf;											// our format string buffer


	va_start( args, fmstring );								// start using variable argument list
	fsbuf.vsprnt( fmstring, args );							// load error message in fsbuf
	va_end( args );                                         // stop using variable argument list

	msg("\n[ERROR]: %s. Aborting Execution\n\n", qstrdup(fsbuf.c_str()) );

	visited.kill();											// delete netnodes from database
	segment.kill();
	invbid.kill();
	edge.kill();

	//error("%s. Aborting Execution\n\n", qstrdup(fsbuf.c_str()) );

	//qexit(ERROR);
}
//-----------------------------------------------------------------------------------------------------------
/*
** locmain(): Search for a function and returns a pointer to it.
**
**	Arguments: name (char*): A pointer to a string containing function name
**
**	Return Value: A pointer to the requested function. If function doesn't exist, a NULL is returned.
*/
func_t *locmain(char *name)
{
	char fname[256];										// plz don't overflow me :)

	for(uint idx=0; idx<get_func_qty(); idx++) {			// iterate over functions

		get_func_name(getn_func(idx)->startEA, fname, sizeof(fname));

		if( strcmp(fname, name) == 0 )						// match found?
			return getn_func(idx);							// if so, return pointer
	}

	return NULL;											// failure. Return null
}
//-----------------------------------------------------------------------------------------------------------
/*
**	addedge(): This function adds an edge between 2 basic blocks.
**	
**	Arguments:	from (ea_t)	     : Effective address of source basic block
**				to   (ea_t)	     : Effective address of target basic block
**              dm   (debugmode) : The level of information will be printed
**
**	Return Value: None.
*/
void addedge(ea_t from, ea_t to, debugmode dm)
{
	// PROBLEM: 1byte bids
	uchar	edglst[256] = { 0 };							// store here edge list
	size_t 	len;											// list length
	uint	bfrom, bto;										// block ids


	bfrom = visited.altval(from) & NOTMSBIT;				// get bids from addresses
	bto   = visited.altval(to)   & NOTMSBIT;
	
	if( (len=edge.supval(bfrom, NULL, 0, 'E')) == -1 )		// empty list ?
		len = 0; 
	else edge.supval(bfrom, edglst, len, 'E');				// if not get it

	((ushort*)edglst)[len>>1] = bto & SHORT;				// store 2 byte bid (look edglst as ushort[128])
	
	edge.supset(bfrom, edglst, len+2, 'E');					// store list back to netnode
	

	if( dm != NONE )										// print detailed information?
	{
		ushort *e;											// edge list pointer
		uint	i;											// iterator

		edge.supval(bfrom, edglst, len+2, 'E');				// update edge list

		msg( "    [*] Block targets from %3d: ", bfrom )	;
		
		for( i=0, e=(ushort*)edglst; i<=len>>1; ++i, ++e )	// print each element
			msg( "%3d, ", *e );
		
		msg( "\n" );					
	}
}
//-----------------------------------------------------------------------------------------------------------
/*
**	basicblksplit(): This function does splits a function into basic blocks. It uses a simple Depth-First
**		Search (DFS) algorithm. Note that function is recursive.
**
**	Arguments:	cfun (func_t*)	: A pointer to the current function
**				curr (ea_t)		: The current address to start spliting
**              dm   (debugmode) : The level of information will be printed
**
**	Return Value: The number of instructions splitted.
*/
uint basicblksplit(func_t *cfun, ea_t curr, debugmode dm)
{
	static uint bid = 1;									// set block ID (start from 1, 0 is a special case)
	char		name[MAXBUFLEN],							// auxilary buffers
				temp[MAXBUFLEN];
	uint		ninst;										// total number of instructions
	ea_t		prev = curr;								// instruction before current instruction	
	insn_t		loccmd;										// backup of cmd global variable (we need it to avoid
															// problems during recursion).
	// PROBLEM: if prev declared after loccmd, we get an exception of corrupted stack near loccmd.

	// PROBLEM: we miscount some block ids.
	//


	// parsing instructions one after another, until one of these occur:
	//   [1]. Reach the end of the function
	//   [2]. Visit an instruction that already belongs to another block
	for(ninst=0; !(visited.altval(curr) >> 31) && curr<=cfun->endEA; ++ninst, curr+=loccmd.size )
	{
		decode_insn(curr);									// decode current instruction
		loccmd = cmd;										// cmd is global (in ua.hpp). Make a local copy of it
	
		get_name(cfun->startEA, curr, name, MAXNAMELEN);	// get location name (if exists)	
		if( name[0] != 0 &&									// if name exists 
			cfun->startEA < curr && curr < cfun->endEA)		// and name is not a function name
			bid++;											// get a new block
		
		visited.altset(curr, (ulong)(MSBIT | bid));			// assign a block ID

		_ltoa_s(bid, temp, MAXBUFLEN, 10);					// DEBUG: comment instructionns with block IDs
		set_cmt(curr, temp, false);							// (use the safe version of ltoa)


		
		if(visited.altval(prev) != visited.altval(curr))	// if 2 consequtive instr. have different bid
			addedge(prev, curr, VERY_VERBOSE);				// add an edge between them		

		if( dm == VERY_VERBOSE )							// print more information ?
			msg( "    [-] Visiting block %3d. Current Address:%x\n", bid, curr );
		

		// for each possible target address (there will be many in switch statements)
		for( ea_t nxt=get_first_cref_from(curr); nxt!=BADADDR; nxt=get_next_cref_from(curr, nxt) )
		{
			if( (curr + loccmd.size != nxt) )				// if the next instr. is not the instr. below
			{
				if( loccmd.itype == NN_call || loccmd.itype == NN_callfi || loccmd.itype == NN_callni)
				{
					// special handling of call instructions
					char segm[MAXBUFLEN];					// store segments

					get_segm_name(nxt, segm, MAXBUFLEN);	// get segment of target function
					if( strcmp(segm, "_text") == 0 )		// if function is not imported, analyze it
					{
						char func[MAXFUNAMELEN];			// get function name
						get_func_name(nxt, func, MAXFUNAMELEN);

						// ignore some useless functions (DEBUG ONLY)
						if( strstr(func, "_RTC_") == 0 && strstr(func, "_security_") == 0 ) 
						{
							bid++;							// new block

							// split the new function
							if(funcsplit(get_func(nxt),dm) == 0)
								bid--;						// if it's already visited no new bid is used
							
							
							addedge(curr, nxt, dm);			// add an edge between blocks
						}
						// we ignore the total instructions splitted here, cause we're insterested only in
						// the total number of instructions within this function
					}
				}
				else										// instruction can jump somewhere else
				{
					// add this check for MSVC++ compiler, to handle trampoline functions
					if( func_contains(get_func(curr), nxt) == false ) 
					{
						bid++;								// new block
						if(funcsplit(get_func(nxt), dm) > 0)// split the new function
							bid++;							// one more time...
					}
					else {									// normal jmp/loop instructions
						//msg("block split: %3d cur:%x\tnxt:%x\n", bid, curr, nxt);

						uint n = basicblksplit(cfun, nxt, dm);

						//msg("block split AFTER: %3d cur:%x\tnxt:%x n:%d\n", bid, curr, nxt, n);
						
						// note that with this method, we may miscount the block id counter. Here if the nxt,
						// is an already visited block, we'll return with a new bid where no instructions are
						// assigned to it. If we have a 2nd consequtive return, we'll increase bid, without
						// using the previous value in any block.
						ninst += n;							// increase total number of instructions				
						if(n > 0) bid++;					// change block only if you have to		

						
						addedge(curr, nxt, dm);				// add an edge between blocks
					}					
				}
			}
			else prev = curr;								// update previous instruction pointer
		}
		
		if(find_code(curr, SEARCH_DOWN) >= cfun->endEA)	{	// if the next instr. exceeds function's end stop
			if( !ninst ) ninst = 1;							// if we made only 1 iteration, we have seen 1 instr.
			break;											// now break
		}
	}

	if( (visited.altval(curr) >> 31) && !ninst)				// if block is visited
		bid++;												// we still have to change block id
		
	return ninst;											// return the total number of instructions
}
//-----------------------------------------------------------------------------------------------------------
/*
**  funcsplit(): This function splits a new function. basicblksplit() may call it, when encounter a new
**		function. This is just a wrapper for basicblksplit(). We create a new function for this job in order
**		to have a more clear design.
**
**	Arguments: cfun (func_t*)   : A pointer to the current function
**              dm  (debugmode) : The level of information will be printed
**
**	Return Value: The total number of instructions splitted.
*/
uint funcsplit(func_t *currfunc, debugmode dm)
{
	char	name[MAXBUFLEN];								// function's name
	uint	ninst;											// total number of instructions
	

	if( (ninst = basicblksplit(currfunc, currfunc->startEA, dm)) > 0 )	
	{
		// print it only the first time you see the function
		get_func_name(currfunc->startEA, name, MAXBUFLEN);
	
		msg("    [-]. %3d instruction(s) splitted on function (%x-%x): %s ...\n",
				ninst, currfunc->startEA, currfunc->endEA, name ); 
	}
	
	return ninst;											// return total number of instructions
}
//-----------------------------------------------------------------------------------------------------------
/*
**  printbbstat(): Print some information about basic block splitting.
**
**	Arguments: dm (debugmode): The level of information detail
**
**	Return Value: None.
*/
void printbbstat( debugmode dm )
{
	ulong	val, prev=-1;									// auxilart vars
	uint	count=0;										// number of basic blocks


	// enumerate all different basic blocks
	for( nodeidx_t addr=visited.alt1st(); addr!=BADNODE; addr=visited.altnxt(addr))
		if( (val = visited.altval(addr)) != prev ) {		// bid changed?
			prev = val;										// update it
			count++;										// increment counter
	
			invbid.altset(val & NOTMSBIT, addr, 'I');		// set this for inverse search
		}

	msg( "[+] Program splitted into %d pieces\n", count );
}
//-----------------------------------------------------------------------------------------------------------
