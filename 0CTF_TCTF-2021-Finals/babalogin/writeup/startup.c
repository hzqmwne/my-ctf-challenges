#include "tinylib.h"

extern int main(int, char **, char **);

// https://stackoverflow.com/questions/55243572/how-can-i-get-ld-to-put-always-put-the-entry-point-at-the-location-of-ttext
__attribute__((section(".text.startup"))) __attribute__((naked)) void _start(void) {    // XXX
	int r;
	int argc;
	char **argv;
	char **envp;
	register unsigned long rsp __asm__("rsp");
	argc = *(int *)rsp;
	argv = (char **)(rsp+8);
	envp = (char **)(rsp+argc*8+16);

	r = main(argc, argv, envp);
	exit(r);
	asm volatile ("hlt");
}

