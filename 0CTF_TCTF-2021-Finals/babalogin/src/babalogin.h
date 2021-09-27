#ifndef SECURE_LOGIN_H_
#define SECURE_LOGIN_H_


#define MAX_SOURCE_LEN 4096
#define MAX_MIDDLE_LEN 4096
#define MAX_BINARY_LEN 8192

#define MAX_INPUT_LEN 4096
#define MAX_OUTPUT_LEN 8192

struct fullcompiler {
	char compiler_binary[MAX_BINARY_LEN];
	int compiler_binary_len;
	char linker_binary[MAX_BINARY_LEN];
	int linker_binary_len;
};


extern struct fullcompiler global_rawcompiler;

extern void install_seccomp();


#endif

