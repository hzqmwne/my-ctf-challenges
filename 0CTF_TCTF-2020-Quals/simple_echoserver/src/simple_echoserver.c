#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_LEN 256

struct userinfo {
	char name[BUF_LEN];
	long phone;
};

struct userinfo global_userinfo;

char global_buf[BUF_LEN];

void initialize(void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	puts("Welcome to my simple echoserver!");
	sleep(1);
	alarm(600);
	puts("Server starts.");
}

void readline(char *buf, int len) {
	register char *p = buf;
	if (len <= 0) {
		return;
	}
	for(p = buf; p+1 < buf+len; p++) {
		register int c = getchar();
		if (c < 0 || c == '\n') {
			break;
		}
		*p = (char)c;
	}
	*p = '\0';
}

long readlong(void) {
	char buf[64];    // it should cover a libc address
	volatile char *p = buf;    // p should in stack, not in register, so it can be adjusted by input length and become to point to a libc address on stack
	register int c;
	while((c=getchar(), (c >= '0' && c <= '9'))) {
		if (p >= buf+sizeof(buf)-1) {
			break;
		}
		if (c == '\n') {
			break;
		}
		*p++ = (char)c;
	}
	*p = '\0';
	return atol(buf);
}

void getuserinfo(struct userinfo *info) {
	puts("For audit, please provide your name and phone number: ");
	printf("Your name: ");
	readline(info->name, 256);
	printf("Your phone: ");
	info->phone = readlong();
}

void loginfo(struct userinfo *info) {
	snprintf(global_buf, BUF_LEN, "[USER] name: %s; phone: %ld\n", info->name, info->phone);
	fprintf(stderr, global_buf);    // vuln!
}

void serve(void) {
	char localbuf[BUF_LEN];    // also a padding, skip the buf var in readlong
	loginfo(&global_userinfo);
	puts("Now enjoy yourself!");
	for(;;) {
		readline(localbuf, BUF_LEN);
		if (strcmp(localbuf, "~.") == 0) {
			break;
		}
		printf("%s\n", localbuf);
	}
}

int main(void) {
	volatile long padding;    // if omit this, gcc will use "pop rbp; ret" instead of "leave; ret"
	initialize();
	getuserinfo(&global_userinfo);
	serve();
	return 0;
}

