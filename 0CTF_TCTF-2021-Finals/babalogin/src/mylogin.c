#include "tinylib.h"


static size_t strlen(const char *s) {
	const char *p = s;
	while (*p) {
		p++;
	}
	return p-s;
}

static int strcmp(const char *s1, const char *s2) {
	const unsigned char *p1 = s1;	
	const unsigned char *p2 = s2;
	while (*p1 && *p1 == *p2) {
		p1++;
		p2++;
	}
	return (*p1 > *p2) ? 1 : ((*p1 < *p2) ? -1 : 0);
}

static int memcmp(const void *vl, const void *vr, size_t n) {
	// http://git.musl-libc.org/cgit/musl/tree/src/string/memcmp.c
	const unsigned char *l=vl, *r=vr;
	for (; n && *l == *r; n--, l++, r++);
	return n ? ( (*l>*r)? 1 : ((*l<*r)? -1 : 0) ) : 0;
}

static int rand_r(unsigned int *seedp) {
	// https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
	unsigned int seed = *seedp;
	seed = (1103515245 * seed + 12345) & 0x7fffffff;
	*seedp = seed;
	return (int)seed;
}

static char *getenv(const char *name, char **envp) {
	char **e = envp;
	int len = strlen(name);
	char *p = NULL;
	while ((p = *e++)) {
		if (memcmp(p, name, len) == 0 && p[len] == '=') {
			return &p[len+1];
		}
	}
	return NULL;
}


static void readlinen(char *buf, int bufsize) {
	int len = 0;
	while (len < bufsize-1) {
		char c = 0;
		int r = read(0, &c, 1);
		if (r <= 0 || c == '\n') {
			break;
		}
		buf[len] = c;
		len += r;
	}
	buf[len] = '\0';
}

static void writestring(const char *s) {
	write(1, s, strlen(s));
}



static int do_login(const char *username, const char *password) {    // return 1 for success, 0 for fail
	int usernamelen = strlen(username);
	int passwordlen = strlen(password);

	int i;

	// check: not empty
	if (usernamelen == 0 || passwordlen == 0) {
		return 0;
	}
	// check: printable chars
	for (i = 0; i < usernamelen; i++) {
		if (! (username[i] >= 33 && username[i] <= 126)) {
			return 0;
		}
	}
	for (i = 0; i < passwordlen; i++) {
		if (! (password[i] >= 33 && password[i] <= 126)) {
			return 0;
		}
	}

	// generate a check number from username
	int tocheck = 0;
	for (i = 0; i < usernamelen; i++) {
		tocheck ^= username[i]+i;
	}
	tocheck &= 0xff;
	// e.g. for "root", the result is ( (114+0)^(111+1)^(111+2)^(116+3) ) & 0xff = 4

	// generate a random table
	char randomtable_[94];
	char *randomtable = ((char *)randomtable_) - 33;
	for (i = 33; i <= 126; i++) {
		randomtable[i] = i-33;
	}
	unsigned int seed = tocheck;
	for (i = 93; i >= 1; i--) {
		int chosen = rand_r(&seed) % (i+1);
		int tmp = randomtable_[i];
		randomtable_[i] = randomtable_[chosen];
		randomtable_[chosen] = tmp;
	}

	int x = 0;
	int y = 0;
	int z = 0;
	for (i = 0; i < passwordlen; i++) {
		if (i % 3 == 0) {
			x = x*94 + randomtable[password[i]];    // base94
		}
		else if (i % 3 == 1) {
			y = y*94 + randomtable[password[i]];
		}
		else {
			z = z*94 + randomtable[password[i]];
		}
	}
	x = (x << 22) >> 22;    // x &= 0x3ff, then signed extend to 32 bits
	y = (y << 22) >> 22;
	z = (z << 22) >> 22;

	/*
	write(1, &usernamelen, 4);
	writestring(username);
	write(1, &passwordlen, 4);
	writestring(password);
	write(1, &tocheck, 4);
	write(1, &x, 4);
	write(1, &y, 4);
	write(1, &z, 4);
	*/

	if (x*x*x + y*y*y + z*z*z == tocheck) {
		// special: 1. there is no integer overflow
		// 2. for tocheck is 9*n+4 or 9*n-4, there is not x,y,z can satisfy
		// 3. for username equals "root", the tocheck value is 4, that means there is no valid password for root !
		// TODO XXX need to check by other people
		return 1;
	}

	return 0;
}


int main(int argc, char **argv, char **envp) {
	char *username = getenv("BABALOGIN_TO_LOGIN_USERNAME", envp);
	char password[32+1] = {0};
	if (username == NULL) {
		char username_buf[32+1] = {0};
		writestring("0CTF-2021-Finals login: ");
		readlinen(username_buf, sizeof(username_buf));
		username = username_buf;
	}
	writestring("Password: ");
	readlinen(password, sizeof(password));

	if (do_login(username, password)) {
		writestring("Welcome to 0CTF-2021-Finals\n");
		if (strcmp(username, "root") == 0) {
			/*
			char *newargv[2] = {"/bin/sh", NULL};
			execve("/bin/sh", newargv, envp);
			exit(0);
			*/
			char flag[128] = {0};
			int fd = open("flag.txt", O_RDONLY);
			if (fd >= 0) {
				int r = read(fd, flag, 128);
				if (r > 0) {
					write(1, flag, r);
				}
			}
		}
		else {
			writestring("Info: For secure policy, only root can get the flag\n");
		}
	}
	else {
		writestring("Login incorrect\n");
	}
	return 0;
}

