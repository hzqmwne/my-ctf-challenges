#include <stdio.h>
#include <unistd.h>

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


int main(void) {
	char s[8192];
	int len = read(0, s, 8192);
	int r = bkdrhash(s, len);
	printf("%#x\n", r);
	return 0;
}


