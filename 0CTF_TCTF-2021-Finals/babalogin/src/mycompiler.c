#include "tinylib.h"

static int check_valid_base64code(const char *in) {    // return 1 for valid, 0 for invalid
	int len = 0;
	const char *p = in;
	for (p = in; *p++; len++);
	if (len % 4 != 0) {
		return 0;
	}

	int checklen = len;
	if (len >= 2) {
		if (in[len-1] == '=') {
			checklen--;
			if (in[len-2] == '=') {
				checklen--;
			}
		}
	}
	
	int i;
	for (i = 0; i < checklen; i++) {
		char c = in[i];
		if ( !( (c >= '0' && c <='9' )|| (c >= 'A' && c <= 'Z') || (c >= 'a' && c<='z') || (c == '+' || c == '/') ) ) {
			return 0;
		}
	}

	return 1;
}

static int b64decode(const char *in, void *out) {
	// 00000000 1111111 2222222 <-> 000000 001111 111122 222222
	if (!check_valid_base64code(in)) {
		return 0;
	}

	const static unsigned char rtable[] = {
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
		0,0,0,0, 0,0,0,0, 0,0,0,62, 0,0,0,63, 
		52,53,54,55, 56,57,58,59, 60,61,0,0, 0,0,0,0,
		0,0,1,2, 3,4,5,6, 7,8,9,10, 11,12,13,14,
		15,16,17,18, 19,20,21,22, 23,24,25,0, 0,0,0,0,
		0,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
		41,42,43,44, 45,46,47,48, 49,50,51
	};
	int len = 0;
	const char *p = in;
	for (p = in; *p++; len++);
	// assert(length % 4 == 0);

	int outlen = len/4 * 3;
	if (len >= 2) {
		if (in[len-1] == '=') {
			outlen--;
			if (in[len-2] == '=') {
				outlen--;
			}
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

static int do_input(char *buf) {
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

static void do_output(char *buf, int len) {
	int count = 0;
	while (count < len) {
		int r = write(1, buf, len-count);
		if (r <= 0) {
			break;
		}
		count += r;
	}
}

static void do_compile(char *source, int source_len, char *middle, int *p_middle_len) {
	while (source_len > 0 && (source[source_len-1] == ' ' || source[source_len-1] == '\n' || source[source_len-1] == '\t')) {
		source[source_len-1] = '\0';
		source_len--;
	}
	*p_middle_len = b64decode(source, middle);
}

int main(int argc, char **argv, char **envp) {
	char source[4096];
	char middle[4096];
	int middle_len = 0;
	int source_len = do_input(source);
	do_compile(source, source_len, middle, &middle_len);
	do_output(middle, middle_len);
	return 0;
}

