#include <string.h>
#include "aes_whitebox.h"
#include "md5.h"


static void md5sum(const uint8_t *input, unsigned int length, uint8_t digest[16]) {
	MD5_CTX context;
	MD5Init(&context);
	MD5Update(&context, input, length);
	MD5Final(digest, &context);
}


__attribute__((visibility("default")))
void secure_hash(const uint8_t m[16], uint8_t h[16]) {
	uint8_t buf[16];
	int i;
	memcpy(buf, m, 16);
	for (i = 0; i < 1337; i++) {
		md5sum(buf, 16, buf);
		aes_whitebox_encrypt_with_external_xor(buf, buf);
	}
	md5sum(buf, 16, h);
}

__attribute__((visibility("default")))
void secure_decrypt(const uint8_t c[16], uint8_t m[16]) {
	uint8_t buf[16];
	int i;
	memcpy(buf, m, 16);
	for (i = 0; i < 1337; i++) {
		aes_whitebox_encrypt_with_external_xor(buf, buf);
	}
	memcpy(m, buf, 16);
}

