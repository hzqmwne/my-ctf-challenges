#ifndef BIGINT_H
#define BIGINT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int sign;           /* 0 for zero, +1 or -1 */
    size_t len;         /* number of used limbs */
    size_t cap;         /* allocated limbs */
    uint32_t *limbs;    /* little-endian base 1e9 limbs */
} BigInt;

BigInt *bi_new(void);
BigInt *bi_from_int64(int64_t v);
BigInt *bi_from_decimal(const char *s);
BigInt *bi_from_le_bytes(const uint8_t *data, size_t n);
BigInt *bi_clone(const BigInt *a);
void bi_free(BigInt *a);
char *bi_to_decimal(const BigInt *a);
size_t bi_to_le_bytes(const BigInt *a, uint8_t *out, size_t max);
size_t bi_to_le_bytes_unsafe(const BigInt *a, uint8_t *out);

int bi_compare(const BigInt *a, const BigInt *b);
BigInt *bi_add(const BigInt *a, const BigInt *b);
BigInt *bi_sub(const BigInt *a, const BigInt *b);
BigInt *bi_mul(const BigInt *a, const BigInt *b);
BigInt *bi_div(const BigInt *a, const BigInt *b, BigInt **rem_out);

#endif
