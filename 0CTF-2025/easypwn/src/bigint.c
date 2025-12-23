#include "bigint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE 0x40000000U  // 2^30 limb base
#define BASE_DIGITS 9      // decimal chunk size (1e9) for printing

static void bi_normalize(BigInt *a) {
    while (a->len > 0 && a->limbs[a->len - 1] == 0) {
        a->len--;
    }
    if (a->len == 0) {
        a->sign = 0;
    }
}

static void bi_reserve(BigInt *a, size_t cap) {
    if (cap > a->cap) {
        size_t new_cap = (a->cap != 0) ? a->cap : 4;
        while (new_cap < cap) {
            new_cap *= 2;
        }
        uint32_t *p = (uint32_t *)realloc(a->limbs, new_cap * sizeof(uint32_t));
        if (p == NULL) {
            // fprintf(stderr, "Out of memory\n");
            exit(1);
        }
        a->limbs = p;
        a->cap = new_cap;
    }
}

BigInt *bi_new(void) {
    BigInt *a = (BigInt *)calloc(1, sizeof(BigInt));
    if (a == NULL) {
        return NULL;
    }
    a->sign = 0;
    a->len = 0;
    a->cap = 0;
    a->limbs = NULL;
    return a;
}

BigInt *bi_from_int64(int64_t v) {
    BigInt *a = bi_new();
    if (a == NULL) {
        return NULL;
    }
    if (v == 0) {
        return a;
    }
    uint64_t x = (v < 0) ? -(uint64_t)v : (uint64_t)v;
    bi_reserve(a, 2);
    while (x != 0) {
        a->limbs[a->len++] = (uint32_t)(x % BASE);
        x /= BASE;
    }
    a->sign = (v < 0) ? -1 : 1;
    return a;
}

static int bi_is_zero(const BigInt *a) {
    return (a->len == 0) || (a->sign == 0);
}

BigInt *bi_clone(const BigInt *a) {
    BigInt *b = bi_new();
    if (b == NULL) {
        return NULL;
    }
    if (a->len != 0) {
        bi_reserve(b, a->len);
        memcpy(b->limbs, a->limbs, a->len * sizeof(uint32_t));
        b->len = a->len;
        b->sign = a->sign;
    }
    return b;
}

void bi_free(BigInt *a) {
    if (a == NULL) {
        return;
    }
    free(a->limbs);
    free(a);
}

static void bi_shift_left_small(BigInt *a, uint32_t mul) {
    uint64_t carry = 0;
    for (size_t i = 0; i < a->len; ++i) {
        uint64_t cur = (uint64_t)a->limbs[i] * mul + carry;
        a->limbs[i] = (uint32_t)(cur % BASE);
        carry = cur / BASE;
    }
    if (carry != 0) {
        bi_reserve(a, a->len + 1);
        a->limbs[a->len++] = (uint32_t)carry;
    }
}

static void bi_add_small(BigInt *a, uint32_t add) {
    uint64_t carry = add;
    size_t i = 0;
    while (carry != 0 && i < a->len) {
        uint64_t cur = (uint64_t)a->limbs[i] + carry;
        a->limbs[i] = (uint32_t)(cur % BASE);
        carry = cur / BASE;
        ++i;
    }
    if (carry != 0) {
        bi_reserve(a, a->len + 1);
        a->limbs[a->len++] = (uint32_t)carry;
    }
}

BigInt *bi_from_decimal(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n') {
        s++;
    }
    int neg = 0;
    if (*s == '+' || *s == '-') {
        neg = (*s == '-');
        s++;
    }
    BigInt *a = bi_new();
    if (a == NULL) {
        return NULL;
    }
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') {
            break;
        }
        if (bi_is_zero(a)) {
            bi_reserve(a, 1);
            a->len = 1;
            a->limbs[0] = 0;
            a->sign = 1;
        }
        bi_shift_left_small(a, 10);
        bi_add_small(a, (uint32_t)(*s - '0'));
        if (a->len != 0 && a->sign == 0) {
            a->sign = 1;
        }
    }
    bi_normalize(a);
    if (bi_is_zero(a)) {
        a->sign = 0;
    } else if (neg) {
        a->sign = -1;
    } else {
        a->sign = 1;
    }
    return a;
}

static int bi_compare_abs(const BigInt *a, const BigInt *b) {
    if (a->len != b->len) {
        return (a->len < b->len) ? -1 : 1;
    }
    for (size_t i = a->len; i-- > 0;) {
        if (a->limbs[i] != b->limbs[i]) {
            return (a->limbs[i] < b->limbs[i]) ? -1 : 1;
        }
    }
    return 0;
}

int bi_compare(const BigInt *a, const BigInt *b) {
    if (a->sign != b->sign) {
        return (a->sign < b->sign) ? -1 : 1;
    }
    if (a->sign == 0) {
        return 0;
    }
    int cmp = bi_compare_abs(a, b);
    return a->sign * cmp;
}

static BigInt *bi_add_abs(const BigInt *a, const BigInt *b) {
    const BigInt *larger = a;
    const BigInt *smaller = b;
    if (b->len > a->len) {
        larger = b;
        smaller = a;
    }
    BigInt *res = bi_new();
    if (res == NULL) {
        return NULL;
    }
    bi_reserve(res, larger->len + 1);
    uint64_t carry = 0;
    size_t i = 0;
    for (i = 0; i < smaller->len; ++i) {
        uint64_t cur = (uint64_t)larger->limbs[i] + smaller->limbs[i] + carry;
        res->limbs[res->len++] = (uint32_t)(cur % BASE);
        carry = cur / BASE;
    }
    for (; i < larger->len; ++i) {
        uint64_t cur = (uint64_t)larger->limbs[i] + carry;
        res->limbs[res->len++] = (uint32_t)(cur % BASE);
        carry = cur / BASE;
    }
    if (carry != 0) {
        res->limbs[res->len++] = (uint32_t)carry;
    }
    res->sign = 1;
    bi_normalize(res);
    return res;
}

static BigInt *bi_sub_abs(const BigInt *a, const BigInt *b) {
    BigInt *res = bi_new();
    if (res == NULL) {
        return NULL;
    }
    bi_reserve(res, a->len);
    int64_t carry = 0;
    for (size_t i = 0; i < a->len; ++i) {
        int64_t cur = (int64_t)a->limbs[i] - ((i < b->len) ? b->limbs[i] : 0) + carry;
        if (cur < 0) {
            cur += BASE;
            carry = -1;
        } else {
            carry = 0;
        }
        res->limbs[res->len++] = (uint32_t)cur;
    }
    res->sign = 1;
    bi_normalize(res);
    return res;
}

BigInt *bi_add(const BigInt *a, const BigInt *b) {
    if (a->sign == 0) {
        return bi_clone(b);
    }
    if (b->sign == 0) {
        return bi_clone(a);
    }
    if (a->sign == b->sign) {
        BigInt *r = bi_add_abs(a, b);
        if (r != NULL) {
            r->sign = a->sign;
        }
        return r;
    }
    int cmp = bi_compare_abs(a, b);
    if (cmp == 0) {
        return bi_new();
    }
    if (cmp > 0) {
        BigInt *r = bi_sub_abs(a, b);
        if (r != NULL) {
            r->sign = a->sign;
        }
        return r;
    } else {
        BigInt *r = bi_sub_abs(b, a);
        if (r != NULL) {
            r->sign = b->sign;
        }
        return r;
    }
}

BigInt *bi_sub(const BigInt *a, const BigInt *b) {
    BigInt nb = *b;
    nb.sign = -nb.sign;
    return bi_add(a, &nb);
}

BigInt *bi_mul(const BigInt *a, const BigInt *b) {
    if (bi_is_zero(a) || bi_is_zero(b)) {
        return bi_new();
    }
    BigInt *res = bi_new();
    if (res == NULL) {
        return NULL;
    }
    size_t max_len = a->len + b->len + 1;  // +1 for possible final carry
    bi_reserve(res, max_len);
    memset(res->limbs, 0, max_len * sizeof(uint32_t));

    for (size_t i = 0; i < a->len; ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->len; ++j) {
            size_t k = i + j;
            uint64_t cur = res->limbs[k] + (uint64_t)a->limbs[i] * b->limbs[j] + carry;
            res->limbs[k] = (uint32_t)(cur % BASE);
            carry = cur / BASE;
        }
        size_t k = i + b->len;
        uint64_t cur = res->limbs[k] + carry;
        res->limbs[k] = (uint32_t)(cur % BASE);
        carry = cur / BASE;
        size_t kk = k + 1;
        while (carry != 0) {
            if (kk >= res->cap) {
                bi_reserve(res, kk + 1);
                // newly allocated limbs are uninitialized; zero the new part
                memset(res->limbs + kk, 0, (res->cap - kk) * sizeof(uint32_t));
            }
            cur = res->limbs[kk] + carry;
            res->limbs[kk] = (uint32_t)(cur % BASE);
            carry = cur / BASE;
            kk++;
        }
    }
    res->len = max_len;
    bi_normalize(res);
    res->sign = a->sign * b->sign;
    return res;
}

static void bi_divmod_small(BigInt *a, uint32_t m, uint32_t *rem) {
    uint64_t r = 0;
    for (size_t i = a->len; i-- > 0;) {
        uint64_t cur = a->limbs[i] + r * BASE;
        a->limbs[i] = (uint32_t)(cur / m);
        r = cur % m;
    }
    if (rem != NULL) {
        *rem = (uint32_t)r;
    }
    bi_normalize(a);
    if (a->len == 0) {
        a->sign = 0;
    }
}

BigInt *bi_div(const BigInt *a, const BigInt *b, BigInt **rem_out) {
    if (bi_is_zero(b)) {
        return NULL;
    }
    if (bi_is_zero(a)) {
        BigInt *zero = bi_new();
        if (rem_out != NULL) {
            *rem_out = bi_new();
        }
        return zero;
    }
    int cmp = bi_compare_abs(a, b);
    if (cmp < 0) {
        BigInt *zero = bi_new();
        if (rem_out != NULL) {
            *rem_out = bi_clone(a);
        }
        return zero;
    }
    if (cmp == 0) {
        BigInt *one = bi_from_int64(1);
        if (one == NULL) {
            return NULL;
        }
        one->sign = a->sign * b->sign;
        if (rem_out != NULL) {
            *rem_out = bi_new();
        }
        return one;
    }

    BigInt *quot = bi_new();
    BigInt *rem = bi_new();
    if (quot == NULL || rem == NULL) {
        bi_free(quot);
        bi_free(rem);
        return NULL;
    }
    bi_reserve(quot, a->len);
    bi_reserve(rem, a->len);

    for (size_t i = 0; i < a->len; ++i) {
        rem->limbs[i] = 0;
    }
    rem->len = 0;
    rem->sign = 0;

    for (size_t idx = a->len; idx-- > 0;) {
        if (rem->len + 1 > rem->cap) {
            bi_reserve(rem, rem->len + 1);
        }
        for (size_t j = rem->len; j > 0; --j) {
            rem->limbs[j] = rem->limbs[j - 1];
        }
        rem->limbs[0] = a->limbs[idx];
        rem->len++;
        bi_normalize(rem);

        uint32_t low = 0;
        uint32_t high = BASE - 1;
        uint32_t best = 0;
        while (low <= high) {
            uint32_t mid = low + (high - low) / 2;
            BigInt *t = bi_from_int64(mid);
            BigInt *prod = bi_mul(b, t);
            int cmp2 = bi_compare_abs(prod, rem);
            bi_free(t);
            if (cmp2 <= 0) {
                best = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
            bi_free(prod);
        }
        BigInt *bestv = bi_from_int64(best);
        BigInt *prod = bi_mul(b, bestv);
        BigInt *newrem = bi_sub(rem, prod);
        bi_free(rem);
        rem = newrem;
        bi_free(bestv);
        bi_free(prod);

        quot->limbs[idx] = best;
    }
    quot->len = a->len;
    bi_normalize(quot);
    bi_normalize(rem);
    quot->sign = a->sign * b->sign;
    if (rem->len == 0) {
        rem->sign = 0;
    } else {
        rem->sign = a->sign;
    }
    if (rem_out != NULL) {
        *rem_out = rem;
    } else {
        bi_free(rem);
    }
    return quot;
}

char *bi_to_decimal(const BigInt *a) {
    if (bi_is_zero(a)) {
        char *s = (char *)malloc(2);
        if (s == NULL) {
            return NULL;
        }
        strcpy(s, "0");
        return s;
    }
    // Convert by repeated divmod 1e9; independent of limb BASE.
    BigInt *tmp = bi_clone(a);
    if (tmp == NULL) {
        return NULL;
    }
    if (tmp->sign < 0) {
        tmp->sign = -tmp->sign;
    }
    uint32_t parts_cap = 8;
    uint32_t parts_len = 0;
    uint32_t *parts = (uint32_t *)malloc(parts_cap * sizeof(uint32_t));
    if (parts == NULL) {
        bi_free(tmp);
        return NULL;
    }
    while (!bi_is_zero(tmp)) {
        uint32_t rem = 0;
        bi_divmod_small(tmp, 1000000000U, &rem);
        if (parts_len == parts_cap) {
            parts_cap *= 2;
            uint32_t *np = (uint32_t *)realloc(parts, parts_cap * sizeof(uint32_t));
            if (np == NULL) {
                free(parts);
                bi_free(tmp);
                return NULL;
            }
            parts = np;
        }
        parts[parts_len++] = rem;
    }
    bi_free(tmp);

    size_t bufsize = (size_t)parts_len * BASE_DIGITS + 2;
    char *buf = (char *)malloc(bufsize);
    if (buf == NULL) {
        free(parts);
        return NULL;
    }
    size_t pos = 0;
    if (a->sign < 0) {
        buf[pos++] = '-';
    }
    // highest part without zero padding
    pos += snprintf(buf + pos, bufsize - pos, "%u", parts[parts_len - 1]);
    for (int i = (int)parts_len - 2; i >= 0; --i) {
        pos += snprintf(buf + pos, bufsize - pos, "%0*u", BASE_DIGITS, parts[i]);
    }
    buf[pos] = '\0';
    free(parts);
    return buf;
}

BigInt *bi_from_le_bytes(const uint8_t *data, size_t n) {
    BigInt *a = bi_new();
    if (a == NULL) {
        return NULL;
    }
    for (size_t i = n; i-- > 0;) {
        if (a->sign == 0 && a->len == 0 && data[i] == 0) {
            continue;
        }
        if (bi_is_zero(a)) {
            bi_reserve(a, 1);
            a->len = 1;
            a->limbs[0] = 0;
            a->sign = 1;
        }
        bi_shift_left_small(a, 256);
        bi_add_small(a, data[i]);
    }
    bi_normalize(a);
    if (a->len != 0) {
        a->sign = 1;
    } else {
        a->sign = 0;
    }
    return a;
}

#if 0
size_t bi_to_le_bytes(const BigInt *a, uint8_t *out, size_t max) {
    if (bi_is_zero(a)) {
        if (out != NULL && max > 0) {
            out[0] = 0;
        }
        return 1;
    }
    BigInt *tmp = bi_clone(a);
    if (tmp == NULL) {
        return 0;
    }
    tmp->sign = 1;
    size_t idx = 0;
    while (!bi_is_zero(tmp)) {
        uint32_t rem = 0;
        bi_divmod_small(tmp, 256, &rem);
        if (out != NULL && idx < max) {
            out[idx] = (uint8_t)rem;
        }
        idx++;
    }
    bi_free(tmp);
    return idx;
}
#else
size_t bi_to_le_bytes_unsafe(const BigInt *a, uint8_t *out) {
    if (bi_is_zero(a)) {
        if (out != NULL) {
            out[0] = 0;
        }
        return 1;
    }
    BigInt *tmp = bi_clone(a);
    if (tmp == NULL) {
        return 0;
    }
    tmp->sign = 1;
    size_t idx = 0;
    while (!bi_is_zero(tmp)) {
        uint32_t rem = 0;
        bi_divmod_small(tmp, 256, &rem);
        if (out != NULL) {
            out[idx] = (uint8_t)rem;
        }
        idx++;
    }
    bi_free(tmp);
    return idx;
}
#endif
