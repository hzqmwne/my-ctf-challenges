#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bigint.h"
#include "parser1_support.h"
#include "parser2_support.h"

Parser1Error parse1_run(const char *input, BigInt **out);
Parser2Error parse2_run(const char *input, BigInt **out);

#if DEBUG
const char *p1_errmsg(Parser1Error code) {
    switch (code) {
        case P1_ERR_NONE: {
            return NULL;
        }
        case P1_ERR_DIV_ZERO: {
            return "division by zero";
        }
        case P1_ERR_INT32: {
            return "int32 overflow";
        }
        case P1_ERR_SYNTAX:
        default: {
            return "syntax error";
        }
    }
}

const char *p2_errmsg(Parser2Error code) {
    switch (code) {
        case P2_ERR_NONE: {
            return NULL;
        }
        case P2_ERR_DIV_ZERO: {
            return "division by zero";
        }
        case P2_ERR_SYNTAX:
        default: {
            return "syntax error";
        }
    }
}
#endif

#if 0
static char *read_all_stdin(void) {
    size_t cap = 1024;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        return NULL;
    }
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            char *nbuf = (char *)realloc(buf, cap);
            if (!nbuf) {
                free(buf);
                return NULL;
            }
            buf = nbuf;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    return buf;
}

static void print_le(const BigInt *v) {
    size_t need = bi_to_le_bytes(v, NULL, 0);
    uint8_t *buf = (uint8_t *)malloc(need);
    if (!buf) {
        return;
    }
    bi_to_le_bytes(v, buf, need);
    printf(" (le bytes %zu): 0x", need);
    for (size_t i = 0; i < need; ++i) {
        printf("%02x", buf[i]);
    }
    free(buf);
}

static void show_result(const char *tag, BigInt *v) {
    char *s = bi_to_decimal(v);
    printf("[%s] %s", tag, s);
    print_le(v);
    printf("\n");
    free(s);
}

int main(void) {
    char *input = read_all_stdin();
    if (!input) {
        fprintf(stderr, "Failed to read input\n");
        return 1;
    }

    BigInt *r1 = NULL; BigInt *r2 = NULL;

    Parser1Error e1 = parse1_run(input, &r1);
    if (e1 != P1_ERR_NONE) {
        const char *msg = p1_errmsg(e1);
        fprintf(stderr, "First pass (non-nested comments) error: %d%s%s\n", (int)e1, msg ? " " : "", msg ? msg : "");
    } else {
        show_result("simulate (non-nested comments)", r1);
        bi_free(r1);
    }

    Parser2Error e2 = parse2_run(input, &r2);
    if (e2 != P2_ERR_NONE) {
        const char *msg = p2_errmsg(e2);
        fprintf(stderr, "Second pass (nested comments) error: %d%s%s\n", (int)e2, msg ? " " : "", msg ? msg : "");
    } else {
        show_result("actual (nested comments)", r2);
        bi_free(r2);
    }

    free(input);
    return 0;
}
#else

int main(void) {
    // readline，调用两个parser_run，然后bi_to_le_bytes_unsafe到栈上int（让parse2_run产生栈溢出）
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("> ");

    char *input = NULL;
    size_t input_len = 0;
    getline(&input, &input_len, stdin);

    if (input_len > 1024) {  // XXX
        // printf("Input too long\n");
        printf("error\n");
        return 1;
    }

    BigInt *r1 = NULL;
    BigInt *r2 = NULL;
    
#if DEBUG
    Parser1Error e1 = parse1_run(input, &r1);
    if (e1 != P1_ERR_NONE) {
        const char *msg = p1_errmsg(e1);
        printf("First pass (non-nested comments) error: %d%s%s\n", (int)e1, msg ? " " : "", msg ? msg : "");
    } else {
        // bi_to_le_bytes_unsafe(r1, (uint8_t *)&answer);
        // printf("simulate (non-nested comments): %d\n", answer);
        char *sr1 = bi_to_decimal(r1);
        printf("simulate (non-nested comments): %s\n", sr1);
        free(sr1);
        bi_free(r1);
    }

    Parser2Error e2 = parse2_run(input, &r2);
    if (e2 != P2_ERR_NONE) {
        const char *msg = p2_errmsg(e2);
        printf("Second pass (nested comments) error: %d%s%s\n", (int)e2, msg ? " " : "", msg ? msg : "");
    } else {
        // bi_to_le_bytes_unsafe(r2, (uint8_t *)&answer);
        // printf("actual (nested comments): %d\n", answer);
        char *sr2 = bi_to_decimal(r2);
        printf("actual (nested comments): %s\n", sr2);
        bi_free(r2);
    }
#else
    Parser1Error e1 = parse1_run(input, &r1);
    if (e1 != P1_ERR_NONE) {
        printf("error\n");
        return 1;
    }
    free(r1);

    Parser2Error e2 = parse2_run(input, &r2);
    if (e2 != P2_ERR_NONE) {
        printf("error\n");
        return 1;
    }

    /*
    char *sr2 = bi_to_decimal(r2);
    printf("actual (nested comments): %s\n", sr2);
    free(sr2);
    */

    int answer = 0;
    bi_to_le_bytes_unsafe(r2, (uint8_t *)&answer);
    bi_free(r2);
    printf("%d\n", answer);

    free(input);
#endif

    return 0;
}

#endif
