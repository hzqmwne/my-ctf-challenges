#ifndef PARSER2_SUPPORT_H
#define PARSER2_SUPPORT_H

#include "bigint.h"

#if DEBUG
typedef enum {
    P2_ERR_NONE = 0,
    P2_ERR_SYNTAX = 1,
    P2_ERR_DIV_ZERO = 2,
} Parser2Error;
#else
typedef enum {
    P2_ERR_NONE = 0,
    P2_ERR_SYNTAX = 1,
    P2_ERR_DIV_ZERO = 1, // 2, obfuscated
} Parser2Error;
#endif

typedef struct Parser2Context {
    BigInt *result;
    Parser2Error error_code;
} Parser2Context;

const char *p2_errmsg(Parser2Error code);

#endif
