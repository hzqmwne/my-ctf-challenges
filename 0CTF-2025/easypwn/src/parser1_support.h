#ifndef PARSER1_SUPPORT_H
#define PARSER1_SUPPORT_H

#include "bigint.h"

typedef struct Lex1Extra {
    int comment_depth;
} Lex1Extra;

typedef enum {
    NODE_NUM,
    NODE_ADD,
    NODE_SUB,
    NODE_MUL,
    NODE_DIV,
    NODE_NEG
} P1NodeKind;

typedef struct ASTNode {
    P1NodeKind kind;
    BigInt *value;
    struct ASTNode *lhs;
    struct ASTNode *rhs;
} ASTNode;

#if DEBUG
typedef enum {
    P1_ERR_NONE = 0,
    P1_ERR_SYNTAX = 1,
    P1_ERR_DIV_ZERO = 2,
    P1_ERR_INT32 = 3,
} Parser1Error;
#else
typedef enum {
    P1_ERR_NONE = 0,
    P1_ERR_SYNTAX = 1,
    P1_ERR_DIV_ZERO = 1,  // 2,  obfuscated
    P1_ERR_INT32 = 1,     // 3,  obfuscated
} Parser1Error;
#endif

typedef struct Parser1Context {
    BigInt *result;
    Parser1Error error_code;
} Parser1Context;

ASTNode *p1_ast_new_num(BigInt *v);
ASTNode *p1_ast_new_bin(int op, ASTNode *a, ASTNode *b);
ASTNode *p1_ast_new_un(int op, ASTNode *a);
void p1_ast_free(ASTNode *n);
BigInt *p1_ast_eval(ASTNode *n, int *div_zero);
int p1_check_int32(const BigInt *n);
const char *p1_errmsg(Parser1Error code);

#endif
