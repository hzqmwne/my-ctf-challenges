#include "parser1_support.h"

#include <stdlib.h>
#include <limits.h>

static ASTNode *p1_ast_alloc(void) {
    ASTNode *n = (ASTNode *)calloc(1, sizeof(ASTNode));
    if (n == NULL) {
        return NULL;
    }
    return n;
}

ASTNode *p1_ast_new_num(BigInt *v) {
    ASTNode *n = p1_ast_alloc();
    if (n == NULL) {
        return NULL;
    }
    n->kind = NODE_NUM;
    n->value = v;
    return n;
}

ASTNode *p1_ast_new_bin(int op, ASTNode *a, ASTNode *b) {
    ASTNode *n = p1_ast_alloc();
    if (n == NULL) {
        return NULL;
    }
    n->lhs = a;
    n->rhs = b;
    switch (op) {
        case '+': {
            n->kind = NODE_ADD;
            break;
        }
        case '-': {
            n->kind = NODE_SUB;
            break;
        }
        case '*': {
            n->kind = NODE_MUL;
            break;
        }
        case '/': {
            n->kind = NODE_DIV;
            break;
        }
        default: {
            n->kind = NODE_ADD;
            break;
        }
    }
    return n;
}

ASTNode *p1_ast_new_un(int op, ASTNode *a) {
    ASTNode *n = p1_ast_alloc();
    if (n == NULL) {
        return NULL;
    }
    n->lhs = a;
    if (op == '-') {
        n->kind = NODE_NEG;
    } else {
        n->kind = NODE_NUM;
    }
    return n;
}

void p1_ast_free(ASTNode *n) {
    if (n == NULL) {
        return;
    }
    if (n->kind == NODE_NUM) {
        bi_free(n->value);
    }
    p1_ast_free(n->lhs);
    p1_ast_free(n->rhs);
    free(n);
}

BigInt *p1_ast_eval(ASTNode *n, int *div_zero) {
    if (n == NULL) {
        return bi_new();
    }
    switch (n->kind) {
        case NODE_NUM: {
            return bi_clone(n->value);
        }
        case NODE_NEG: {
            BigInt *zero = bi_new();
            BigInt *v = p1_ast_eval(n->lhs, div_zero);
            BigInt *res = bi_sub(zero, v);
            bi_free(zero);
            bi_free(v);
            return res;
        }
        case NODE_ADD: {
            BigInt *a = p1_ast_eval(n->lhs, div_zero);
            BigInt *b = p1_ast_eval(n->rhs, div_zero);
            BigInt *res = bi_add(a, b);
            bi_free(a);
            bi_free(b);
            return res;
        }
        case NODE_SUB: {
            BigInt *a = p1_ast_eval(n->lhs, div_zero);
            BigInt *b = p1_ast_eval(n->rhs, div_zero);
            BigInt *res = bi_sub(a, b);
            bi_free(a);
            bi_free(b);
            return res;
        }
        case NODE_MUL: {
            BigInt *a = p1_ast_eval(n->lhs, div_zero);
            BigInt *b = p1_ast_eval(n->rhs, div_zero);
            BigInt *res = bi_mul(a, b);
            bi_free(a);
            bi_free(b);
            return res;
        }
        case NODE_DIV: {
            BigInt *a = p1_ast_eval(n->lhs, div_zero);
            BigInt *b = p1_ast_eval(n->rhs, div_zero);
            BigInt *zero = bi_new();
            int is_zero = bi_compare(b, zero) == 0;
            bi_free(zero);
            if (is_zero != 0) {
                *div_zero = 1;
                bi_free(a);
                bi_free(b);
                return bi_new();
            }
            BigInt *res = bi_div(a, b, NULL);
            bi_free(a);
            bi_free(b);
            return res;
        }
        default: {
            return bi_new();
        }
    }
}

static BigInt *p1_int32_max(void) {
    static BigInt *v = NULL;
    if (v == NULL) {
        v = bi_from_int64(INT32_MAX);
    }
    return v;
}

static BigInt *p1_int32_min(void) {
    static BigInt *v = NULL;
    if (v == NULL) {
        v = bi_from_int64(INT32_MIN);
    }
    return v;
}

int p1_check_int32(const BigInt *n) {
    if (bi_compare(n, p1_int32_max()) > 0) {
        return -1;
    }
    if (bi_compare(n, p1_int32_min()) < 0) {
        return -1;
    }
    return 0;
}

