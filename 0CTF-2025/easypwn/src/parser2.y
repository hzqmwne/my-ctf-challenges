%{
#include <stdio.h>
#include "bigint.h"
#include "parser2_support.h"

typedef union P2STYPE P2STYPE;
typedef void *yyscan_t;
typedef struct yy_buffer_state *YY_BUFFER_STATE;
typedef struct Lex2Extra Lex2Extra;
int p2lex_init_extra(void *user_defined, yyscan_t *scanner);
int p2lex_destroy(yyscan_t yyscanner);
YY_BUFFER_STATE p2_scan_string(const char *str, yyscan_t scanner);
void p2_delete_buffer(YY_BUFFER_STATE b, yyscan_t scanner);
int p2lex(P2STYPE *yylval_param, yyscan_t scanner);

static void p2error(Parser2Context *ctx, yyscan_t scanner, const char *msg) {
    (void)scanner;
    (void)msg;
    ctx->error_code = P2_ERR_SYNTAX;
}
%}

%code requires {
#include "parser2_support.h"
typedef struct Lex2Extra {
    int comment_depth;
} Lex2Extra;
}

%define api.pure full
%define api.prefix {p2}
%lex-param { yyscan_t scanner }
%parse-param { Parser2Context *ctx }
%parse-param { yyscan_t scanner }
%define parse.error simple

%union {
    BigInt *big;
}

%token <big> NUMBER
%left '+' '-'
%left '*' '/'
%precedence UMINUS
%type <big> expr

%%
input:
      expr { ctx->result = $1; }
    ;

expr:
      expr '+' expr { BigInt *t = bi_add($1, $3); bi_free($1); bi_free($3); $$ = t; }
    | expr '-' expr { BigInt *t = bi_sub($1, $3); bi_free($1); bi_free($3); $$ = t; }
    | expr '*' expr { BigInt *t = bi_mul($1, $3); bi_free($1); bi_free($3); $$ = t; }
    | expr '/' expr {
          BigInt *zero = bi_new();
          int is_zero = bi_compare($3, zero) == 0;
          bi_free(zero);
          if (is_zero != 0) {
              ctx->error_code = P2_ERR_DIV_ZERO;
              bi_free($1);
              bi_free($3);
              YYERROR;
          }
          BigInt *t = bi_div($1, $3, NULL);
          bi_free($1);
          bi_free($3);
          $$ = t;
      }
    | '-' expr %prec UMINUS {
          BigInt *zero = bi_new();
          BigInt *t = bi_sub(zero, $2);
          bi_free(zero);
          bi_free($2);
          $$ = t;
      }
    | '(' expr ')' { $$ = $2; }
    | NUMBER { $$ = $1; }
    ;
%%

Parser2Error parse2_run(const char *input, BigInt **out) {
    Parser2Context ctx = (Parser2Context){0};
    yyscan_t scanner;
    Lex2Extra extra = {0};
    if (p2lex_init_extra(&extra, &scanner) != 0) {
        if (out != NULL) {
            *out = NULL;
        }
        return P2_ERR_SYNTAX;
    }
    YY_BUFFER_STATE buf = p2_scan_string(input, scanner);
    int ret = p2parse(&ctx, scanner);
    p2_delete_buffer(buf, scanner);
    p2lex_destroy(scanner);
    if (ret != 0 || ctx.error_code != P2_ERR_NONE) {
        Parser2Error code = (ctx.error_code != P2_ERR_NONE) ? ctx.error_code : P2_ERR_SYNTAX;
        if (out != NULL) {
            *out = NULL;
        }
        if (ctx.result != NULL) {
            bi_free(ctx.result);
        }
        return code;
    }
    if (out != NULL) {
        *out = ctx.result;
    }
    return P2_ERR_NONE;
}
