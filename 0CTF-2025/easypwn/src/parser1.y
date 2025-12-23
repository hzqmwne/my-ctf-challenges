%{
#include <stdio.h>
#include "bigint.h"
#include "parser1_support.h"

typedef union P1STYPE P1STYPE;
typedef void *yyscan_t;
typedef struct yy_buffer_state *YY_BUFFER_STATE;
int p1lex_init(yyscan_t *scanner);
int p1lex_destroy(yyscan_t yyscanner);
YY_BUFFER_STATE p1_scan_string(const char *str, yyscan_t scanner);
void p1_delete_buffer(YY_BUFFER_STATE b, yyscan_t scanner);
int p1lex(P1STYPE *yylval_param, yyscan_t scanner);

static void p1error(Parser1Context *ctx, yyscan_t scanner, const char *msg) {
    (void)scanner;
    (void)msg;
    ctx->error_code = P1_ERR_SYNTAX;
}
%}

%code requires {
#include "parser1_support.h"
}

%define api.pure full
%define api.prefix {p1}
%lex-param { yyscan_t scanner }
%parse-param { Parser1Context *ctx }
%parse-param { yyscan_t scanner }
%define parse.error simple

%union {
    BigInt *big;
    ASTNode *node;
}

%token <big> NUMBER
%left '+' '-'
%left '*' '/'
%precedence UMINUS
%type <node> expr

%%
input:
      expr {
          int div_zero = 0;
          ctx->result = p1_ast_eval($1, &div_zero);
          if (div_zero != 0) {
              ctx->error_code = P1_ERR_DIV_ZERO;
          } else if (ctx->result != NULL && p1_check_int32(ctx->result) != 0) {
              ctx->error_code = P1_ERR_INT32;
          }
          p1_ast_free($1);
      }
    ;

expr:
      expr '+' expr { $$ = p1_ast_new_bin('+', $1, $3); }
    | expr '-' expr { $$ = p1_ast_new_bin('-', $1, $3); }
    | expr '*' expr { $$ = p1_ast_new_bin('*', $1, $3); }
    | expr '/' expr { $$ = p1_ast_new_bin('/', $1, $3); }
    | '-' expr %prec UMINUS { $$ = p1_ast_new_un('-', $2); }
    | '(' expr ')' { $$ = $2; }
    | NUMBER { $$ = p1_ast_new_num($1); }
    ;
%%

Parser1Error parse1_run(const char *input, BigInt **out) {
    Parser1Context ctx = (Parser1Context){0};
    yyscan_t scanner;
    if (p1lex_init(&scanner) != 0) {
        if (out != NULL) {
            *out = NULL;
        }
        return P1_ERR_SYNTAX;
    }
    YY_BUFFER_STATE buf = p1_scan_string(input, scanner);
    int ret = p1parse(&ctx, scanner);
    p1_delete_buffer(buf, scanner);
    p1lex_destroy(scanner);
    if (ret != 0 || ctx.error_code != P1_ERR_NONE) {
        Parser1Error code = (ctx.error_code != P1_ERR_NONE) ? ctx.error_code : P1_ERR_SYNTAX;
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
    return P1_ERR_NONE;
}
