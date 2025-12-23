%option noyywrap
%option reentrant
%option bison-bridge
%option nounput noinput
%option prefix="p2"
%x SLASH
%x COMMENT
%x CMTSTAR

%{
#define _POSIX_C_SOURCE 200809L
#include "parser2.tab.h"
#include "bigint.h"
#include "parser2_support.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int fileno(FILE *);

#ifndef PARSER_IO
#define PARSER_IO 0
#endif

static void p2_yyfatal_silent(yyscan_t yyscanner) __attribute__((unused));
static void p2_yyfatal_silent(yyscan_t yyscanner) { (void)yyscanner; }
#undef YY_FATAL_ERROR
#define YY_FATAL_ERROR(msg) p2_yyfatal_silent(yyscanner)

#define YYSTYPE P2STYPE
#define YY_DECL int p2lex(YYSTYPE *yylval_param, yyscan_t yyscanner)
%}

ws      [ \t\r\n]+
num     [0-9]+

%%
{ws}            { /* skip whitespace */ }
"/"            { BEGIN(SLASH); }
{num}           { yylval->big = bi_from_decimal(yytext); BEGIN(INITIAL); return NUMBER; }
"+"            { BEGIN(INITIAL); return '+'; }
"-"            { BEGIN(INITIAL); return '-'; }
"*"            { BEGIN(INITIAL); return '*'; }
"("            { BEGIN(INITIAL); return '('; }
")"            { BEGIN(INITIAL); return ')'; }
.               { BEGIN(INITIAL); return yytext[0]; }

<SLASH>"*"     { Lex2Extra *ex = (Lex2Extra*)yyget_extra(yyscanner); if (ex->comment_depth == 0) { ex->comment_depth = 1; } else { ex->comment_depth++; } BEGIN(COMMENT); }
<SLASH>.        { Lex2Extra *ex = (Lex2Extra*)yyget_extra(yyscanner); if (ex->comment_depth == 0) { yyless(0); BEGIN(INITIAL); return '/'; } BEGIN(COMMENT); }
<SLASH><<EOF>>  { Lex2Extra *ex = (Lex2Extra*)yyget_extra(yyscanner); if (ex->comment_depth == 0) { BEGIN(INITIAL); return '/'; } return 0; }

<COMMENT>"*"   { BEGIN(CMTSTAR); }
<COMMENT>"/"   { BEGIN(SLASH); }
<COMMENT>.      { /* consume */ }
<COMMENT>\n     { }
<COMMENT><<EOF>> { return 0; }

<CMTSTAR>"/"   { Lex2Extra *ex = (Lex2Extra*)yyget_extra(yyscanner); ex->comment_depth--; if (ex->comment_depth == 0) { BEGIN(INITIAL); } else { BEGIN(COMMENT); } }
<CMTSTAR>"*"   { BEGIN(CMTSTAR); }
<CMTSTAR>.      { BEGIN(COMMENT); }
<CMTSTAR>\n     { BEGIN(COMMENT); }
%%
