%option noyywrap
%option reentrant
%option bison-bridge
%option nounput noinput
%option prefix="p1"
%x SLASH
%x COMMENT
%x CMTSTAR
%x STAR_OUT

%{
#define _POSIX_C_SOURCE 200809L
#include "parser1.tab.h"
#include "bigint.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int fileno(FILE *);

#ifndef PARSER_IO
#define PARSER_IO 0
#endif

static void p1_yyfatal_silent(yyscan_t yyscanner) __attribute__((unused));
static void p1_yyfatal_silent(yyscan_t yyscanner) { (void)yyscanner; }
#undef YY_FATAL_ERROR
#define YY_FATAL_ERROR(msg) p1_yyfatal_silent(yyscanner)

#define YYSTYPE P1STYPE
#define YY_DECL int p1lex(YYSTYPE *yylval_param, yyscan_t yyscanner)
%}

ws      [ \t\r\n]+
num     [0-9]+

%%
{ws}            { /* skip whitespace */ }
"/"            { BEGIN(SLASH); }
"*"            { BEGIN(STAR_OUT); }
{num}           { yylval->big = bi_from_decimal(yytext); BEGIN(INITIAL); return NUMBER; }
"+"            { BEGIN(INITIAL); return '+'; }
"-"            { BEGIN(INITIAL); return '-'; }
"("            { BEGIN(INITIAL); return '('; }
")"            { BEGIN(INITIAL); return ')'; }
.               { BEGIN(INITIAL); return yytext[0]; }

<SLASH>"*"     { BEGIN(COMMENT); }
<SLASH>.        { yyless(0); BEGIN(INITIAL); return '/'; }
<SLASH><<EOF>>  { BEGIN(INITIAL); return '/'; }

<COMMENT>"*"   { BEGIN(CMTSTAR); }
<COMMENT>.      { /* consume */ }
<COMMENT>\n     { /* consume */ }
<COMMENT><<EOF>> { return 0; }

<CMTSTAR>"/"   { BEGIN(INITIAL); }
<CMTSTAR>"*"   { BEGIN(CMTSTAR); }
<CMTSTAR>.      { BEGIN(COMMENT); }
<CMTSTAR>\n     { BEGIN(COMMENT); }

<STAR_OUT>"/"  { BEGIN(INITIAL); if (PARSER_IO) { fprintf(stderr, "warning: stray */ ignored\n"); } }
<STAR_OUT>.     { yyless(0); BEGIN(INITIAL); return '*'; }
<STAR_OUT><<EOF>> { BEGIN(INITIAL); return '*'; }
%%
