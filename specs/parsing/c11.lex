# c11.lex - C11 Lexer Specification
# ═══════════════════════════════════════════════════════════════════════════
#
# Lexer rules for C11 subset used in IR-based live reload.
# Input to lexgen: generates c11_lex.c,h
#
# Usage: ./build/lexgen specs/parsing/c11.lex gen/parsing c11
#
# Format:
#   pattern  -> TOKEN_NAME  { optional action }
#
# Patterns use extended regex syntax.
# Actions are optional C code blocks.
#
# ═══════════════════════════════════════════════════════════════════════════

@name c11
@prefix c11
@include "c11_tokens.h"

# ─── Options ────────────────────────────────────────────────────────────────

@option case_sensitive true
@option track_line     true
@option track_column   true

# ─── State Definitions ──────────────────────────────────────────────────────

@state INITIAL      "Default state"
@state IN_COMMENT   "Inside /* */ comment"
@state IN_STRING    "Inside string literal"
@state IN_CHAR      "Inside character literal"

# ─── Whitespace and Comments ────────────────────────────────────────────────

[ \t\r]+            -> SKIP         { /* skip whitespace */ }
\n                  -> NEWLINE      { lex->line++; lex->col = 1; }

"//"[^\n]*          -> SKIP         { /* single-line comment */ }

"/*"                -> PUSH(IN_COMMENT) { /* start block comment */ }
<IN_COMMENT>"*/"    -> POP          { /* end block comment */ }
<IN_COMMENT>[^*]+   -> SKIP         { /* comment content */ }
<IN_COMMENT>"*"     -> SKIP         { /* lone * in comment */ }
<IN_COMMENT>\n      -> SKIP         { lex->line++; }

# ─── Keywords (must come before IDENT) ──────────────────────────────────────

"auto"              -> AUTO
"break"             -> BREAK
"case"              -> CASE
"char"              -> CHAR
"const"             -> CONST
"continue"          -> CONTINUE
"default"           -> DEFAULT
"do"                -> DO
"double"            -> DOUBLE
"else"              -> ELSE
"enum"              -> ENUM
"extern"            -> EXTERN
"float"             -> FLOAT
"for"               -> FOR
"goto"              -> GOTO
"if"                -> IF
"inline"            -> INLINE
"int"               -> INT
"long"              -> LONG
"register"          -> REGISTER
"restrict"          -> RESTRICT
"return"            -> RETURN
"short"             -> SHORT
"signed"            -> SIGNED
"sizeof"            -> SIZEOF
"static"            -> STATIC
"struct"            -> STRUCT
"switch"            -> SWITCH
"typedef"           -> TYPEDEF
"union"             -> UNION
"unsigned"          -> UNSIGNED
"void"              -> VOID
"volatile"          -> VOLATILE
"while"             -> WHILE
"_Bool"             -> _BOOL
"_Complex"          -> _COMPLEX
"_Imaginary"        -> _IMAGINARY

# ─── Identifiers ────────────────────────────────────────────────────────────

[a-zA-Z_][a-zA-Z0-9_]*  -> IDENT    { c11_save_ident(lex); }

# ─── Integer Literals ───────────────────────────────────────────────────────

0[xX][0-9a-fA-F]+[uUlL]*        -> INT_LIT  { c11_parse_hex(lex); }
0[0-7]+[uUlL]*                  -> INT_LIT  { c11_parse_octal(lex); }
0[bB][01]+[uUlL]*               -> INT_LIT  { c11_parse_binary(lex); }
[0-9]+[uUlL]*                   -> INT_LIT  { c11_parse_decimal(lex); }

# ─── Float Literals ─────────────────────────────────────────────────────────

[0-9]+\.[0-9]*([eE][+-]?[0-9]+)?[fFlL]?   -> FLOAT_LIT { c11_parse_float(lex); }
[0-9]*\.[0-9]+([eE][+-]?[0-9]+)?[fFlL]?   -> FLOAT_LIT { c11_parse_float(lex); }
[0-9]+[eE][+-]?[0-9]+[fFlL]?              -> FLOAT_LIT { c11_parse_float(lex); }

# ─── String Literals ────────────────────────────────────────────────────────

\"                  -> PUSH(IN_STRING) { c11_start_string(lex); }
<IN_STRING>\"       -> STRING_LIT, POP { c11_end_string(lex); }
<IN_STRING>\\n      -> SKIP         { c11_append_char(lex, '\n'); }
<IN_STRING>\\t      -> SKIP         { c11_append_char(lex, '\t'); }
<IN_STRING>\\r      -> SKIP         { c11_append_char(lex, '\r'); }
<IN_STRING>\\\\     -> SKIP         { c11_append_char(lex, '\\'); }
<IN_STRING>\\\"     -> SKIP         { c11_append_char(lex, '"'); }
<IN_STRING>\\[0-7]{1,3}   -> SKIP   { c11_append_octal_escape(lex); }
<IN_STRING>\\x[0-9a-fA-F]+  -> SKIP { c11_append_hex_escape(lex); }
<IN_STRING>[^\"\\]+  -> SKIP        { c11_append_text(lex); }
<IN_STRING>\n       -> ERROR        { c11_error(lex, "unterminated string"); }

# ─── Character Literals ─────────────────────────────────────────────────────

\'                  -> PUSH(IN_CHAR) { c11_start_char(lex); }
<IN_CHAR>\'         -> CHAR_LIT, POP { c11_end_char(lex); }
<IN_CHAR>\\n        -> SKIP         { lex->char_value = '\n'; }
<IN_CHAR>\\t        -> SKIP         { lex->char_value = '\t'; }
<IN_CHAR>\\r        -> SKIP         { lex->char_value = '\r'; }
<IN_CHAR>\\\\       -> SKIP         { lex->char_value = '\\'; }
<IN_CHAR>\\'        -> SKIP         { lex->char_value = '\''; }
<IN_CHAR>\\[0-7]{1,3}   -> SKIP     { c11_parse_char_octal(lex); }
<IN_CHAR>\\x[0-9a-fA-F]+  -> SKIP   { c11_parse_char_hex(lex); }
<IN_CHAR>[^\'\\]    -> SKIP         { lex->char_value = lex->text[0]; }
<IN_CHAR>\n         -> ERROR        { c11_error(lex, "unterminated char"); }

# ─── Multi-character Operators (longest match first) ────────────────────────

"..."               -> ELLIPSIS
"<<="               -> LTLTEQ
">>="               -> GTGTEQ
"->"                -> ARROW
"++"                -> PLUSPLUS
"--"                -> MINUSMINUS
"<<"                -> LTLT
">>"                -> GTGT
"<="                -> LTEQ
">="                -> GTEQ
"=="                -> EQEQ
"!="                -> BANGEQ
"&&"                -> AMPAMP
"||"                -> PIPEPIPE
"+="                -> PLUSEQ
"-="                -> MINUSEQ
"*="                -> STAREQ
"/="                -> SLASHEQ
"%="                -> PERCENTEQ
"&="                -> AMPEQ
"|="                -> PIPEEQ
"^="                -> CARETEQ

# ─── Single-character Operators and Punctuation ─────────────────────────────

"+"                 -> PLUS
"-"                 -> MINUS
"*"                 -> STAR
"/"                 -> SLASH
"%"                 -> PERCENT
"&"                 -> AMP
"|"                 -> PIPE
"^"                 -> CARET
"~"                 -> TILDE
"!"                 -> BANG
"<"                 -> LT
">"                 -> GT
"="                 -> EQ
"?"                 -> QUESTION
":"                 -> COLON
","                 -> COMMA
";"                 -> SEMI
"."                 -> DOT
"("                 -> LPAREN
")"                 -> RPAREN
"{"                 -> LBRACE
"}"                 -> RBRACE
"["                 -> LBRACKET
"]"                 -> RBRACKET

# ─── End of File ────────────────────────────────────────────────────────────

<<EOF>>             -> EOF_TOK

# ─── Error Fallback ─────────────────────────────────────────────────────────

.                   -> ERROR        { c11_error(lex, "unexpected character"); }
