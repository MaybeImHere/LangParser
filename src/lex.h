#pragma once

#include "err.h"
#include "strings.h"

typedef enum TokenType {
    Token_Integer,
    Token_Identifier,

    Token_Plus,
    Token_Minus,
    Token_Asterisk,
    Token_OpenParen,
    Token_CloseParen,
    Token_OpenBracket,
    Token_CloseBracket,
    Token_Eq,
    Token_Division,
    Token_Semicolon,
    Token_Eof,

    // keywords
    Token_If,
    Token_Else,
} TokenType;

typedef struct Token {
    TokenType token_type;
    String token_data;
} Token;

// Creates a token from the token type and the given string data.
Token Token_Create(TokenType token_type, const byte *data, UInt length);

// Prints the token. Note that this is only for debugging purposes, so it isn't very pretty.
void Token_Print(const Token *token);

// Returns the next token present within the chracter stream. Returns Error_UnknownToken if unable
// to parse the next token.
// Error_UnknownToken
Error Token_Parse(StringStream *character_stream, Token *out);