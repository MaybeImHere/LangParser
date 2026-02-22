#include "lex.h"
#include "test.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    String test_string = StringFromLiteral("123  hello    +- * ( ) { } = / ;   if  else ");
    TokenType expected[] = {
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

        // keywords
        Token_If,
        Token_Else,
        Token_Eof,
    };
    const char *expected_str[] = {"123", "hello", "+", "-", "*",  "(",    ")", "{",
                                  "}",   "=",     "/", ";", "if", "else", ""};
    StringStream ss;
    StringStream_Init(&ss, &test_string);

    // done with initialization, now try lexing.
    // here, we check if the token type and expected strings are correct.
    for (UInt i = 0; expected[i] != Token_Eof; i++) {
        Token token;
        Error err = Token_Parse(&ss, &token);
        NOFAIL("Token_Parse");

        if (token.token_type != expected[i]) {
            printf("Expected %d, found %d.\n", expected[i], token.token_type);
            ERROR("Token_Parse: unexpected token.");
        }

        if (token.token_type != Token_Eof) {
            if (!String_IsStaticEqual(&token.token_data, expected_str[i])) {
                printf("Token %d: expected %s, found '", token.token_type, expected_str[i]);
                String_Print(&token.token_data);
                putchar('\'');
                putchar('\n');
                ERROR("Token_Parse: unexpected token.");
            }
        }
    }

    // now, make sure it can error gracefully.
    String es = StringFromLiteral("%~`");
    StringStream_Init(&ss, &es);

    Token token;
    Error err = Token_Parse(&ss, &token);
    if (err == Error_Good) {
        ERROR("Token_Parse: should have been an error!");
    } else if (err != Error_UnknownToken) {
        ERROR("Token_Parse: should have returned Error_UnexpectedToken!");
    }

    return 0;
}