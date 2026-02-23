#include "lex.h"
#include <stdio.h>

static bool IsWhitespace(byte b) { return b <= 32 || b >= 127; }
static bool IsIdent(byte b) {
    return ('a' <= b && 'z' >= b) || ('A' <= b && 'Z' >= b) || (b == '_');
}
static bool IsInteger(byte b) { return ('0' <= b && '9' >= b); }
static bool IsIdentMiddle(byte b) { return IsIdent(b) || IsInteger(b); }

Token Token_Create(TokenType token_type, const byte *data, UInt length) {
    Token ret = {.token_type = token_type, .token_data = String_Create(data, length)};
    return ret;
}

static const char *token_map[] = {
    "Token_Integer",      "Token_Identifier", "Token_Plus",       "Token_Minus",
    "Token_Asterisk",     "Token_OpenParen",  "Token_CloseParen", "Token_OpenBracket",
    "Token_CloseBracket", "Token_Eq",         "Token_Division",   "Token_Semicolon",
    "Token_Eof",          "Token_If",         "Token_Else",
};

void Token_Print(const Token *token) {
    printf("%s '", token_map[token->token_type]);
    String_Print(&token->token_data);
    putchar('\'');
}

// Skips characters from the character stream while they match the parse function. If the character
// doesn't match, it will be left on the stream, and can be peeked later.
static void Token_ParseWhile(StringStream *character_stream, bool (*parse_func)(byte),
                             UInt *valid_chars) {
    byte b;
    bool eof;

    // account for the character already parsed before.
    while (true) {
        eof = StringStream_IsEof(character_stream);
        if (eof)
            break;

        b = StringStream_Peek(character_stream);

        // parse identifier token
        if (!parse_func(b))
            break;

        (*valid_chars)++;
        // Just ignore the return value of Error_Eof, since it will be checked anyway.
        StringStream_Advance(character_stream);
    }
}

static bool Token_ParseOperators(StringStream *s, UInt *valid_chars, byte cur_byte,
                                 TokenType *out) {
    UInt valid_chars_original = *valid_chars;
    (*valid_chars)++;
    byte next_byte = 0;

    switch (cur_byte) {
    case '+':
        *out = Token_Plus;
        return true;
    case '-':
        *out = Token_Minus;
        return true;
    case '*':
        *out = Token_Asterisk;
        return true;
    case '(':
        *out = Token_OpenParen;
        return true;
    case ')':
        *out = Token_CloseParen;
        return true;
    case '=':;
        // Can be Token_Eq or Token_EqualBool
        next_byte = StringStream_Peek(s);
        if (next_byte == '=') {
            *out = Token_EqualBool;
            // just ignore the eof error here, will be dealt with on the next peek call.
            StringStream_Advance(s);
            (*valid_chars)++;
            return true;
        } else {
            *out = Token_Eq;
            return true;
        }
    case '/':
        *out = Token_Division;
        return true;
    case ';':
        *out = Token_Semicolon;
        return true;
    case '{':
        *out = Token_OpenBracket;
        return true;
    case '}':
        *out = Token_CloseBracket;
        return true;
    case '>':
        // Can be Token_GreaterThan or Token_GreaterOrEqual
        next_byte = StringStream_Peek(s);
        if (next_byte == '=') {
            *out = Token_GreaterOrEqual;
            // just ignore the eof error here, will be dealt with on the next peek call.
            StringStream_Advance(s);
            (*valid_chars)++;
            return true;
        } else {
            *out = Token_GreaterThan;
            return true;
        }
    case '<':
        // Can be Token_LessThan or Token_LessOrEqual
        next_byte = StringStream_Peek(s);
        if (next_byte == '=') {
            *out = Token_LessOrEqual;
            // just ignore the eof error here, will be dealt with on the next peek call.
            StringStream_Advance(s);
            (*valid_chars)++;
            return true;
        } else {
            *out = Token_LessThan;
            return true;
        }
    case '!':
        // Can only be Token_NotEqual
        next_byte = StringStream_Peek(s);
        if (next_byte == '=') {
            *out = Token_NotEqual;
            // just ignore the eof error here, will be dealt with on the next peek call.
            StringStream_Advance(s);
            (*valid_chars)++;
            return true;
        } else {
            goto error;
        }
    default:
        goto error;
    }

error:
    *valid_chars = valid_chars_original;
    return false;
}

// Error_UnknownToken
Error Token_Parse(StringStream *character_stream, Token *out) {
    byte b;
    bool eof;

    // valid chars is incremented if the current character in b should be added to the token string.
    UInt valid_chars = 0;
    StringStream copy = *character_stream;

    // begin lexing
start:
    eof = StringStream_IsEof(&copy);
    b = StringStream_Peek(&copy);

    // don't worry about the eof return, we will just handle that above.
    StringStream_Advance(&copy);

    // parse eof token
    if (eof) {
        out->token_type = Token_Eof;
        return Error_Good;
    }

    // parse identifier token
    if (IsIdent(b)) {
        valid_chars++;

        Token_ParseWhile(&copy, IsIdentMiddle, &valid_chars);
        out->token_type = Token_Identifier;
    } else if (IsInteger(b)) {
        valid_chars++;

        Token_ParseWhile(&copy, IsInteger, &valid_chars);
        out->token_type = Token_Integer;
    } else if (IsWhitespace(b)) {
        // just ignore whitespace
        goto start;
    } else {
        // deal with single character tokens.
        if (!Token_ParseOperators(&copy, &valid_chars, b, &out->token_type)) {
            return Error_UnknownToken;
        }
    }

    // done lexing, convert to token.
    out->token_data = StringStream_GetStringWithLength(&copy, valid_chars);

    // parse keywords
    if (out->token_type == Token_Identifier) {
        if (String_IsStaticEqual(&out->token_data, "if"))
            out->token_type = Token_If;
        else if (String_IsStaticEqual(&out->token_data, "else"))
            out->token_type = Token_Else;
        else if (String_IsStaticEqual(&out->token_data, "and"))
            out->token_type = Token_And;
        else if (String_IsStaticEqual(&out->token_data, "or"))
            out->token_type = Token_Or;
    }

    // update the stream.
    *character_stream = copy;
    return Error_Good;
}