#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "nodes.h"
#include "stack.h"
#include "strings.h"

bool IsWhitespace(byte b) { return b <= 32 || b >= 127; }

bool IsIdent(byte b) { return ('a' <= b && 'z' >= b) || ('A' <= b && 'Z' >= b) || (b == '_'); }

bool IsInteger(byte b) { return ('0' <= b && '9' >= b); }

// Error_Alloc
// Error_UnableToOpenFile
// Error_WhileReadingFile

typedef struct StringToPtrMapBlock {
    String key;
    void *value;
    UInt hash;

    struct StringToPtrMapBlock *hash_is_smaller;
    struct StringToPtrMapBlock *hash_is_equal;
    struct StringToPtrMapBlock *hash_is_greater;
} StringToPtrMapBlock;

void StringToPtrMapBlock_Init(StringToPtrMapBlock *map, String *key, void *value) {
    map->key = *key;
    map->value = value;
    map->hash = String_Hash(&map->key);

    map->hash_is_smaller = NULL;
    map->hash_is_equal = NULL;
    map->hash_is_greater = NULL;
}

// Error_KeyExists
// Error_MustCreateNewNode
Error StringToPtrMapBlock_ExistsHelper(StringToPtrMapBlock *map, String *key, UInt key_hash,
                                       void **value_out, StringToPtrMapBlock ***to_initialize) {
    if (map->hash == key_hash) {
        if (String_IsEqual(&map->key, key)) {
            if (value_out != NULL)
                *value_out = map->value;
            return Error_KeyExists;
        } else {
            if (map->hash_is_equal != NULL) {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_equal, key, key_hash,
                                                        value_out, to_initialize);
            } else {
                // we would have to create a new one.
                *to_initialize = &map->hash_is_equal;
                return Error_MustCreateNewNode;
            }
        }
    } else {
        if (key_hash > map->hash) {
            if (map->hash_is_greater != NULL) {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_greater, key, key_hash,
                                                        value_out, to_initialize);
            } else {
                *to_initialize = &map->hash_is_greater;
                return Error_MustCreateNewNode;
            }
        } else {
            if (map->hash_is_smaller != NULL) {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_smaller, key, key_hash,
                                                        value_out, to_initialize);
            } else {
                *to_initialize = &map->hash_is_smaller;
                return Error_MustCreateNewNode;
            }
        }
    }
}

// Error_KeyExists
// Error_Alloc
Error StringToPtrMapBlock_CreateIfNotExist(StringToPtrMapBlock *map, String *key, void *value_ptr) {
    StringToPtrMapBlock **new_node_to_allocate = NULL;
    Error err =
        StringToPtrMapBlock_ExistsHelper(map, key, String_Hash(key), NULL, &new_node_to_allocate);
    if (err == Error_KeyExists)
        return Error_KeyExists;
    if (err == Error_MustCreateNewNode) {
        *new_node_to_allocate = malloc(sizeof(StringToPtrMapBlock));
        if (*new_node_to_allocate == NULL)
            return Error_Alloc;
        StringToPtrMapBlock_Init(*new_node_to_allocate, key, value_ptr);
        return Error_Good;
    }
    NOFAIL(err);
    return Error_Good;
}

typedef struct StringToPtrMap {
    StringToPtrMapBlock first_block;
    bool has_first_block;
} StringToPtrMap;

void StringToPtrMap_Init(StringToPtrMap *map) { map->has_first_block = false; }

// Error_KeyExists
// Error_Alloc
Error StringToPtrMap_CreateIfNotExist(StringToPtrMap *map, String *key, void *value_ptr) {
    if (!map->has_first_block) {
        StringToPtrMapBlock_Init(&map->first_block, key, value_ptr);
        return Error_Good;
    } else {
        Error err = StringToPtrMapBlock_CreateIfNotExist(&map->first_block, key, value_ptr);
        if (err == Error_KeyExists)
            return Error_KeyExists;
        if (err == Error_Alloc)
            return Error_Alloc;
        NOFAIL(err);
        return Error_Good;
    }
}

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

Token Token_Create(TokenType token_type, const byte *data, UInt length) {
    Token ret = {.token_type = token_type, .token_data = String_Create(data, length)};
    return ret;
}

static const char *token_map[] = {"Token_Integer",    "Token_Identifier",  "Token_Plus",
                                  "Token_Minus",      "Token_Asterisk",    "Token_OpenParen",
                                  "Token_CloseParen", "Token_OpenBracket", "Token_CloseBracket",
                                  "Token_Eq",         "Token_Division",    "Token_Semicolon",
                                  "Token_Eof",        "Token_If",          "Token_Else"};

void Token_Print(const Token *token) {
    printf("%s '", token_map[token->token_type]);
    String_Print(&token->token_data);
    putchar('\'');
}

void Token_ParseWhile(StringStream *character_stream, bool (*parse_func)(byte), UInt *valid_chars) {
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

bool IsIdentMiddle(byte b) { return IsIdent(b) || IsInteger(b); }

bool Token_GetSingleByteToken(byte b, TokenType *out) {
    switch (b) {
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
    case '=':
        *out = Token_Eq;
        return true;
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
    default:
        return false;
    }
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
        if (Token_GetSingleByteToken(b, &out->token_type)) {
            valid_chars++;
        } else {
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
    }

    // update the stream.
    *character_stream = copy;
    return Error_Good;
}

void Node_Print(Node *node) {
    if (node == NULL)
        return;
    switch (node->node_type) {
    case Node_Integer:
        String_Print(&node->integer.src);
        break;
    case Node_Identifier:
        String_Print(&node->ident.src);
        break;
    case Node_Value:
        Node_Print(node->value.identifier_or_integer);
        break;
    case Node_VariableExprAtom:
        if (node->variable_expr_atom.neg) {
            // print the minus sign if it's negative.
            printf("-");
        }
        if (node->variable_expr_atom.value_or_variable_expr->node_type == Node_Value) {
            // if its just a bare value, print it normally
            Node_Print(node->variable_expr_atom.value_or_variable_expr);
        } else {
            printf("(");
            // it's an expression, so print parenthesis.
            Node_Print(node->variable_expr_atom.value_or_variable_expr);
            printf(")");
        }
        break;
    case Node_VariableExpr:
        if (node->variable_expr.type == Expr_Add) {
            Node_Print(node->variable_expr.lhs);
            printf(" + ");
            Node_Print(node->variable_expr.rhs);
        } else if (node->variable_expr.type == Expr_Sub) {
            Node_Print(node->variable_expr.lhs);
            printf(" - ");
            Node_Print(node->variable_expr.rhs);
        } else if (node->variable_expr.type == Expr_Mul) {
            Node_Print(node->variable_expr.lhs);
            printf(" * ");
            Node_Print(node->variable_expr.rhs);
        } else if (node->variable_expr.type == Expr_SingleAtom) {
            Node_Print(node->variable_expr.lhs);
        } else {
            printf("main(%d): Unknown variable expression type.", __LINE__);
        }
        break;

    case Node_VariableDecl:
        Node_Print(node->variable_decl_node.variable_name);
        printf(" = ");
        Node_Print(node->variable_decl_node.variable_expr);
        break;

    case Node_BooleanExpr:
        if (node->boolean_expr.type == BoolExpr_Eq) {
            Node_Print(node->boolean_expr.rhs);
            printf(" = ");
            Node_Print(node->boolean_expr.lhs);
        } else {
            printf("main(%d): Unknown boolean expression type.", __LINE__);
        }
        break;
    case Node_Program:
        Node_Print(node->program_node.variable_decl);
        break;

    default:
        printf("Undefined node type.");
        break;
    }
}

typedef struct ParseState {
    StringStream stream;

    // will hold the nodes.
    SaveStack stack;

    // will be used to restore the stack to a previous state should a function fail.
    SaveStackSaveState stack_save_state;

    Error last_error;
} ParseState;

// Error_Alloc
Error ParseState_Init(ParseState *p, const String *src) {
    StringStream_Init(&p->stream, src);
    Error err = SaveStack_Init(&p->stack, sizeof(Node));
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    p->stack_save_state = SaveStack_SaveState(&p->stack);

    p->last_error = Error_Good;

    return Error_Good;
}

// creates a new save
ParseState ParseState_Save(const ParseState *p) {
    ParseState ret = *p;
    // make sure to update the stack save state.
    ret.stack_save_state = SaveStack_SaveState(&ret.stack);

    return ret;
}

// undoes anything that was done inside of a bad state.
void ParseState_Undo(ParseState *bad_state) {
    SaveStack_RestoreState(&bad_state->stack, &bad_state->stack_save_state);
}

// applies a save
void ParseState_Apply(ParseState *old, ParseState *new) {
    if (new->last_error != Error_Good) {
        // undo any modifications if the parsing failed.
        ParseState_Undo(new);
        // bubble up the error
        old->last_error = new->last_error;
        // don't copy the stringstream.

        // save the current state of the stack, however.
        old->stack_save_state = SaveStack_SaveState(&old->stack);
    } else {
        *old = *new;
        // update the stack save state so it matches with the new stack.
        old->stack_save_state = SaveStack_SaveState(&old->stack);
    }
}

Node *ParseState_CreateNode(ParseState *state) {
    Node *ret = NULL;
    state->last_error = SaveStack_Push(&state->stack, (void **)&ret);
    return ret;
}

#define PARSE_FUNC_INIT                                                                            \
    ParseState save = ParseState_Save(state);                                                      \
    state->last_error = Error_ParseFailed;

#define PARSE_FUNC_DONE_GOOD                                                                       \
    {                                                                                              \
        state->last_error = Error_Good;                                                            \
        ParseState_Apply(state, &save);                                                            \
        return true;                                                                               \
    }

#define PARSE_FUNC_DONE_ERR                                                                        \
    {                                                                                              \
        state->last_error = save.last_error;                                                       \
        ParseState_Apply(state, &save);                                                            \
        return false;                                                                              \
    }

bool ParseState_CanRecover(ParseState *state) {
    return state->last_error == Error_Good || state->last_error == Error_UnexpectedToken ||
           state->last_error == Error_ParseFailed;
}

// All parsing functions return true if successful.
bool Node_ParseToken(ParseState *state, TokenType expected_token, String *out) {
    PARSE_FUNC_INIT;

    Token t;

    Error err = Token_Parse(&save.stream, &t);
    if (err == Error_Good) {
        if (t.token_type == expected_token) {
            // successfully parsed.
            if (out != NULL)
                *out = t.token_data;

            PARSE_FUNC_DONE_GOOD;
        }
        save.last_error = Error_UnexpectedToken;
    } else {
        if (err == Error_UnknownToken) {
            save.last_error = Error_UnknownToken;
        } else {
            save.last_error = Error_Internal;
        }
    }

    PARSE_FUNC_DONE_ERR;
}

bool Node_ParseInteger(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    String integer;
    if (Node_ParseToken(&save, Token_Integer, &integer)) {
        Node *new_node = ParseState_CreateNode(&save);
        if (!new_node)
            PARSE_FUNC_DONE_ERR;

        new_node->node_type = Node_Integer;
        new_node->integer.src = integer;
        *node_ptr_out = new_node;
        PARSE_FUNC_DONE_GOOD;
    }

    PARSE_FUNC_DONE_ERR;
}

bool Node_ParseIdentifier(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    String identifier;
    if (Node_ParseToken(&save, Token_Identifier, &identifier)) {
        Node *new_node = ParseState_CreateNode(&save);
        if (!new_node)
            PARSE_FUNC_DONE_ERR;

        new_node->node_type = Node_Identifier;
        new_node->ident.src = identifier;
        *node_ptr_out = new_node;
        PARSE_FUNC_DONE_GOOD;
    }

    PARSE_FUNC_DONE_ERR;
}

bool Node_ParseValue(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    Node *identifier_or_integer = NULL;
    if (Node_ParseIdentifier(&save, &identifier_or_integer)) {
        goto create_node;
    }

    if (!ParseState_CanRecover(&save))
        PARSE_FUNC_DONE_ERR;

    if (Node_ParseInteger(&save, &identifier_or_integer)) {
        goto create_node;
    }

    PARSE_FUNC_DONE_ERR;

create_node:;
    Node *new_node = ParseState_CreateNode(&save);
    if (!new_node)
        PARSE_FUNC_DONE_ERR;

    new_node->node_type = Node_Value;
    new_node->value.identifier_or_integer = identifier_or_integer;
    *node_ptr_out = new_node;
    PARSE_FUNC_DONE_GOOD;
}

bool Node_ParseVariableExprAtom(ParseState *state, Node **node_ptr_out);

bool Node_ParseVariableExpr(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    VariableExprType expr_type;
    Node *expr_atom_lhs = NULL;
    Node *expr_atom_rhs = NULL;

    if (!Node_ParseVariableExprAtom(&save, &expr_atom_lhs))
        PARSE_FUNC_DONE_ERR;

    // +
    if (Node_ParseToken(&save, Token_Plus, NULL)) {
        expr_type = Expr_Add;
        goto parsed_operator;
    }

    if (!ParseState_CanRecover(&save))
        PARSE_FUNC_DONE_ERR;

    // -
    if (Node_ParseToken(&save, Token_Minus, NULL)) {
        expr_type = Expr_Sub;
        goto parsed_operator;
    }

    if (!ParseState_CanRecover(&save))
        PARSE_FUNC_DONE_ERR;

    // *
    if (Node_ParseToken(&save, Token_Asterisk, NULL)) {
        expr_type = Expr_Mul;
        goto parsed_operator;
    }

    if (!ParseState_CanRecover(&save))
        PARSE_FUNC_DONE_ERR;

    // just a lonely value in the declaration "a = 2;"
    // since rhs is already null, just reuse this operator code.
    expr_type = Expr_SingleAtom;
    goto create_node;

parsed_operator:
    if (!Node_ParseVariableExprAtom(&save, &expr_atom_rhs))
        PARSE_FUNC_DONE_ERR;

create_node:;
    Node *variable_expr = NULL;
    if (!(variable_expr = ParseState_CreateNode(&save)))
        PARSE_FUNC_DONE_ERR;

    variable_expr->node_type = Node_VariableExpr;
    variable_expr->variable_expr.type = expr_type;
    variable_expr->variable_expr.lhs = expr_atom_lhs;
    variable_expr->variable_expr.rhs = expr_atom_rhs;

    *node_ptr_out = variable_expr;
    PARSE_FUNC_DONE_GOOD;
}

// expr-atom := '(' expr ')' | value
bool Node_ParseVariableExprAtom(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    // whether it is something like "-a" or "a". true means "-a"
    bool neg = false;
    Node *value_or_paren_expr = NULL;

    if (Node_ParseToken(&save, Token_Minus, NULL)) {
        neg = true;
    }

    if (!ParseState_CanRecover(&save))
        PARSE_FUNC_DONE_ERR;

    // done parsing the negative symbol, now try parsing a value or a parenthesized expression.
    if (Node_ParseToken(&save, Token_OpenParen, NULL)) {
        // parsing a parethesis expression
        if (!Node_ParseVariableExpr(&save, &value_or_paren_expr))
            PARSE_FUNC_DONE_ERR;

        if (!Node_ParseToken(&save, Token_CloseParen, NULL))
            PARSE_FUNC_DONE_ERR;
        // parsed everything successfully, so this will just go down to the node creation part.
    } else {
        if (!ParseState_CanRecover(&save))
            PARSE_FUNC_DONE_ERR;

        // try parsing a value instead.
        if (!Node_ParseValue(&save, &value_or_paren_expr))
            PARSE_FUNC_DONE_ERR;
    }

    // done parsing, now make the node
    Node *variable_expr_atom = ParseState_CreateNode(&save);
    if (!variable_expr_atom)
        PARSE_FUNC_DONE_ERR;

    variable_expr_atom->node_type = Node_VariableExprAtom;
    variable_expr_atom->variable_expr_atom.neg = neg;
    variable_expr_atom->variable_expr_atom.value_or_variable_expr = value_or_paren_expr;

    *node_ptr_out = variable_expr_atom;

    PARSE_FUNC_DONE_GOOD;
}

bool Node_ParseVariableDecl(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;
    Node *variable_name = NULL;
    Node *variable_expr = NULL;

    // parse the left hand side of the equals sign.
    if (!Node_ParseIdentifier(&save, &variable_name))
        PARSE_FUNC_DONE_ERR;

    // parse the equals sign
    if (!Node_ParseToken(&save, Token_Eq, NULL))
        PARSE_FUNC_DONE_ERR;

    // parse the right side of the equal sign.
    if (!Node_ParseVariableExpr(&save, &variable_expr))
        PARSE_FUNC_DONE_ERR;

    // now create the node on the stack
    Node *new_variable_decl_node = ParseState_CreateNode(&save);
    if (!new_variable_decl_node)
        PARSE_FUNC_DONE_ERR;

    // initialize the node
    new_variable_decl_node->node_type = Node_VariableDecl;
    new_variable_decl_node->variable_decl_node.variable_name = variable_name;
    new_variable_decl_node->variable_decl_node.variable_expr = variable_expr;

    *node_ptr_out = new_variable_decl_node;
    PARSE_FUNC_DONE_GOOD;
}

// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseBooleanExpr(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);

    enum BooleanExprType type;
    Node *lhs = NULL;
    Node *rhs = NULL;

    // parse the left side of the expression.
    err = Node_ParseVariableExprAtom(&save, &lhs);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // parse the equals
    err = Node_ParseToken(&save, Token_Eq, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);
    type = BoolExpr_Eq;

    // parse the right side of the expression.
    err = Node_ParseVariableExprAtom(&save, &rhs);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now that we are done, check to make sure that the nodes were actually created.
    ASSERT(lhs != NULL && rhs != NULL);

    // now create the node on the stack
    Node *new_bool_expr_node = NULL;
    err = SaveStack_Push(&save.stack, (void **)&new_bool_expr_node);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // initialize the node
    new_bool_expr_node->node_type = Node_BooleanExpr;
    new_bool_expr_node->boolean_expr.type = type;
    new_bool_expr_node->boolean_expr.lhs = lhs;
    new_bool_expr_node->boolean_expr.rhs = rhs;

    *node_ptr_out = new_bool_expr_node;
    ParseState_Apply(state, &save);

    return Error_Good;
}

Error Node_ParseStatementList(ParseState *state, Node **node_ptr_out);

// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseIfBlock(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);

    Node *boolean_expr = NULL;
    Node *first_statement = NULL;

    // parse the if token
    err = Node_ParseToken(&save, Token_If, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);

    // parse the condition
    err = Node_ParseBooleanExpr(&save, &boolean_expr);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // parse the opening bracket
    err = Node_ParseToken(&save, Token_OpenBracket, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);

    // parse the inside of the statement block.
    err = Node_ParseStatementList(&save, &first_statement);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // parse the trailing close bracket.
    err = Node_ParseToken(&save, Token_CloseBracket, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);

    // now that we are done, check to make sure that the nodes were actually created.
    ASSERT(boolean_expr != NULL && first_statement != NULL);

    // now create the node on the stack
    Node *new_if_block = NULL;
    err = SaveStack_Push(&save.stack, (void **)&new_if_block);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // initialize the node
    new_if_block->node_type = Node_IfBlock;
    new_if_block->if_block.boolean_expr = boolean_expr;
    new_if_block->if_block.first_statement = first_statement;

    *node_ptr_out = new_if_block;
    ParseState_Apply(state, &save);

    return Error_Good;
}

Error Node_ParseStatementList(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);

    Node *first_statement = NULL;
    Node *next_statement = NULL;

    do {
        err = Node_ParseVariableDecl(&save, &first_statement);
        BUBBLE(Error_UnknownToken);
        BUBBLE(Error_Alloc);
        if (err == Error_ParseFailed) {
            // try parsing if block instead.
            err = Node_ParseIfBlock(&save, &first_statement);
            if (err == Error_ParseFailed) {
                if (first_statement == NULL) {
                    // haven't even parsed a single statement.
                    return Error_ParseFailed;
                } else {
                    // have parsed at least one statement.
                    break;
                }
            }
            BUBBLE(Error_UnknownToken);
            BUBBLE(Error_Alloc);
            NOFAIL(err);

        } else {
            NOFAIL(err);
        }
    } while (true);

    // now that we are done, check to make sure that the nodes were actually created.
    ASSERT(first_statement != NULL);

    // now create the node on the stack
    Node *new_if_block = NULL;
    err = SaveStack_Push(&save.stack, (void **)&new_if_block);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // initialize the node
    new_if_block->node_type = Node_IfBlock;
    new_if_block->if_block.boolean_expr = NULL; // TODO: replace this with the actual pointer.
    new_if_block->if_block.first_statement = first_statement;

    *node_ptr_out = new_if_block;
    ParseState_Apply(state, &save);

    return Error_Good;
}

typedef enum StateInstructionType { SInstr_Assign, SInstr_AddThenAssign } StateInstructionType;

typedef struct StateInstruction {
    StateInstructionType type;

    union {
        struct Assign {
            String dest_variable;
            String src;
        } assign;

        struct AddThenAssign {
            String dest_variable;
            String src1;
            String src2;
        } add_then_assign;
    };
} StateInstruction;

typedef enum StateBooleanExprType { SBoolExpr_Eq } StateBooleanExprType;

typedef struct StateBooleanExpr {
    StateBooleanExprType type;

    union {
        struct Eq {
            String op1;
            String op2;
        } eq;
    };
} StateBooleanExpr;

typedef struct State State;

typedef struct StateSwitcher {
    StateBooleanExpr expr;
    State *true_state;
    State *false_state;
} StateSwitcher;

typedef struct State {
    // stack of StateInstruction
    Stack state_instructions;
} State;

typedef struct StateMachine {
    StringToPtrMap variables;
    // stack of State
    Stack states;
} StateMachine;

Error StateMachine_Init(StateMachine *m) {
    Error err;
    StringToPtrMap_Init(&m->variables);
    err = Stack_Init(&m->states, sizeof(State), 16);
    if (err == Error_Alloc)
        return Error_Alloc;
    NOFAIL(err);

    return Error_Good;
}

#pragma clang diagnostic ignored "-Wunused-variable"

void error(const char *src, const char *msg, UInt line) {
    printf("%s(%u): %s\n", src, line, msg);
    exit(1);
}

#define IF_ERR(_err, msg)                                                                          \
    if (_err == err) {                                                                             \
        error("main", msg, __LINE__);                                                              \
    }

#undef NOFAIL
#define NOFAIL                                                                                     \
    if (err != Error_Good) {                                                                       \
        error("main", "internal error.", __LINE__);                                                \
    }

int main(void) {
    String test_program;
    byte *program_data;
    Error err = String_FromFile(&test_program, &program_data, "data/test.txt");

    IF_ERR(Error_Alloc, "allocation failure.");
    IF_ERR(Error_UnableToOpenFile, "unable to open file.");
    IF_ERR(Error_WhileReadingFile, "while reading file.");
    NOFAIL;

    ParseState parser;
    err = ParseState_Init(&parser, &test_program);
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node *node = NULL;

    if (!Node_ParseVariableDecl(&parser, &node)) {
        err = parser.last_error;
        IF_ERR(Error_UnknownToken, "unknown token.");
        IF_ERR(Error_ParseFailed, "parse failed.");
        IF_ERR(Error_Alloc, "allocation failure.");
        NOFAIL;
    }

    Node_Print(node);
    printf("\n");

    if (!Node_ParseVariableDecl(&parser, &node)) {
        err = parser.last_error;
        IF_ERR(Error_UnknownToken, "unknown token.");
        IF_ERR(Error_ParseFailed, "parse failed.");
        IF_ERR(Error_Alloc, "allocation failure.");
        NOFAIL;
    }

    Node_Print(node);

    printf("\nC program:\n");

    return 0;
}
