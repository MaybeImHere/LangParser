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

static const char *token_map[] = {"Token_Integer",   "Token_Identifier",

                                  "Token_Plus",      "Token_Minus",      "Token_Asterisk",
                                  "Token_OpenParen", "Token_CloseParen", "Token_Eq",
                                  "Token_Division",  "Token_Semicolon",  "Token_Eof",

                                  "Token_If",        "Token_Else"};

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

typedef enum NodeType {
    Node_Integer,
    Node_Identifier,
    Node_Value,
    Node_VariableExprAtom,
    Node_VariableExpr,
    Node_VariableDecl,
    Node_Add,
    Node_BooleanExpr,
    Node_IfBlock,
    Node_Program
} NodeType;

typedef struct Node {
    NodeType node_type;

    union {
        IntegerNode integer;
        IdentifierNode ident;
        ValueNode value;
        VariableExprAtom variable_expr_atom;
        VariableExpr variable_expr;
        VariableDecl variable_decl_node;
        Program program_node;
    };
} Node;

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
            printf("Internal print error.");
        }
        break;

    case Node_VariableDecl:
        Node_Print(node->variable_decl_node.variable_name);
        printf(" = ");
        Node_Print(node->variable_decl_node.variable_expr);
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
} ParseState;

// Error_Alloc
Error ParseState_Init(ParseState *p, const String *src) {
    StringStream_Init(&p->stream, src);
    Error err = SaveStack_Init(&p->stack, sizeof(Node));
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    p->stack_save_state = SaveStack_SaveState(&p->stack);

    return Error_Good;
}

// creates a new save
ParseState ParseState_Save(const ParseState *p) {
    ParseState ret = *p;
    // make sure to update the stack save state.
    ret.stack_save_state = SaveStack_SaveState(&ret.stack);

    return ret;
}

// applies a save
void ParseState_Apply(ParseState *old, const ParseState *new) {
    *old = *new;
    // update the stack save state so it matches with the new stack.
    old->stack_save_state = SaveStack_SaveState(&old->stack);
}

// undoes anything that was done inside of a bad state.
void ParseState_Undo(ParseState *bad_state) {
    SaveStack_RestoreState(&bad_state->stack, &bad_state->stack_save_state);
}

// Error_UnknownToken
// Error_UnexpectedToken
Error Node_ParseToken(ParseState *state, TokenType expected_token, String *out) {
    Error err;
    ParseState save = ParseState_Save(state);
    Token t;

    err = Token_Parse(&save.stream, &t);
    BUBBLE(Error_UnknownToken);
    NOFAIL(err);

    if (t.token_type != expected_token)
        return Error_UnexpectedToken;

    if (out != NULL)
        *out = t.token_data;
    ParseState_Apply(state, &save);
    return Error_Good;
}

// Error_UnknownToken
// Error_UnexpectedToken
// Error_Alloc
Error Node_ParseTokenNode(ParseState *state, TokenType expected_token, NodeType node_type,
                          size_t string_offset, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);
    String token_str;

    err = Node_ParseToken(&save, expected_token, &token_str);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_UnexpectedToken);
    NOFAIL(err);

    err = SaveStack_Push(&save.stack, (void **)node_ptr_out);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    (*node_ptr_out)->node_type = node_type;
    // we need to cast to byte, since string_offset should be bytes from the start of the node
    // struct.
    *((String *)((byte *)*node_ptr_out + string_offset)) = token_str;

    ParseState_Apply(state, &save);
    return Error_Good;
}

// Error_UnknownToken
// Error_UnexpectedToken
// Error_Alloc
Error Node_ParseInteger(ParseState *state, Node **node_ptr_out) {
    Error err;
    err = Node_ParseTokenNode(state, Token_Integer, Node_Integer, offsetof(Node, integer.src),
                              node_ptr_out);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_UnexpectedToken);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

// Error_UnknownToken
// Error_UnexpectedToken
// Error_Alloc
Error Node_ParseIdentifier(ParseState *state, Node **node_ptr_out) {
    Error err;
    err = Node_ParseTokenNode(state, Token_Identifier, Node_Identifier, offsetof(Node, ident.src),
                              node_ptr_out);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_UnexpectedToken);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseValue(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);

    Node *integer_or_identifier = NULL;

    err = Node_ParseInteger(&save, &integer_or_identifier);
    // non recoverable errors.
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_Alloc);
    if (err == Error_Good)
        goto good;
    NOFAIL_SKIP_PARSE_FAILURE(err);

    // now try parsing an identifier.
    err = Node_ParseIdentifier(&save, &integer_or_identifier);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    BUBBLE(Error_Alloc);
    NOFAIL(err);

good:
    ASSERT(integer_or_identifier != NULL);

    Node *value = NULL;
    err = SaveStack_Push(&state->stack, (void **)&value);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    value->node_type = Node_Value;
    value->value.identifier_or_integer = integer_or_identifier;

    *node_ptr_out = value;

    ParseState_Apply(state, &save);
    return Error_Good;
}

Error Node_ParseVariableExprAtom(ParseState *state, Node **node_ptr_out);

// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseVariableExpr(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);

    enum VariableExprType expr_type;
    Node *expr_atom_lhs = NULL;
    Node *expr_atom_rhs = NULL;

    // parse the first atom.
    err = Node_ParseVariableExprAtom(&save, &expr_atom_lhs);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now try parsing the operator, + - *
    // maybe parse a +
    err = Node_ParseToken(&save, Token_Plus, NULL);
    if (err == Error_Good) {
        expr_type = Expr_Add;
        goto parse_rhs;
    }
    BUBBLE(Error_UnknownToken);
    NOFAIL_SKIP_PARSE_FAILURE(err);

    // maybe parse a -
    err = Node_ParseToken(&save, Token_Minus, NULL);
    if (err == Error_Good) {
        expr_type = Expr_Sub;
        goto parse_rhs;
    }
    BUBBLE(Error_UnknownToken);
    NOFAIL_SKIP_PARSE_FAILURE(err);

    // if this one fails, there are no other possible binary operators, so just quit parsing in this
    // function. maybe parse a *
    err = Node_ParseToken(&save, Token_Asterisk, NULL);
    if (err == Error_Good) {
        expr_type = Expr_Mul;
        goto parse_rhs;
    }
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken) {
        // no operator was present, so it was just a lone value like in "a = 2"
        expr_type = Expr_SingleAtom;
        goto create_expr_node;
    }
    NOFAIL(err);

parse_rhs:
    // done parsing the operator, now parse the second expression atom
    err = Node_ParseVariableExprAtom(&save, &expr_atom_rhs);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);
    goto create_expr_node;

create_expr_node:
    // done parsing, so create the node.
    ASSERT(expr_atom_lhs != NULL &&
           (expr_atom_rhs != NULL || (expr_atom_rhs == NULL && expr_type == Expr_SingleAtom)));
    Node *variable_expr = NULL;
    err = SaveStack_Push(&state->stack, (void **)&variable_expr);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    variable_expr->node_type = Node_VariableExpr;
    variable_expr->variable_expr.type = expr_type;
    variable_expr->variable_expr.lhs = expr_atom_lhs;
    variable_expr->variable_expr.rhs = expr_atom_rhs;

    *node_ptr_out = variable_expr;

    // now one of the two above succeeded, so continue.
    ParseState_Apply(state, &save);
    return Error_Good;
}

// expr-atom := '(' expr ')' | value
// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseVariableExprAtom(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);

    bool neg = false;
    Node *value_or_paren_expr = NULL;

    // try parsing a negative
    err = Node_ParseToken(&save, Token_Minus, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken) {
        neg = false;
    } else {
        NOFAIL(err);
        neg = true;
    }

    // now try a value, or a parenthesized expression.
    err = Node_ParseValue(&save, &value_or_paren_expr);
    if (err == Error_Good)
        goto good;
    BUBBLE(Error_Alloc);
    NOFAIL_SKIP_PARSE_FAILURE(err);

    // above failed, so now try parsing a parenthesis expression.
    err = Node_ParseToken(&save, Token_OpenParen, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);

    // now parse the expression within.
    err = Node_ParseVariableExpr(&save, &value_or_paren_expr);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now parse the final parenthesis.
    err = Node_ParseToken(&save, Token_CloseParen, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);

    // done parsing, now make the node
good:
    ASSERT(value_or_paren_expr != NULL);
    Node *variable_expr_atom = NULL;
    err = SaveStack_Push(&state->stack, (void **)&variable_expr_atom);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    variable_expr_atom->node_type = Node_VariableExprAtom;
    variable_expr_atom->variable_expr_atom.neg = neg;
    variable_expr_atom->variable_expr_atom.value_or_variable_expr = value_or_paren_expr;

    *node_ptr_out = variable_expr_atom;

    // now one of the two above succeeded, so continue.
    ParseState_Apply(state, &save);
    return Error_Good;
}

// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseVariableDecl(ParseState *state, Node **node_ptr_out) {
    Error err;
    ParseState save = ParseState_Save(state);
    Node *variable_name = NULL;
    Node *variable_expr = NULL;

    // parse the left hand side of the equals sign.
    err = Node_ParseIdentifier(&save, &variable_name);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // parse the equals sign
    err = Node_ParseToken(&save, Token_Eq, NULL);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    NOFAIL(err);

    // parse the right side of the equal sign.
    err = Node_ParseVariableExpr(&save, &variable_expr);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_ParseFailed);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now that we are done, check to make sure that the nodes were actually created.
    ASSERT(variable_name != NULL && variable_expr != NULL);

    // now create the node on the stack
    Node *new_variable_decl_node = NULL;
    err = SaveStack_Push(&save.stack, (void **)&new_variable_decl_node);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // initialize the node
    new_variable_decl_node->node_type = Node_VariableDecl;
    new_variable_decl_node->variable_decl_node.variable_name = variable_name;
    new_variable_decl_node->variable_decl_node.variable_expr = variable_expr;

    *node_ptr_out = new_variable_decl_node;
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

    err = Node_ParseVariableDecl(&parser, &node);
    IF_ERR(Error_UnknownToken, "unknown token.");
    IF_ERR(Error_ParseFailed, "parse failed.");
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node_Print(node);
    printf("\n");

    err = Node_ParseVariableDecl(&parser, &node);
    IF_ERR(Error_UnknownToken, "unknown token.");
    IF_ERR(Error_ParseFailed, "parse failed.");
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node_Print(node);

    printf("\nC program:\n");

    return 0;
}
