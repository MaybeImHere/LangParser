#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "err.h"
#include "stack.h"

bool IsWhitespace(byte b)
{
    return b <= 32 || b >= 127;
}

bool IsIdent(byte b)
{
    return ('a' <= b && 'z' >= b) || ('A' <= b && 'Z' >= b) || (b == '_');
}

bool IsInteger(byte b)
{
    return ('0' <= b && '9' >= b);
}

typedef struct String
{
    const byte *data;
    UInt length;
} String;

// Error_Alloc
// Error_UnableToOpenFile
// Error_WhileReadingFile
Error String_FromFile(String *out, byte **data, const char *filename)
{
    // first try and open the file
    FILE *file_handle = fopen(filename, "r");
    if (file_handle == NULL)
        return Error_UnableToOpenFile;

    // set up the allocated buffer with a starting size of 512 bytes.
    UInt current_capacity = 512;
    UInt current_length = 0;
    byte *buf = malloc(current_capacity);
    if (buf == NULL)
    {
        // didn't allocate, so close the file and return
        fclose(file_handle);
        return Error_Alloc;
    }

    // this will read the entire file into buf
    // since fread does not start from the beginning each time, we only read in the difference between the capacity and the currently read portion
    // in buf.
    UInt current_read_size = current_capacity;
    while (true)
    {
        // read the next few bytes
        size_t ret_val = fread(buf + (uintptr_t)current_length, sizeof(byte), current_read_size, file_handle);
        current_length += (UInt)ret_val;

        // we didn't read the specified number of bytes. either there weren't anymore bytes, or there was some error.
        if (ret_val != current_read_size)
        {
            // check for end of file.
            if (feof(file_handle))
            {
                *data = buf;
                out->data = buf;
                out->length = current_length;
                return Error_Good;
            }
            else if (ferror(file_handle))
            {
                // there was an error, so just free the buffer and return.
                fclose(file_handle);
                free(buf);
                return Error_WhileReadingFile;
            }
        }
        else
        {
            // we read the entire specified read size, so there are probably more bytes to read.
            // we increase the reading size by 1.5x, and add that onto the buffer capacity.
            UInt new_reading_size = current_read_size + (current_read_size >> 1) + 1;
            buf = realloc(buf, current_capacity + new_reading_size);
            if (buf == NULL)
            {
                fclose(file_handle);
                return Error_Alloc;
            }
            current_capacity += new_reading_size;
        }
    }
}

String StringFromLiteral(const char *literal)
{
    String ret = {
        .data = (const byte *)literal,
        .length = strlen(literal)};

    return ret;
}

String String_Create(const byte *src, UInt length)
{
    String ret = {
        .data = src,
        .length = length};
    return ret;
}

void String_Print(const String *src)
{
    for (UInt i = 0; i < src->length; i++)
    {
        putchar(src->data[i]);
    }
}

byte String_At(String *s, UInt pos)
{
    return s->data[pos];
}

UInt String_Hash(const String *src)
{
    UInt ret = 0;
    for (UInt i = 0; i < src->length; i++)
    {
        ret *= 17;
        ret += src->data[i];
    }

    return ret;
}

bool String_IsEqual(const String *s1, const String *s2)
{
    if (s1->length != s2->length)
        return false;
    return memcmp(s1->data, s2->data, s1->length) == 0;
}

bool String_IsStaticEqual(const String *s1, const char *s2)
{
    for (UInt i = 0; i < s1->length; i++)
    {
        if (s2[i] == '\0')
            return false;
        if ((byte)s2[i] != s1->data[i])
            return false;
    }
    return true;
}

typedef struct StringStream
{
    String src;
    UInt pos;
    bool eof;
} StringStream;

void StringStream_Init(StringStream *s, const String *src)
{
    s->src = *src;
    s->pos = 0;
    // if we are already at the end, make sure to set the eof bit.
    s->eof = src->length == 0;
}

// returns the byte at the current position, or 0 if at the end of file.
byte StringStream_Peek(StringStream *s)
{
    if (s->eof)
    {
        return 0;
    }
    else
    {
        return s->src.data[s->pos];
    }
}

// Error_Eof: if the next peek call will result in Error_Eof
Error StringStream_Advance(StringStream *s)
{
    if (s->eof)
        return Error_Eof;
    s->pos++;
    if (s->pos == s->src.length)
    {
        s->eof = true;
        return Error_Eof;
    }
    return Error_Good;
}

bool StringStream_IsEof(StringStream *s)
{
    return s->eof;
}

String StringStream_GetStringWithLength(StringStream *s, UInt length)
{
    return String_Create(&s->src.data[s->pos - length], length);
}

typedef struct StringToPtrMapBlock
{
    String key;
    void *value;
    UInt hash;

    struct StringToPtrMapBlock *hash_is_smaller;
    struct StringToPtrMapBlock *hash_is_equal;
    struct StringToPtrMapBlock *hash_is_greater;
} StringToPtrMapBlock;

void StringToPtrMapBlock_Init(StringToPtrMapBlock *map, String *key, void *value)
{
    map->key = *key;
    map->value = value;
    map->hash = String_Hash(&map->key);

    map->hash_is_smaller = NULL;
    map->hash_is_equal = NULL;
    map->hash_is_greater = NULL;
}

// Error_KeyExists
// Error_MustCreateNewNode
Error StringToPtrMapBlock_ExistsHelper(StringToPtrMapBlock *map, String *key, UInt key_hash, void **value_out, StringToPtrMapBlock ***to_initialize)
{
    if (map->hash == key_hash)
    {
        if (String_IsEqual(&map->key, key))
        {
            if (value_out != NULL)
                *value_out = map->value;
            return Error_KeyExists;
        }
        else
        {
            if (map->hash_is_equal != NULL)
            {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_equal, key, key_hash, value_out, to_initialize);
            }
            else
            {
                // we would have to create a new one.
                *to_initialize = &map->hash_is_equal;
                return Error_MustCreateNewNode;
            }
        }
    }
    else
    {
        if (key_hash > map->hash)
        {
            if (map->hash_is_greater != NULL)
            {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_greater, key, key_hash, value_out, to_initialize);
            }
            else
            {
                *to_initialize = &map->hash_is_greater;
                return Error_MustCreateNewNode;
            }
        }
        else
        {
            if (map->hash_is_smaller != NULL)
            {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_smaller, key, key_hash, value_out, to_initialize);
            }
            else
            {
                *to_initialize = &map->hash_is_smaller;
                return Error_MustCreateNewNode;
            }
        }
    }
}

// Error_KeyExists
// Error_Alloc
Error StringToPtrMapBlock_CreateIfNotExist(StringToPtrMapBlock *map, String *key, void *value_ptr)
{
    StringToPtrMapBlock **new_node_to_allocate = NULL;
    Error err = StringToPtrMapBlock_ExistsHelper(map, key, String_Hash(key), NULL, &new_node_to_allocate);
    if (err == Error_KeyExists)
        return Error_KeyExists;
    if (err == Error_MustCreateNewNode)
    {
        *new_node_to_allocate = malloc(sizeof(StringToPtrMapBlock));
        if (*new_node_to_allocate == NULL)
            return Error_Alloc;
        StringToPtrMapBlock_Init(*new_node_to_allocate, key, value_ptr);
        return Error_Good;
    }
    NOFAIL(err);
    return Error_Good;
}

typedef struct StringToPtrMap
{
    StringToPtrMapBlock first_block;
    bool has_first_block;
} StringToPtrMap;

void StringToPtrMap_Init(StringToPtrMap *map)
{
    map->has_first_block = false;
}

// Error_KeyExists
// Error_Alloc
Error StringToPtrMap_CreateIfNotExist(StringToPtrMap *map, String *key, void *value_ptr)
{
    if (!map->has_first_block)
    {
        StringToPtrMapBlock_Init(&map->first_block, key, value_ptr);
        return Error_Good;
    }
    else
    {
        Error err = StringToPtrMapBlock_CreateIfNotExist(&map->first_block, key, value_ptr);
        if (err == Error_KeyExists)
            return Error_KeyExists;
        if (err == Error_Alloc)
            return Error_Alloc;
        NOFAIL(err);
        return Error_Good;
    }
}

typedef enum TokenType
{
    Token_Integer,
    Token_Plus,
    Token_Eq,
    Token_Identifier,
    Token_Division,
    Token_Eof,

    // keywords
    Token_Auto,
    Token_Break,
    Token_Case,
    Token_Char,
    Token_Const,
    Token_Continue,
    Token_Default,
    Token_Do,
    Token_Double,
    Token_Else,
    Token_Enum,
    Token_Extern,
    Token_Float,
    Token_For,
    Token_Goto,
    Token_If,
    Token_Inline,
    Token_Int,
    Token_Long,
    Token_Register,
    Token_Restrict,
    Token_Return,
    Token_Short,
    Token_Signed,
    Token_Sizeof,
    Token_Static,
    Token_Struct,
    Token_Switch,
    Token_Typedef,
    Token_Union,
    Token_Unsigned,
    Token_Void,
    Token_Volatile,
    Token_While,
} TokenType;

typedef struct Token
{
    TokenType token_type;
    String token_data;
} Token;

Token Token_Create(TokenType token_type, const byte *data, UInt length)
{
    Token ret = {
        .token_type = token_type,
        .token_data = String_Create(data, length)};
    return ret;
}

static const char *token_map[] = {
    "Token_Integer",
    "Token_Plus",
    "Token_Eq",
    "Token_Identifier",
    "Token_Division",
    "Token_Eof",
    "Token_Auto",
    "Token_Break",
    "Token_Case",
    "Token_Char",
    "Token_Const",
    "Token_Continue",
    "Token_Default",
    "Token_Do",
    "Token_Double",
    "Token_Else",
    "Token_Enum",
    "Token_Extern",
    "Token_Float",
    "Token_For",
    "Token_Goto",
    "Token_If",
    "Token_Inline",
    "Token_Int",
    "Token_Long",
    "Token_Register",
    "Token_Restrict",
    "Token_Return",
    "Token_Short",
    "Token_Signed",
    "Token_Sizeof",
    "Token_Static",
    "Token_Struct",
    "Token_Switch",
    "Token_Typedef",
    "Token_Union",
    "Token_Unsigned",
    "Token_Void",
    "Token_Volatile",
    "Token_While"};

void Token_Print(const Token *token)
{
    printf("%s '", token_map[token->token_type]);
    String_Print(&token->token_data);
    putchar('\'');
}

void Token_ParseWhile(StringStream *character_stream, bool (*parse_func)(byte), UInt *valid_chars)
{
    byte b;
    bool eof;

    // account for the character already parsed before.
    while (true)
    {
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

bool IsIdentMiddle(byte b)
{
    return IsIdent(b) || IsInteger(b);
}

// Error_UnknownToken
Error Token_Parse(StringStream *character_stream, Token *out)
{
    byte b;
    bool eof;
    UInt valid_chars = 0;
    StringStream copy = *character_stream;

    // begin lexing
start:
    eof = StringStream_IsEof(&copy);
    b = StringStream_Peek(&copy);

    // don't worry about the eof return, we will just handle that above.
    StringStream_Advance(&copy);

    // parse eof token
    if (eof)
    {
        out->token_type = Token_Eof;
        return Error_Good;
    }

    // parse identifier token
    if (IsIdent(b))
    {
        valid_chars++;

        Token_ParseWhile(&copy, IsIdentMiddle, &valid_chars);
        out->token_type = Token_Identifier;
    }
    else if (IsInteger(b))
    {
        valid_chars++;

        Token_ParseWhile(&copy, IsInteger, &valid_chars);
        out->token_type = Token_Integer;
    }
    else if (IsWhitespace(b))
    {
        // just ignore whitespace
        goto start;
    }
    else if (b == '=')
    {
        valid_chars++;
        out->token_type = Token_Eq;
    }
    else
    {
        return Error_UnknownToken;
    }

    // done lexing, convert to token.
    out->token_data = StringStream_GetStringWithLength(&copy, valid_chars);

    // parse keywords
    if (out->token_type == Token_Identifier)
    {
        if (String_IsStaticEqual(&out->token_data, "if"))
            out->token_type = Token_If;
        else if (String_IsStaticEqual(&out->token_data, "else"))
            out->token_type = Token_Else;
    }

    // update the stream.
    *character_stream = copy;
    return Error_Good;
}

typedef enum NodeType
{
    Node_Integer,
    Node_Identifier,
    Node_Add,
    Node_VariableDecl,
    Node_Value,
    Node_BooleanExpr,
    Node_IfBlock,
    Node_Program
} NodeType;

typedef enum NodeBooleanExprType
{
    NodeBoolExpr_Equal
} NodeBooleanExprType;

typedef struct Node
{
    NodeType node_type;

    union
    {
        struct IntegerNode
        {
            String src;
        } integer_node;

        struct IdentifierNode
        {
            String src;
        } identifier_node;

        struct AddNode
        {
            struct Node *term_l;
            struct Node *term_r;
        } add_node;

        struct VariableDecl
        {
            // identifier node
            struct Node *variable_name;

            // integer node
            struct Node *variable_value;

            struct Node *maybe_next_variable_decl;
        } variable_decl_node;

        struct Value
        {
            // something like a variable
            struct Node *identifier_or_integer;
        } value_node;

        struct BooleanExpr
        {
            NodeBooleanExprType type;
            // both are of type Value
            struct Node *left_node;
            struct Node *right_node;
        } boolean_expr_node;

        struct Program
        {
            struct Node *variable_decl;
        } program_node;
    };
} Node;

void Node_Print(Node *node)
{
    if (node == NULL)
        return;
    switch (node->node_type)
    {
    case Node_Integer:
        String_Print(&node->integer_node.src);
        break;

    case Node_Identifier:
        String_Print(&node->identifier_node.src);
        break;

    case Node_Add:
        Node_Print(node->add_node.term_l);
        printf(" + ");
        Node_Print(node->add_node.term_r);
        break;

    case Node_VariableDecl:
        Node_Print(node->variable_decl_node.variable_name);
        printf(" = ");
        Node_Print(node->variable_decl_node.variable_value);
        printf("\n");
        Node_Print(node->variable_decl_node.maybe_next_variable_decl);
        break;

    case Node_Value:
        Node_Print(node->value_node.identifier_or_integer);
        break;

    case Node_Program:
        Node_Print(node->program_node.variable_decl);
        break;

    default:
        printf("Undefined node type.");
        break;
    }
}

typedef struct ParseState
{
    StringStream stream;
    SaveStack stack;
    SaveStackSaveState stack_save_state;
} ParseState;

// Error_Alloc
Error ParseState_Init(ParseState *p, const String *src)
{
    StringStream_Init(&p->stream, src);
    Error err = SaveStack_Init(&p->stack, sizeof(Node));
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    p->stack_save_state = SaveStack_SaveState(&p->stack);

    return Error_Good;
}

ParseState ParseState_Save(const ParseState *p)
{
    ParseState ret = *p;
    // make sure to update the stack save state.
    ret.stack_save_state = SaveStack_SaveState(&ret.stack);

    return ret;
}

void ParseState_Apply(ParseState *old, const ParseState *new)
{
    *old = *new;
    // update the stack save state so it matches with the new stack.
    old->stack_save_state = SaveStack_SaveState(&old->stack);
}

void ParseState_Undo(ParseState *bad_state)
{
    SaveStack_RestoreState(&bad_state->stack, &bad_state->stack_save_state);
}

// Error_UnknownToken
// Error_UnexpectedToken
Error Node_ParseToken(ParseState *state, TokenType expected_token, String *out)
{
    Error err;
    ParseState save = ParseState_Save(state);
    Token t;

    err = Token_Parse(&save.stream, &t);
    BUBBLE(Error_UnknownToken);
    NOFAIL(err);

    if (t.token_type != expected_token)
        return Error_UnexpectedToken;

    *out = t.token_data;
    ParseState_Apply(state, &save);
    return Error_Good;
}

// Error_UnknownToken
// Error_UnexpectedToken
// Error_Alloc
Error Node_ParseTokenNode(ParseState *state, TokenType expected_token, NodeType node_type, size_t string_offset, Node **node_ptr_out)
{
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
    // we need to cast to byte, since string_offset should be bytes from the start of the node struct.
    *((String *)((byte *)*node_ptr_out + string_offset)) = token_str;

    ParseState_Apply(state, &save);
    return Error_Good;
}

// Error_UnknownToken
// Error_UnexpectedToken
// Error_Alloc
Error Node_ParseInteger(ParseState *state, Node **node_ptr_out)
{
    Error err;
    err = Node_ParseTokenNode(state, Token_Integer, Node_Integer, offsetof(Node, integer_node.src), node_ptr_out);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_UnexpectedToken);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

// Error_UnknownToken
// Error_UnexpectedToken
// Error_Alloc
Error Node_ParseIdentifier(ParseState *state, Node **node_ptr_out)
{
    Error err;
    err = Node_ParseTokenNode(state, Token_Identifier, Node_Identifier, offsetof(Node, identifier_node.src), node_ptr_out);
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_UnexpectedToken);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

// Error_UnknownToken
// Error_ParseFailed
// Error_Alloc
Error Node_ParseValue(ParseState *state, Node **node_ptr_out)
{
    Error err;
    ParseState save = ParseState_Save(state);

    err = Node_ParseInteger(&save, node_ptr_out);
    // non recoverable errors.
    BUBBLE(Error_UnknownToken);
    BUBBLE(Error_Alloc);
    BUBBLE(Error_Internal);
    if (err == Error_Good)
        goto good;
    NOFAIL(err);

    err = Node_ParseIdentifier(&save, node_ptr_out);
    BUBBLE(Error_UnknownToken);
    if (err == Error_UnexpectedToken)
        return Error_ParseFailed;
    BUBBLE(Error_Alloc);
    NOFAIL(err);

good:
    ParseState_Apply(state, &save);
    return Error_Good;
}

typedef enum StateInstructionType
{
    SInstr_Assign,
    SInstr_AddThenAssign
} StateInstructionType;

typedef struct StateInstruction
{
    StateInstructionType type;

    union
    {
        struct Assign
        {
            String dest_variable;
            String src;
        } assign;

        struct AddThenAssign
        {
            String dest_variable;
            String src1;
            String src2;
        } add_then_assign;
    };
} StateInstruction;

typedef enum StateBooleanExprType
{
    SBoolExpr_Eq
} StateBooleanExprType;

typedef struct StateBooleanExpr
{
    StateBooleanExprType type;

    union
    {
        struct Eq
        {
            String op1;
            String op2;
        } eq;
    };
} StateBooleanExpr;

typedef struct State State;

typedef struct StateSwitcher
{
    StateBooleanExpr expr;
    State *true_state;
    State *false_state;
} StateSwitcher;

typedef struct State
{
    // stack of StateInstruction
    Stack state_instructions;
} State;

typedef struct StateMachine
{
    StringToPtrMap variables;
    // stack of State
    Stack states;
} StateMachine;

Error StateMachine_Init(StateMachine *m)
{
    Error err;
    StringToPtrMap_Init(&m->variables);
    err = Stack_Init(&m->states, sizeof(State), 16);
    if (err == Error_Alloc)
        return Error_Alloc;
    NOFAIL(err);

    return Error_Good;
}

#pragma clang diagnostic ignored "-Wunused-variable"

void error(const char *src, const char *msg, UInt line)
{
    printf("%s(%u): %s\n", src, line, msg);
    exit(1);
}

#define IF_ERR(_err, msg)             \
    if (_err == err)                  \
    {                                 \
        error("main", msg, __LINE__); \
    }

#undef NOFAIL
#define NOFAIL                                      \
    if (err != Error_Good)                          \
    {                                               \
        error("main", "internal error.", __LINE__); \
    }

int main(void)
{
    String test_program;
    byte *program_data;
    Error err = String_FromFile(&test_program, &program_data, "test.txt");

    IF_ERR(Error_Alloc, "allocation failure.");
    IF_ERR(Error_UnableToOpenFile, "unable to open file.");
    IF_ERR(Error_WhileReadingFile, "while reading file.");
    NOFAIL;

    ParseState parser;
    err = ParseState_Init(&parser, &test_program);
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node *node = NULL;

    err = Node_ParseValue(&parser, &node);
    IF_ERR(Error_UnknownToken, "unknown token.");
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node_Print(node);

    printf("\nC program:\n");

    return 0;
}
