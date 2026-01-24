#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef uint8_t byte;
typedef uint32_t UInt;
typedef int32_t Int;

typedef enum Error {
    Error_Good,
    Error_VarExists,
    Error_Alloc,
    Error_ParseFailed,
    Error_Eof,
    Error_OutOfBounds,
    Error_UnexpectedToken,
    Error_NothingToPop,
    Error_FoundNothing,
    Error_MustCreateNewNode,
    Error_KeyExists,

    Error_Internal
} Error;

#define NOFAIL(x) if ((x) != Error_Good) { return Error_Internal; }

typedef struct String {
    const byte* data;
    UInt length;
} String;

String StringFromLiteral(const char* literal) {
    String ret = {
        .data = (const byte*)literal,
        .length = strlen(literal)
    };
    
    return ret;
}

String String_Create(const byte* src, UInt length) {
    String ret = {
        .data = src,
        .length = length
    };
    return ret;
}

void String_Print(const String* src) {
    for(UInt i = 0; i < src->length; i++) {
        putchar(src->data[i]);
    }
}

byte StringAt(String* s, UInt pos) {
    return s->data[pos];
}

UInt String_Hash(const String* src) {
    UInt ret = 0;
    for (UInt i = 0; i < src->length; i++) {
        ret *= 17;
        ret += src->data[i];
    }

    return ret;
}

bool String_IsEqual(const String* s1, const String* s2) {
    if (s1->length != s2->length) return false;
    return memcmp(s1->data, s2->data, s1->length) == 0;
}

typedef struct StackBlock {
    byte* data;
    UInt length;
    UInt capacity;
    UInt bytes_per_item;
    
    struct StackBlock* prev_block;
    struct StackBlock* next_block;
} StackBlock;

// Error_Alloc: if unable to allocate memory
Error StackBlock_Init(StackBlock* stack_block, UInt bytes_per_item, UInt capacity) {
    stack_block->data = calloc(capacity, bytes_per_item);
    if (stack_block->data == NULL) return Error_Alloc;

    stack_block->length = 0;
    stack_block->capacity = capacity;
    stack_block->bytes_per_item = bytes_per_item;

    stack_block->prev_block = NULL;
    stack_block->next_block = NULL;

    return Error_Good;
}

void StackBlock_Free(StackBlock* stack_block) {
    if (stack_block == NULL) return;
    free(stack_block->data);
    StackBlock_Free(stack_block->next_block);
}

// Error_Alloc
Error StackBlock_Push(StackBlock* stack_block, void* src, void** ptr_out, StackBlock** final_block) {
    Error ret = Error_Good;

    while (true) {
        // create or go to the next block if we are out of space 
        if (stack_block->length >= stack_block->capacity) {
            // check if we have to create the block
            if (stack_block->next_block == NULL) {
                StackBlock* next_block = malloc(sizeof(StackBlock));
                if (next_block == NULL) return Error_Alloc;

                stack_block->next_block = next_block;

                ret = StackBlock_Init(next_block, stack_block->bytes_per_item, stack_block->capacity + (stack_block->capacity >> 1) + 1);
                next_block->prev_block = stack_block;
                if (ret == Error_Alloc) {
                    free(next_block);
                    return Error_Alloc;
                }
                // we just let the loop finish so that way the other branch to write the data will be taken. 
                stack_block = stack_block->next_block;
            } else {
                stack_block = stack_block->next_block;
            }
        } else {
            byte* dest_ptr = stack_block->data + (uintptr_t)(stack_block->bytes_per_item * stack_block->length);
            if (ptr_out != NULL) *ptr_out = dest_ptr;
            if (src != NULL) memcpy(dest_ptr, src, stack_block->bytes_per_item);
            stack_block->length++;
            if (final_block != NULL) *final_block = stack_block;
            return Error_Good;
        }
    }
}

void* StackBlock_GetObjPtr(StackBlock* stack_block, UInt index) {
    return &(stack_block->data[index * stack_block->bytes_per_item]);
}

void StackBlock_GetTopObj(StackBlock* stack_block, void* out) {
    memcpy(out, StackBlock_GetObjPtr(stack_block, stack_block->length - 1), stack_block->bytes_per_item);
}

void StackBlock_PopUnsafe(StackBlock* stack_block, void* out) {
    if (out != NULL) { StackBlock_GetTopObj(stack_block, out); }
    stack_block->length--;
}

typedef struct Stack {
    StackBlock stack_block;
    StackBlock* last_block_with_items;
    UInt stack_size;
} Stack;

// Error_Alloc
Error Stack_Init(Stack* out, UInt bytes_per_item, UInt capacity) {
    Error err = StackBlock_Init(&out->stack_block, bytes_per_item, capacity);
    if (err == Error_Alloc) return Error_Alloc;

    out->last_block_with_items = &out->stack_block;
    out->stack_size = 0;

    return Error_Good;
}

void Stack_Free(Stack* out) {
    if (out == NULL) return;
    StackBlock_Free(&out->stack_block);
}

// Error_Alloc
Error Stack_Push(Stack* out, void* src, void** ptr_out) {
    Error err = StackBlock_Push(out->last_block_with_items, src, ptr_out, &out->last_block_with_items);
    if (err == Error_Alloc) return Error_Alloc;

    out->stack_size++;

    return Error_Good;
}

// Error_OutOfBounds
Error Stack_Peek(Stack* in, void** ptr_out, UInt index_from_top) {
    StackBlock* current_block = in->last_block_with_items;
    
    if (!(index_from_top < in->stack_size)) return Error_OutOfBounds;
    
    // the index of the object as a regular array index.
    UInt converted_index = in->stack_size - index_from_top - 1;
    // when we go to the previous block, we need to keep track of how many indices we skipped in total.
    UInt objects_skipped = 0;

    while (true) {
        UInt start_pos_of_block = in->stack_size - current_block->length - objects_skipped;
        // if the index is in the previous block
        if (converted_index < start_pos_of_block) {
            current_block = current_block->prev_block;
            objects_skipped += current_block->length;
            continue;
        } else {
            // the position of the object within the current block.
            UInt block_position = converted_index - start_pos_of_block;
            *ptr_out = &(current_block->data[block_position * current_block->bytes_per_item]);
            return Error_Good;
        }
    }
}

typedef struct StackInfo {
    UInt stack_position;
    bool is_last_item;
} StackInfo;

void Stack_Loop(Stack* stack, void(*func_ptr)(void*, const StackInfo*)) {
    UInt index = 0;
    StackBlock* stack_block = &(stack->stack_block);    
    if (stack_block->length == 0) return;
    StackInfo info;

    while (true) {
        // set info struct
        info.stack_position = index;
        info.is_last_item = (index >= stack->stack_size);

        // call function
        func_ptr(stack_block->data + (uintptr_t)(index * stack_block->bytes_per_item), &info);
        
        // check to see if we are at a stack block boundary/end of the stack entirely.
        if (index >= stack_block->length - 1) {
            if (stack_block->next_block == NULL) {
                return;
            } else {
                stack_block = stack_block->next_block;
                index = 0;
                continue;
            }
        } else {
            index++;
        }
    }
}

// Error_NothingToPop
Error Stack_Pop(Stack* stack, void* out) {
    StackBlock* last_block = stack->last_block_with_items;
    const UInt block_length = last_block->length;

    if (block_length > 1) {
        // we don't have to worry about the block getting emptied.
        StackBlock_PopUnsafe(last_block, out);
        return Error_Good;
    } else if (block_length == 1) {
        // just have to make sure we go to the previous block after popping.
        StackBlock_PopUnsafe(last_block, out);
        if (last_block->prev_block != NULL) {
            stack->last_block_with_items = last_block->prev_block;
        }
        return Error_Good;
    } else {
        return Error_NothingToPop;
    }
}

typedef struct StringToPtrMap {
    String key;
    void* value;
    UInt hash;

    struct StringToPtrMap* hash_is_smaller;
    struct StringToPtrMap* hash_is_equal;
    struct StringToPtrMap* hash_is_greater;
} StringToPtrMap;

void StringToPtrMap_Init(StringToPtrMap* map, String* key, void* value) {
    map->key = *key;
    map->value = value;
    map->hash = String_hash(&map->key);

    map->hash_is_smaller = NULL;
    map->hash_is_equal = NULL;
    map->hash_is_greater = NULL;
}

// Error_KeyExists
// Error_MustCreateNewNode
Error StringToPtrMap_ExistsHelper(StringToPtrMap* map, String* key, UInt key_hash, void** value_out, StringToPtrMap*** to_initialize) {
    if (map->hash == key_hash) {
        if (String_IsEqual(&map->key, key)) {
            if (value_out != NULL) *value_out = map->value;
            return Error_KeyExists;
        } else {
            if (map->hash_is_equal != NULL) {
                return StringToPtrMap_ExistsHelper(map->hash_is_equal, key, key_hash, value_out, to_initialize);
            } else {
                // we would have to create a new one.
                *to_initialize = &map->hash_is_equal;
                return Error_MustCreateNewNode;
            }
        }
    } else {
        if (key_hash > map->hash) {
            if (map->hash_is_greater != NULL) {
                return StringToPtrMap_ExistsHelper(map->hash_is_greater, key, key_hash, value_out, to_initialize);
            } else {
                *to_initialize = &map->hash_is_greater;
                return Error_MustCreateNewNode;
            }
        } else {
            if (map->hash_is_smaller != NULL) {
                return StringToPtrMap_ExistsHelper(map->hash_is_smaller, key, key_hash, value_out, to_initialize);
            } else {
                *to_initialize = &map->hash_is_smaller;
                return Error_MustCreateNewNode;
            }
        }
    }
}

// Error_KeyExists
// Error_Alloc
Error StringToPtrMap_CreateIfNotExist(StringToPtrMap* map, String* key, void* value_ptr) {
    StringToPtrMap** new_node_to_allocate = NULL;
    Error err = StringToPtrMap_ExistsHelper(map, key, String_Hash(key), NULL, &new_node_to_allocate);
    if (err == Error_KeyExists) return Error_KeyExists;
    if (err == Error_MustCreateNewNode) {
        *new_node_to_allocate = malloc(sizeof(StringToPtrMap));
        if (*new_node_to_allocate == NULL) return Error_Alloc;
        StringToPtrMap_Init(*new_node_to_allocate, key, value_ptr);
        return Error_Good;
    }
    NOFAIL(err);
}

typedef enum TokenType {
    Token_Integer,
    Token_Plus,
    Token_Eq,
    Token_Identifier,
    Token_Eof
} TokenType;

typedef struct Token {
    TokenType token_type;
    String token_data;
} Token;

Token Token_Create(TokenType token_type, const byte* data, UInt length) {
    Token ret = {
        .token_type = token_type,
        .token_data = String_Create(data, length)
    };
    return ret;
}

const char* token_map[] = {
    "Int",
    "+",
    "=",
    "Identifier"
};

void Token_Print(const Token* token) {
    printf("%s '", token_map[token->token_type]);
    String_Print(&token->token_data);
    putchar('\'');
}

typedef enum NodeType {
    Node_Integer,
    Node_Identifier,
    Node_Token,
    Node_Add,
    Node_VariableDecl,
    Node_VariableDeclList
} NodeType;

typedef struct Node {
    NodeType node_type;

    union {
        struct IntegerNode {
            String src;
        } integer_node;

        struct IdentifierNode {
            String src;
        } identifier_node;

        struct TokenNode {
            Token token;
        } token_node;

        struct AddNode {
            struct Node* term_l;
            struct Node* term_r;
        } add_node;

        struct VariableDecl {
            struct Node* variable_name;
            struct Node* variable_value;

            struct Node* maybe_next_variable_decl;
        } variable_decl_node;
    };
} Node;

Node Node_CreateInteger(String src) {
    Node ret = {
        .node_type = Node_Integer,
        .integer_node = {
            .src = src
        }
    };
    return ret;
}

Node Node_CreateIdentifier(String src) {
    Node ret = {
        .node_type = Node_Identifier,
        .identifier_node = {
            .src = src
        }
    };
    return ret;
}

Node Node_CreateVariableDecl(Node* variable_name, Node* variable_value, Node* next_variable_decl) {
    Node ret = {
        .node_type = Node_VariableDecl,
        .variable_decl_node = {
            .variable_name = variable_name,
            .variable_value = variable_value,
            .maybe_next_variable_decl = next_variable_decl
        }
    };
    return ret;
}

void Node_Print(Node* node) {
    if (node == NULL) return;
    switch(node->node_type) {
        case Node_Integer:
            String_Print(&node->integer_node.src);
            break;
        
        case Node_Identifier:
            String_Print(&node->identifier_node.src);
            break;
        
        case Node_Token:
            Token_Print(&node->token_node.token);
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

        default:
            printf("Undefined node type.");
            break;
    }
}

// #define NOFAIL(err) if (err != Error_Good) { return Error_Internal; }
// #define A(x) x + 1;
// NOFAIL(A(x))

typedef enum DefineExpressionBlockType {
    DefineExprBlock_String,
    DefineExprBlock_Argument
} DefineExpressionBlockType;

typedef struct DefineExpressionBlock {
    DefineExpressionBlockType block_type;

    union {
        String string_chars;
        UInt arg_number;
    };
} DefineExpressionBlock;

typedef struct DefineExpression {
    DefineExpressionBlock first_block;
} DefineExpression;

typedef struct ProgramBlock {
    String data;
    struct ProgramBlock* next_block;
} ProgramBlock;

void ProgramBlock_Init(ProgramBlock* block, String* src, UInt start_pos) {
    block->data.data = src->data + (uintptr_t)start_pos;
    block->data.length = 0;
    block->next_block = NULL;
}

void ProgramBlock_IncrementLength(ProgramBlock* block) {
    block->data.length++;
}

typedef struct Preprocessor {
    String src;
    UInt pos;
    ProgramBlock processed_program;
    ProgramBlock* last_block;
} Preprocessor;

void Preprocessor_Init(Preprocessor* p, String* src) {
    p->src = *src;
    p->pos = 0;
    ProgramBlock_Init(&p->processed_program, src, p->pos);
    p->last_block = &p->processed_program;
}

byte Preprocessor_Get(Preprocessor* p) {
    return StringAt(&p->src, p->pos);
}

bool Preprocessor_IsEof(Preprocessor* p) {
    return p->pos >= p->src.length;
}

Error Preprocessor_ParseLine(Preprocessor* p) {
    // before hitting a preprocessor stmt

    bool can_parse_preproc = true;
    byte c;
    while (true) {
        if (Preprocessor_IsEof(p)) return Error_Good;

        c = Preprocessor_Get(p);
        p->pos++;
        if (c == '#' && can_parse_preproc) {
            break;
        } else if (!IsWhitespace(c)) {
            can_parse_preproc = false;
        } else if (c == '\n') {
            can_parse_preproc = true;
        }
        ProgramBlock_IncrementLength(p->last_block);
    }

    // now parsing preproc stmt

    char* string_to_parse = NULL;
    UInt string_to_parse_pos = 1;
    int state = 0;

    while (true) {
        if (Preprocessor_IsEof(p)) return Error_ParseFailed;

        c = Preprocessor_Get(p);
        p->pos++;

        if (state == 0) {
            if (c == 'd') {
                string_to_parse = "define";
                state = 1;
            } else if (c == 'i') {
                string_to_parse = "include";
                state = 2;
            } else if (!IsWhitespace(c)) {
                return Error_ParseFailed;
            }
        } else if (state == 1 || state == 2) {
            if (string_to_parse[string_to_parse_pos] == '\0') {
                // done with parsing the define or include
                break;
            } else if (string_to_parse[string_to_parse_pos] != c) {
                return Error_ParseFailed;
            }
            string_to_parse_pos++;
        }
    }

    // done parsing the preprocessor instruction, now parse args

    if (state == 1) {
        while (true) {
            if (Preprocessor_IsEof(p)) return Error_ParseFailed;

            c = Preprocessor_Get(p);
            p->pos++;
        }
    } else if (state == 2) {
        state = 0;
        while (true) {
            if (Preprocessor_IsEof(p)) return Error_ParseFailed;

            c = Preprocessor_Get(p);
            p->pos++;

            if (state == 0) {
                if (IsWhitespace(c)) {
                    continue;
                } else if (c == '<') {
                    state = 1;
                } else { return Error_ParseFailed; }
            }
        }
    } else {
        return Error_Internal;
    }

    return Error_Good;
}

typedef struct ParseState {
    // a stack of Node
    Stack object_stack;

    // sometimes, we want to try multiple different branches.
    // this would involve allocations in each branch. to get rid of any allocations from a failed branch,
    // we simply set up a recorder to record the number of allocations. then, we can just pop them all if
    // they failed. 
    Stack num_to_pop;
    UInt* cur_num_to_pop;
    Token current_token;

    String src;
    UInt pos;
    bool eof_state;
    bool has_token;
} ParseState;

// Error_Alloc
Error ParseState_Init(ParseState* state, String src) {
    Error ret = Stack_Init(&state->object_stack, sizeof(Node), 256);
    if (ret == Error_Alloc) goto err1;
    NOFAIL(ret);

    ret = Stack_Init(&state->num_to_pop, sizeof(UInt), 256);
    if (ret == Error_Alloc) goto err2;
    NOFAIL(ret);

    UInt num_to_pop_initial = 0;
    ret = Stack_Push(&state->num_to_pop, &num_to_pop_initial, (void**)&state->cur_num_to_pop);
    if (ret == Error_Alloc) goto err3;
    NOFAIL(ret);

    state->src = src;
    state->pos = 0;
    state->eof_state = false;
    state->has_token = false;

    return Error_Good;
    
    err3:
    Stack_Free(&state->num_to_pop);
    err2:
    Stack_Free(&state->object_stack);
    err1:
    return Error_Alloc;
}

Error ParseState_AllocNode(ParseState* state, Node** node_ptr) {
    Error err = Stack_Push(&state->object_stack, NULL, (void**)node_ptr);
    if (err == Error_Alloc) return Error_Alloc;
    NOFAIL(err);

    (*state->cur_num_to_pop)++;

    return Error_Good;
}

// Error_Alloc
Error ParseState_NewPopCounter(ParseState* state) {
    UInt num_to_pop_initial = 0;
    Error err = Stack_Push(&state->num_to_pop, &num_to_pop_initial, (void**)&state->cur_num_to_pop);
    if (err == Error_Alloc) return Error_Alloc;
    NOFAIL(err);

    return Error_Good;
}

// nofail
Error ParseState_RevertPopCounter(ParseState* state) {
    Error err;
    for (UInt i = 0; i < *state->cur_num_to_pop; i++) {
        err = Stack_Pop(&state->object_stack, NULL);
        NOFAIL(err);
    }
    err = Stack_Pop(&state->num_to_pop, NULL);
    NOFAIL(err);

    err = Stack_Peek(&state->num_to_pop, (void**)&state->cur_num_to_pop, 0);
    NOFAIL(err);

    return Error_Good;
}

// nofail
Error ParseState_CommitPopCounter(ParseState* state) {
    Error err;
    UInt extra_nodes_to_pop = 0;
    err = Stack_Pop(&state->num_to_pop, &extra_nodes_to_pop);
    NOFAIL(err);

    err = Stack_Peek(&state->num_to_pop, (void**)&state->cur_num_to_pop, 0);
    NOFAIL(err);

    // make sure that if the current save state is failed, we pop the extra nodes created afterwards.
    *(state->cur_num_to_pop) += extra_nodes_to_pop;

    return Error_Good;
}

byte ParseState_At(ParseState* p) {
    return StringAt(&p->src, p->pos);
}

bool IsWhitespace(byte b) {
    return b <= 32 || b >= 127;
}

bool IsIdent(byte b) {
    return ('a' <= b && 'z' >= b) || ('A' <= b && 'Z' >= b) || (b == '_');
}

bool IsInteger(byte b) {
    return ('0' <= b && '9' >= b);
}

// Error_Eof
Error ParseState_Advance(ParseState* p) {
    if (p->pos >= p->src.length - 1) {
        p->eof_state = true;
        return Error_Eof;
    } else {
        p->pos++;
        return Error_Good;
    }
}

const byte* ParseState_PosPtr(ParseState* p) {
    return p->src.data + (uintptr_t)p->pos;
}

// Error_Eof
Error ParseState_SkipWhitespace(ParseState* p, bool* was_newline) {
    *was_newline = false;
    while (true) {
        byte b = ParseState_At(p);

        // first check for whitespace
        if (IsWhitespace(b)) {
            if (b == '\n') *was_newline = true;
            Error err = ParseState_Advance(p);
            if (err == Error_Eof) return Error_Eof;
            NOFAIL(err);
            continue;
        } else {
            return Error_Good;
        }
    }
}

// DOES NOT SKIP WHITESPACE!
// Error_ParseFailed
// Error_Eof
Error ParseState_ParseStringLiteral(ParseState* p, const byte* str) {
    Error err;
    UInt prev_pos = p->pos;
    bool prev_eof = p->eof_state;

    while (true) {
        if (*str == 0) return Error_Good;

        byte b = ParseState_At(p);

        if (b == *str) {
            // parse preprocessor directives.
            err = ParseState_Advance(p);
            if (err == Error_Eof) {
                if (*(str+1) != 0) {
                    p->pos = prev_pos;
                    p->eof_state = prev_eof;
                    return Error_Eof;
                }
                return Error_Good;
            }
            NOFAIL(err);
            str++;
        } else {
            p->pos = prev_pos;
            p->eof_state = prev_eof;
            return Error_ParseFailed;
        }
    }
}

// Error_Eof
// Error_ParseFailed: unknown token.
Error ParseState_NextTokenHelper(ParseState* p, const byte** first_char_ptr_out, UInt* token_length_out, TokenType* token_type_out) {
    Error err = Error_Good;

    if (p->eof_state) return Error_Eof;

    bool was_newline = false;
    err = ParseState_SkipWhitespace(p, &was_newline);
    if (err == Error_Eof) return Error_Eof;
    NOFAIL(err);

    byte b = ParseState_At(p);
    if (b == '#' && was_newline == true) {
        // parse preprocessor directives.
        err = ParseState_Advance(p);
        if (err == Error_Eof) return Error_ParseFailed;
        NOFAIL(err);

        err = ParseState_ParseStringLiteral(p, "include");
        NOFAIL(err);
        err = ParseState_ParseStringLiteral(p, "define");
        NOFAIL(err);

    } else if (IsInteger(b)) {
        *first_char_ptr_out = ParseState_PosPtr(p);
        *token_length_out = 1;
        *token_type_out = Token_Integer;

        while (true) {
            err = ParseState_Advance(p);
            if (err == Error_Eof) return Error_Good;
            NOFAIL(err);

            b = ParseState_At(p);

            if (IsInteger(b)) {
                (*token_length_out)++;
            } else {
                return Error_Good;
            }
        }
    } else if (IsIdent(b)) {
        *first_char_ptr_out = ParseState_PosPtr(p);
        *token_length_out = 1;
        *token_type_out = Token_Identifier;

        while (true) {
            err = ParseState_Advance(p);
            if (err == Error_Eof) return Error_Good;
            NOFAIL(err);

            b = ParseState_At(p);

            if (IsIdent(b) || IsInteger(b)) {
                (*token_length_out)++;
            } else {
                return Error_Good;
            }
        }
    } else if (b == '+') {
        *first_char_ptr_out = ParseState_PosPtr(p);
        *token_length_out = 1;
        *token_type_out = Token_Plus;

        ParseState_Advance(p);
        return Error_Good;
    } else if (b == '=') {
        *first_char_ptr_out = ParseState_PosPtr(p);
        *token_length_out = 1;
        *token_type_out = Token_Eq;

        ParseState_Advance(p);
        return Error_Good;
    } else {
        return Error_ParseFailed;
    }
}

// Error_ParseFailed
Error ParseState_PeekToken(ParseState* p, Token* out) {
    if (p->has_token) {
        *out = p->current_token;
        return Error_Good;
    }

    const byte* token_data_ptr = NULL;
    UInt token_length;
    TokenType token_type;

    Error err = ParseState_NextTokenHelper(p, &token_data_ptr, &token_length, &token_type);
    if (err == Error_Eof) {
        p->current_token.token_type = Token_Eof;
        *out = p->current_token;
        p->has_token = true;
        return Error_Good;
    } else if (err == Error_ParseFailed) {
        p->has_token = false;
        return Error_ParseFailed;
    } else {
        NOFAIL(err);
        p->current_token = Token_Create(token_type, token_data_ptr, token_length);
        *out = p->current_token;
        p->has_token = true;
        return Error_Good;
    }
}

void ParseState_ConsumeToken(ParseState* p) {
    p->has_token = false;
}

// Error_Alloc
// Error_ParseFailed
Error ParseState_ParseInteger(ParseState* p, Node** out) {
    Error err;
    Token token;
    err = ParseState_PeekToken(p, &token);
    if (err == Error_ParseFailed) return Error_ParseFailed;
    NOFAIL(err);

    if (token.token_type == Token_Integer) {
        ParseState_ConsumeToken(p);

        // allocate the node
        err = ParseState_AllocNode(p, out);
        if (err == Error_Alloc) return Error_Alloc;
        NOFAIL(err);
        
        // now set the memory
        **out = Node_CreateIdentifier(token.token_data);
        return Error_Good;
    } else {
        return Error_ParseFailed;
    }
}

// Error_Alloc
// Error_ParseFailed
Error ParseState_ParseIdentifier(ParseState* p, Node** out) {
    Error err;
    Token token;
    err = ParseState_PeekToken(p, &token);
    if (err == Error_ParseFailed) return Error_ParseFailed;
    NOFAIL(err);

    if (token.token_type == Token_Identifier) {
        ParseState_ConsumeToken(p);

        // allocate the node
        err = ParseState_AllocNode(p, out);
        if (err == Error_Alloc) return Error_Alloc; 
        NOFAIL(err);
        
        // now set the memory
        **out = Node_CreateIdentifier(token.token_data);
        return Error_Good;
    } else {
        return Error_ParseFailed;
    }
}

// Error_Alloc
// Error_ParseFailed
Error ParseState_ParseOneOrMoreVariableDecl(ParseState* p, Node** out) {
    Error err;
    Token token;

    Node** current_output_loc = out;
    Node* variable_name = NULL;
    Node* variable_value = NULL;
    bool parsed_at_least_one = false;
    while (true) {
        // set up the pop stack so we can revert if the parsing goes wrong
        err = ParseState_NewPopCounter(p);
        if (err == Error_Alloc) return Error_Alloc;
        NOFAIL(err);

        // first parse the variable name
        err = ParseState_ParseIdentifier(p, &variable_name);
        if (err == Error_Alloc) return Error_Alloc;
        if (err == Error_ParseFailed) goto failed_parse;
        NOFAIL(err);

        // now parse the equals sign
        err = ParseState_PeekToken(p, &token);
        if (err == Error_ParseFailed) goto failed_parse;
        NOFAIL(err);

        if (token.token_type != Token_Eq) {
            return Error_ParseFailed;
        } else {
            ParseState_ConsumeToken(p);
        }

        // now parse the variable value
        err = ParseState_ParseInteger(p, &variable_value);
        if (err == Error_Alloc) return Error_Alloc;
        if (err == Error_ParseFailed) goto failed_parse;
        NOFAIL(err);

        // now allocate a new node and set the data
        err = ParseState_AllocNode(p, current_output_loc);
        if (err == Error_Alloc) return Error_Alloc;
        NOFAIL(err);

        **current_output_loc = Node_CreateVariableDecl(variable_name, variable_value, NULL);
        parsed_at_least_one = true;

        // since nothing failed, commit the changes of the current node.
        ParseState_CommitPopCounter(p);
        
        // now try parsing the next variable declaration
        // set the output location to the pointer to the next variable decl in the struct we just created.
        Node* new_node = *current_output_loc;
        current_output_loc = &new_node->variable_decl_node.maybe_next_variable_decl;

        // make sure to skip over the error handling code below.
        continue;

        failed_parse:
        ParseState_RevertPopCounter(p);
        if (parsed_at_least_one) {
            return Error_Good;
        } else {
            return Error_ParseFailed;
        }
    }
}

#pragma clang diagnostic ignored "-Wunused-variable"

int main(void) {
    String test_program = StringFromLiteral("a = 1 b = 2");

    ParseState parse_state;
    Error err = ParseState_Init(&parse_state, test_program);
    if (err != Error_Good) {
        printf("init error");
        return 1;
    }

    Token token;
    UInt iterations = 0;
    Node* variable_decl = NULL;
    err = ParseState_ParseOneOrMoreVariableDecl(&parse_state, &variable_decl);
    printf("err: %d\n", err);
    if (err != Error_Good) return 1;

    Node_Print(variable_decl);
    
    return 0;
}
