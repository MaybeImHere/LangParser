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

    Error_UnableToOpenFile,
    Error_WhileReadingFile,

    Error_DuringFirstSlash,
    Error_DuringBackslash,
    Error_DuringOpenQuote,
    Error_DuringOpenQuoteBackslash,
    Error_DuringWhitespace,
    Error_DuringSingleQuote,
    Error_DuringSingleQuoteBackslash,
    Error_DuringLineComment,
    Error_DuringBlockComment,
    Error_DuringMaybeClosingBlockComment,

    Error_Internal
} Error;

const char* Error_ToConstStr(Error err) {
    switch(err) {
        case Error_Good: return "Error_Good";
        case Error_VarExists: return "Error_VarExists";
        case Error_Alloc: return "Error_Alloc";
        case Error_ParseFailed: return "Error_ParseFailed";
        case Error_Eof: return "Error_Eof";
        case Error_OutOfBounds: return "Error_OutOfBounds";
        case Error_UnexpectedToken: return "Error_UnexpectedToken";
        case Error_NothingToPop: return "Error_NothingToPop";
        case Error_FoundNothing: return "Error_FoundNothing";
        case Error_MustCreateNewNode: return "Error_MustCreateNewNode";
        case Error_KeyExists: return "Error_KeyExists";
        case Error_UnableToOpenFile: return "Error_UnableToOpenFile";
        case Error_WhileReadingFile: return "Error_WhileReadingFile";
        case Error_DuringFirstSlash: return "Error_DuringFirstSlash";
        case Error_DuringBackslash: return "Error_DuringBackslash";
        case Error_DuringOpenQuote: return "Error_DuringOpenQuote";
        case Error_DuringOpenQuoteBackslash: return "Error_DuringOpenQuoteBackslash";
        case Error_DuringWhitespace: return "Error_DuringWhitespace";
        case Error_DuringSingleQuote: return "Error_DuringSingleQuote";
        case Error_DuringSingleQuoteBackslash: return "Error_DuringSingleQuoteBackslash";
        case Error_DuringLineComment: return "Error_DuringLineComment";
        case Error_DuringBlockComment: return "Error_DuringBlockComment";
        case Error_DuringMaybeClosingBlockComment: return "Error_DuringMaybeClosingBlockComment";
        case Error_Internal: return "Error_Internal";
        default: return "Unknown error type.";
    }
}

#define NOFAIL(x) if ((x) != Error_Good) { return Error_Internal; }

typedef struct String {
    const byte* data;
    UInt length;
} String;

// Error_Alloc
// Error_UnableToOpenFile
// Error_WhileReadingFile
Error String_FromFile(String* out, byte** data, const char* filename) {
    // first try and open the file
    FILE* file_handle = fopen(filename, "r");
    if (file_handle == NULL) return Error_UnableToOpenFile;

    // set up the allocated buffer with a starting size of 512 bytes.
    UInt current_capacity = 512;
    UInt current_length = 0;
    byte* buf = malloc(current_capacity);
    if (buf == NULL) {
        // didn't allocate, so close the file and return
        fclose(file_handle);
        return Error_Alloc;
    }

    // this will read the entire file into buf
    // since fread does not start from the beginning each time, we only read in the difference between the capacity and the currently read portion
    // in buf.
    UInt current_read_size = current_capacity;
    while (true) {
        // read the next few bytes
        size_t ret_val = fread(buf + (uintptr_t)current_length, sizeof(byte), current_read_size, file_handle);
        current_length += (UInt)ret_val;

        // we didn't read the specified number of bytes. either there weren't anymore bytes, or there was some error.
        if (ret_val != current_read_size) {
            // check for end of file.
            if (feof(file_handle)) {
                *data = buf;
                out->data = buf;
                out->length = current_length;
                return Error_Good;
            } else if (ferror(file_handle)) {
                // there was an error, so just free the buffer and return.
                fclose(file_handle);
                free(buf);
                return Error_WhileReadingFile;
            }
        } else {
            // we read the entire specified read size, so there are probably more bytes to read.
            // we increase the reading size by 1.5x, and add that onto the buffer capacity.
            UInt new_reading_size = current_read_size + (current_read_size >> 1) + 1;
            buf = realloc(buf, current_capacity + new_reading_size);
            if (buf == NULL) {
                fclose(file_handle);
                return Error_Alloc;
            }
            current_capacity += new_reading_size;
        }
    }
}

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

byte String_At(String* s, UInt pos) {
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

typedef struct StringToPtrMapBlock {
    String key;
    void* value;
    UInt hash;

    struct StringToPtrMapBlock* hash_is_smaller;
    struct StringToPtrMapBlock* hash_is_equal;
    struct StringToPtrMapBlock* hash_is_greater;
} StringToPtrMapBlock;

void StringToPtrMapBlock_Init(StringToPtrMapBlock* map, String* key, void* value) {
    map->key = *key;
    map->value = value;
    map->hash = String_Hash(&map->key);

    map->hash_is_smaller = NULL;
    map->hash_is_equal = NULL;
    map->hash_is_greater = NULL;
}

// Error_KeyExists
// Error_MustCreateNewNode
Error StringToPtrMapBlock_ExistsHelper(StringToPtrMapBlock* map, String* key, UInt key_hash, void** value_out, StringToPtrMapBlock*** to_initialize) {
    if (map->hash == key_hash) {
        if (String_IsEqual(&map->key, key)) {
            if (value_out != NULL) *value_out = map->value;
            return Error_KeyExists;
        } else {
            if (map->hash_is_equal != NULL) {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_equal, key, key_hash, value_out, to_initialize);
            } else {
                // we would have to create a new one.
                *to_initialize = &map->hash_is_equal;
                return Error_MustCreateNewNode;
            }
        }
    } else {
        if (key_hash > map->hash) {
            if (map->hash_is_greater != NULL) {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_greater, key, key_hash, value_out, to_initialize);
            } else {
                *to_initialize = &map->hash_is_greater;
                return Error_MustCreateNewNode;
            }
        } else {
            if (map->hash_is_smaller != NULL) {
                return StringToPtrMapBlock_ExistsHelper(map->hash_is_smaller, key, key_hash, value_out, to_initialize);
            } else {
                *to_initialize = &map->hash_is_smaller;
                return Error_MustCreateNewNode;
            }
        }
    }
}

// Error_KeyExists
// Error_Alloc
Error StringToPtrMapBlock_CreateIfNotExist(StringToPtrMapBlock* map, String* key, void* value_ptr) {
    StringToPtrMapBlock** new_node_to_allocate = NULL;
    Error err = StringToPtrMapBlock_ExistsHelper(map, key, String_Hash(key), NULL, &new_node_to_allocate);
    if (err == Error_KeyExists) return Error_KeyExists;
    if (err == Error_MustCreateNewNode) {
        *new_node_to_allocate = malloc(sizeof(StringToPtrMapBlock));
        if (*new_node_to_allocate == NULL) return Error_Alloc;
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

void StringToPtrMap_Init(StringToPtrMap* map) {
    map->has_first_block = false;
}

// Error_KeyExists
// Error_Alloc
Error StringToPtrMap_CreateIfNotExist(StringToPtrMap* map, String* key, void* value_ptr) {
    if (!map->has_first_block) {
        StringToPtrMapBlock_Init(&map->first_block, key, value_ptr);
        return Error_Good;
    } else {
        Error err = StringToPtrMapBlock_CreateIfNotExist(&map->first_block, key, value_ptr);
        if (err == Error_KeyExists) return Error_KeyExists;
        if (err == Error_Alloc) return Error_Alloc;
        NOFAIL(err);
        return Error_Good;
    }
}



typedef enum TokenType {
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

static const char* token_map[] = {
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
    "Token_While"
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
    Node_VariableDeclList,
    Node_Program
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
            // identifier node
            struct Node* variable_name;

            // integer node
            struct Node* variable_value;

            struct Node* maybe_next_variable_decl;
        } variable_decl_node;

        struct Program {
            struct Node* variable_decl;
        } program_node;
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
        case Node_Program:
            Node_Print(node->program_node.variable_decl);
            break;
        default:
            printf("Undefined node type.");
            break;
    }
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

    StringToPtrMap variables;

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

bool ParseState_DoesByteExistAt(ParseState* p, UInt pos) {
    return p->src.length > pos;
}

byte ParseState_AtExtended(ParseState* p, UInt pos) {
    return String_At(&p->src, pos);
}

byte ParseState_At(ParseState* p) {
    return ParseState_AtExtended(p, p->pos);
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

bool ParseState_IsNextByte(ParseState* p, byte b) {
    if (!ParseState_DoesByteExistAt(p, p->pos + 1)) {
        // if we hit end of string, then the byte doesn't match
        return false;
    } else {
        return ParseState_AtExtended(p, p->pos + 1) == b;
    }
}

// this function is just looking for a newline. it doesn't care about the start of the line comment.
// Error_Eof: only if there was no newlines before the end of the file!
Error ParseState_ParseLineComment(ParseState* p) {
    Error err;

    while (true) {
        byte b = ParseState_At(p);
        err = ParseState_Advance(p);
        if (b == (byte)'\n') {
            return Error_Good;
        }
        if (err == Error_Eof) return Error_Eof;
    }
}

// this function is just looking for a */
// it doesn't care about the start of the line comment.
// Error_ParseFailed: if there wasn't a closing */
Error ParseState_ParseBlockComment(ParseState* p) {
    Error err;

    bool was_star = false;
    while (true) {
        byte b = ParseState_At(p);
        err = ParseState_Advance(p);
        
        if (was_star && b == (byte)'/') {
            return Error_Good;
        } else if (b == (byte)'*') {
            was_star = true;
        } else {
            was_star = false;
        }

        if (err == Error_Eof) return Error_ParseFailed;
    }
}

struct KeywordMap {
    UInt len;
    const char* kw;
    TokenType t;
};

static const struct KeywordMap keyword_map[] = {
    {2, "do", Token_Do},
    {2, "if", Token_If},
    {3, "for", Token_For},
    {3, "int", Token_Int},
    {4, "auto", Token_Auto},
    {4, "case", Token_Case},
    {4, "char", Token_Char},
    {4, "else", Token_Else},
    {4, "enum", Token_Enum},
    {4, "goto", Token_Goto},
    {4, "long", Token_Long},
    {4, "void", Token_Void},
    {5, "break", Token_Break},
    {5, "const", Token_Const},
    {5, "float", Token_Float},
    {5, "short", Token_Short},
    {5, "union", Token_Union},
    {5, "while", Token_While},
    {6, "double", Token_Double},
    {6, "extern", Token_Extern},
    {6, "inline", Token_Inline},
    {6, "return", Token_Return},
    {6, "signed", Token_Signed},
    {6, "sizeof", Token_Sizeof},
    {6, "static", Token_Static},
    {6, "struct", Token_Struct},
    {6, "switch", Token_Switch},
    {7, "typedef", Token_Typedef},
    {7, "default", Token_Default},
    {8, "register", Token_Register},
    {8, "restrict", Token_Restrict},
    {8, "unsigned", Token_Unsigned},
    {8, "volatile", Token_Volatile},
    {8, "continue", Token_Continue}
};

void ParseState_CheckForKeywords(ParseState* p, const byte* first_char_ptr, UInt token_length, TokenType* token_type_out) {
    for (UInt i = 0; i < sizeof(keyword_map) / sizeof(*keyword_map); i++) {
        if (keyword_map[i].len == token_length) {
            if (memcmp(keyword_map[i].kw, first_char_ptr, token_length) == 0) {
                *token_type_out = keyword_map[i].t;
            }
        }
    }
}

// assumes the current character is already an identifier character.
Error ParseState_ParseIdentifierOrKeyword(ParseState* p, const byte** first_char_ptr_out, UInt* token_length_out, TokenType* token_type_out) {
    Error err;
    byte b;

    *first_char_ptr_out = ParseState_PosPtr(p);
    *token_length_out = 1;
    *token_type_out = Token_Identifier;
    
    while (true) {
        err = ParseState_Advance(p);
        if (err == Error_Eof) break;
        NOFAIL(err);

        b = ParseState_At(p);

        if (IsIdent(b) || IsInteger(b)) {
            (*token_length_out)++;
        } else {
            break;
        }
    }

    ParseState_CheckForKeywords(p, *first_char_ptr_out, *token_length_out, token_type_out);
    return Error_Good;
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
    if (IsInteger(b)) {
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
        err = ParseState_ParseIdentifierOrKeyword(p, first_char_ptr_out, token_length_out, token_type_out);
        NOFAIL(err);
        return Error_Good;
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
    } else if (b == '/') {
        if (ParseState_IsNextByte(p, '/')) {
            // this is a line comment
            err = ParseState_ParseLineComment(p);
            if (err == Error_Eof) return Error_Eof;
            NOFAIL(err);
        } else if (ParseState_IsNextByte(p, '*')) {
            // this is a block comment
            err = ParseState_ParseBlockComment(p);
            if (err == Error_ParseFailed) return Error_ParseFailed;
            NOFAIL(err);
        } else {
            // just a regular division
            *first_char_ptr_out = ParseState_PosPtr(p);
            *token_length_out = 1;
            *token_type_out = Token_Division;
            
            ParseState_Advance(p);
            return Error_Good;
        }
    } else {
        return Error_ParseFailed;
    }
    return Error_Good;
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

// Error_Alloc
// Error_ParseFailed
Error ParseState_ParseProgram(ParseState* p, Node** out) {
    Error err;
    err = ParseState_AllocNode(p, out);
    if (err == Error_Alloc) return Error_Alloc;
    NOFAIL(err);

    Node* node_ptr = *out;
    node_ptr->node_type = Node_Program;

    err = ParseState_ParseOneOrMoreVariableDecl(p, &node_ptr->program_node.variable_decl);
    if (err == Error_Alloc) return Error_Alloc;
    if (err == Error_ParseFailed) return Error_ParseFailed;
    NOFAIL(err);

    return Error_Good;
}

typedef enum StateInstructionType {
    SInstr_Assign,
    SInstr_AddThenAssign
} StateInstructionType;

typedef struct StateInstruction {
    StateInstructionType type;

    union {
        struct Assign {
            String dest_variable;
            String src;
        } assign;

        struct Assign {
            String dest_variable;
            String src1;
            String src2;
        } add_then_assign;
    };
} StateInstruction;

typedef enum StateBooleanExprType {
    SBoolExpr_Eq
} StateBooleanExprType;

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
    State* true_state;
    State* false_state;
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

Error StateMachine_Init(StateMachine* m) {
    Error err;
    StringToPtrMap_Init(&m->variables);
    err = Stack_Init(&m->states, sizeof(State), 16);
    if (err == Error_Alloc) return Error_Alloc;
    NOFAIL(err);

    return Error_Good;
}

#pragma clang diagnostic ignored "-Wunused-variable"

void error(const char* src, const char* msg, UInt line) {
    printf("%s(%u): %s\n", src, line, msg);
    exit(1);
}

#define IF_ERR(_err, msg) if (_err == err) { error("main", msg, __LINE__); }

#undef NOFAIL
#define NOFAIL if (err != Error_Good) { error("main", "internal error.", __LINE__); }

int main(void) {
    String test_program;
    byte* program_data;
    Error err = String_FromFile(&test_program, &program_data, "test.txt");

    IF_ERR(Error_Alloc, "allocation failure.");
    IF_ERR(Error_UnableToOpenFile, "unable to open file.");
    IF_ERR(Error_WhileReadingFile, "while reading file.");
    NOFAIL;

    ParseState state;
    err = ParseState_Init(&state, test_program);
    NOFAIL;

    Node* node_ptr = NULL;
    err = ParseState_ParseProgram(&state, &node_ptr);
    NOFAIL;

    Node_Print(node_ptr);
    printf("\nC program:\n");

    return 0;
}
