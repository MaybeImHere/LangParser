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

typedef struct StringStream {
    String src;
    UInt pos;
    bool eof;
} StringStream;

void StringStream_Init(StringStream* s, String* src) {
    s->src = *src;
    s->pos = 0;
    // if we are already at the end, make sure to set the eof bit.
    s->eof = src->length == 0;
}

// returns the byte at the current position, or 0 if at the end of file.
byte StringStream_Peek(StringStream* s) {
    if (s->eof) {
        return 0;
    } else {
        return s->src.data[s->pos];
    }
}

// Error_Eof: if the next peek call will result in Error_Eof
Error StringStream_Advance(StringStream* s) {
    if (s->eof) return Error_Eof;
    s->pos++;
    if (s->pos == s->src.length) {
        s->eof = true;
        return Error_Eof;
    }
    return Error_Good;
}

bool StringStream_IsEof(StringStream* s) {
    return s->eof;
}

String StringStream_GetStringWithLength(StringStream* s, UInt length) {
    return String_Create(&s->src.data[s->pos], length);
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
    Node_Value,
    Node_BooleanExpr,
    Node_IfBlock,
    Node_Program
} NodeType;

typedef enum NodeBooleanExprType {
    NodeBoolExpr_Equal
} NodeBooleanExprType;

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

        struct Value {
            // something like a variable
            struct Node* identifier_or_integer;
        } value_node;

        struct BooleanExpr {
            NodeBooleanExprType type;
            // both are of type Value
            struct Node* left_node;
            struct Node* right_node;
        } boolean_expr_node;

        struct Program {
            struct Node* variable_decl;
        } program_node;
    };
} Node;

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

bool IsWhitespace(byte b) {
    return b <= 32 || b >= 127;
}

bool IsIdent(byte b) {
    return ('a' <= b && 'z' >= b) || ('A' <= b && 'Z' >= b) || (b == '_');
}

bool IsInteger(byte b) {
    return ('0' <= b && '9' >= b);
}

typedef struct ParseStateSavePoint {
    Stack* node_stack;
    UInt nodes_created;

    StringStream str;
} ParseStateSavePoint;

// Error_Alloc
Error ParseStateSavePoint_Init(ParseStateSavePoint* p, String* src) {
    p->node_stack = malloc(sizeof(Stack));
    if (p->node_stack == NULL) return Error_Alloc;
    Error err = Stack_Init(p->node_stack, sizeof(Node), 8);
    if (err == Error_Alloc) {
        free(p->node_stack);
        return Error_Alloc;
    }
    p->nodes_created = 0;
    StringStream_Init(&p->str, src);
    return Error_Good;
}

// Error_Eof
Error ParseStateSavePoint_PeekByte(ParseStateSavePoint* p, byte* out) {
    byte b = StringStream_Peek(&p->str);
    if (b == '\0') {
        if (StringStream_IsEof(&p->str)) {
            return Error_Eof;
        }
    }
    *out = b;
    return Error_Good;
}

void ParseStateSavePoint_AdvanceByte(ParseStateSavePoint* p) {
    // we don't care about end of file.
    // that should be handled by the PeekByte caller anyway.
    StringStream_Advance(&p->str);
}

Error ParseStateSavePoint_SkipWhitespace(ParseStateSavePoint* p) {
    Error err;
    byte b;
    while (true) {
        err = ParseStateSavePoint_PeekByte(p, &b);
        if (err == Error_Eof) return Error_Good;
        NOFAIL(err);

        // first check for whitespace
        if (IsWhitespace(b)) {
            ParseStateSavePoint_AdvanceByte(p);
            continue;
        } else {
            return Error_Good;
        }
    }
}

// Error_Alloc
Error ParseStateSavePoint_AllocNode(ParseStateSavePoint* p, NodeType node_type, Node** ptr_to_node_out) {
    Error err = Stack_Push(p->node_stack, NULL, (void**)ptr_to_node_out);
    if (err == Error_Alloc) return Error_Alloc;
    NOFAIL(err);
    (**ptr_to_node_out).node_type = node_type;
    p->nodes_created++;
    return Error_Good;
}

void ParseStateSavePoint_SaveLexerState(ParseStateSavePoint* p, StringStream* out) {
    *out = p->str;
}

void ParseStateSavePoint_RestoreLexerState(ParseStateSavePoint* p, StringStream* in) {
    p->str = *in;
}

String ParseStateSavePoint_GetNPreviousBytes(ParseStateSavePoint* p, UInt n) {
    return StringStream_GetStringWithLength(&p->str, n);
}

String ParseStateSavePoint_GetNPreviousBytesDropPeeked(ParseStateSavePoint* p, UInt n) {
    StringStream temp = p->str;
    temp.pos--;
    return StringStream_GetStringWithLength(&temp, n);
}

ParseStateSavePoint ParseStateSavePoint_CreateNewSavePoint(ParseStateSavePoint* p) {
    ParseStateSavePoint ret = {
        .node_stack = p->node_stack,
        .nodes_created = 0,
        .str = p->str
    };

    return ret;
}

void ParseStateSavePoint_Commit(const ParseStateSavePoint* save_point, ParseStateSavePoint* to_modify) {
    to_modify->nodes_created += save_point->nodes_created;
    to_modify->str = save_point->str;
}

Error ParseStateSavePoint_DestroySavePoint(ParseStateSavePoint* p) {
    while (p->nodes_created > 0) {
        NOFAIL(Stack_Pop(p->node_stack, NULL));
        p->nodes_created--;
    }
    return Error_Good;
}

typedef Error(*ParseFunc)(ParseStateSavePoint*, Node**);

// Error_Alloc
// Error_ParseFailed
Error ParseStateSavePoint_ParseOneOf(ParseStateSavePoint* p, ParseFunc func[], UInt number_of_functions, Node** node_ptr_out) {
    Error err;
    Node* node_ptr = NULL;

    for (UInt function_index = 0; function_index < number_of_functions; function_index++) {
        err = (func[function_index])(p, &node_ptr);
        if (err == Error_Alloc) {
            return Error_Alloc;
        } else if (err == Error_ParseFailed) {
            continue;
        } else if (err == Error_Good) {
            *node_ptr_out = node_ptr;
            return Error_Good;
        } else {
            return Error_Internal;
        }
    }
    return Error_ParseFailed;
}

Error ParseStateSavePoint_ParseByte(ParseStateSavePoint* p, bool(*isValid)(byte))

// Error ParseStateSavePoint_ParseToken(ParseStateSavePoint* p, TokenType token_type, NodeType node_type_out, Node** ptr_to_node_out)

// Error_ParseFailed
// Error_Alloc
Error ParseStateSavePoint_ParseIdentifier(ParseStateSavePoint* p, Node** ptr_to_node_out) {
    Error err;
    byte b;
    UInt identifier_length = 0;

    StringStream before_lexing;
    ParseStateSavePoint_SaveLexerState(p, &before_lexing);

    NOFAIL(ParseStateSavePoint_SkipWhitespace(p));

    // parse first char
    err = ParseStateSavePoint_PeekByte(p, &b);
    if (err == Error_Eof || !IsIdent(b)) {
        // need to at least parse the first character to succeed
        goto parse_failed;
    } else {
        // parsed first character successfully
        ParseStateSavePoint_AdvanceByte(p);
        identifier_length++;

        while (true) {
            err = ParseStateSavePoint_PeekByte(p, &b);
            if (err == Error_Eof || !IsIdent(b)) {
                err = ParseStateSavePoint_AllocNode(p, Node_Identifier, ptr_to_node_out);
                if (err == Error_Alloc) goto alloc_error;
                NOFAIL(err);

                (**ptr_to_node_out).identifier_node.src = ParseStateSavePoint_GetNPreviousBytesDropPeeked(p, identifier_length);

                return Error_Good;
            } else {
                ParseStateSavePoint_AdvanceByte(p);
                identifier_length++;
            }
        }
    }

    parse_failed:
    ParseStateSavePoint_RestoreLexerState(p, &before_lexing);
    return Error_ParseFailed;

    alloc_error:
    ParseStateSavePoint_RestoreLexerState(p, &before_lexing);
    return Error_Alloc;
}

// Error_ParseFailed
// Error_Alloc
Error ParseStateSavePoint_ParseInteger(ParseStateSavePoint* p, Node** ptr_to_node_out) {
    Error err;
    byte b;
    UInt integer_length = 0;

    StringStream before_lexing;
    ParseStateSavePoint_SaveLexerState(p, &before_lexing);

    NOFAIL(ParseStateSavePoint_SkipWhitespace(p));

    // parse first char
    err = ParseStateSavePoint_PeekByte(p, &b);
    if (err == Error_Eof || !IsInteger(b)) {
        // need to at least parse the first character to succeed
        ParseStateSavePoint_RestoreLexerState(p, &before_lexing);
        goto parse_failed;
    } else {
        // parsed first character successfully
        ParseStateSavePoint_AdvanceByte(p);
        integer_length++;

        while (true) {
            err = ParseStateSavePoint_PeekByte(p, &b);
            if (err == Error_Eof || !IsInteger(b)) {
                err = ParseStateSavePoint_AllocNode(p, Node_Integer, ptr_to_node_out);
                if (err == Error_Alloc) goto alloc_error;
                NOFAIL(err);

                (**ptr_to_node_out).integer_node.src = ParseStateSavePoint_GetNPreviousBytesDropPeeked(p, integer_length);

                return Error_Good;
            } else {
                ParseStateSavePoint_AdvanceByte(p);
                integer_length++;
            }
        }
    }

    parse_failed:
    ParseStateSavePoint_RestoreLexerState(p, &before_lexing);
    return Error_ParseFailed;

    alloc_error:
    ParseStateSavePoint_RestoreLexerState(p, &before_lexing);
    return Error_Alloc;
}

// Error_ParseFailed
// Error_Alloc
Error ParseStateSavePoint_ParseValue(ParseStateSavePoint* p, Node** ptr_to_node_out) {
    Error err;
    ParseStateSavePoint save_point = ParseStateSavePoint_CreateNewSavePoint(p);

    Node* identifier_or_integer = NULL;
    ParseFunc funcs[] = {
        &ParseStateSavePoint_ParseIdentifier,
        &ParseStateSavePoint_ParseInteger
    };

    err = ParseStateSavePoint_ParseOneOf(&save_point, funcs, 2, &identifier_or_integer);
    if (err == Error_Alloc) goto was_err;
    if (err == Error_ParseFailed) goto was_err;
    NOFAIL(err);

    err = ParseStateSavePoint_AllocNode(&save_point, Node_Value, ptr_to_node_out);
    if (err == Error_Alloc) goto was_err;
    NOFAIL(err);

    // here we set the values of the new value node.
    if (identifier_or_integer->node_type == Node_Identifier || identifier_or_integer->node_type == Node_Integer) {
        (**ptr_to_node_out).value_node.identifier_or_integer = identifier_or_integer;
    } else {
        return Error_Internal;
    }

    // now commit the savepoint
    ParseStateSavePoint_Commit(&save_point, p);
    return Error_Good;

    was_err:
    NOFAIL(ParseStateSavePoint_DestroySavePoint(&save_point));
    return err;
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

        struct AddThenAssign {
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

    ParseStateSavePoint state;
    err = ParseStateSavePoint_Init(&state, &test_program);
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node* node = NULL;
    err = ParseStateSavePoint_ParseValue(&state, &node);
    IF_ERR(Error_ParseFailed, "parse failure.");
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node_Print(node);

    err = ParseStateSavePoint_ParseValue(&state, &node);
    IF_ERR(Error_ParseFailed, "parse failure.");
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    Node_Print(node);

    printf("\nC program:\n");

    return 0;
}
