#pragma once

#include "dyn.h"
#include "err.h"
#include "strings.h"

typedef struct ParseState {
    // holds the text that will be parsed.
    String text_to_parse;

    // will hold the nodes.
    DynamicArray node_array;
} ParseState;

// Initializes the parser with the given string. Returns Error_Alloc if unable to allocate memory.
// Error_Alloc
Error ParseState_Init(ParseState *p, const String *src);

typedef struct Node Node;

// The parsing functions use array indices, since the node array may reallocate, invalidating
// pointers. Instead, at the end of parsing, since the dynamic array shouldn't change anymore, we
// convert all of the indices to pointers, using the union to help save memory.
struct Child {
    union {
        Node *next_ptr;
        ArrayIndex next_idx;
    };
};

typedef struct Child Child;

Error ParseState_ParseProgram(ParseState *p, Node **node_ptr_out);
void ParseState_Free(ParseState *p);

typedef enum NodeType {
    Node_Integer,
    Node_Identifier,
    Node_Value,
    Node_ExprAtom,
    Node_Expr,
    Node_Program,
} NodeType;

// holds an integer.
typedef struct IntegerNode {
    String src;
} IntegerNode;

// holds an identifier
typedef struct IdentifierNode {
    String src;
} IdentifierNode;

// can hold either an identifier or an integer.
typedef struct Value {
    NodeType child_node_type;
    Child identifier_or_integer;
} ValueNode;

// 1 + (2 + 3) * 4

typedef enum ExprAtomType {
    ExprAtom_Paren,
    ExprAtom_Value,
    ExprAtom_Invalid,
} ExprAtomType;

typedef struct ExprAtom {
    ExprAtomType atom_type;
    union {
        Child parenthesized_expr;
        Child value;
    };
} ExprAtom;

typedef enum ExprOp {
    ExprOp_Add,
    ExprOp_Sub,
    ExprOp_Mul,
    ExprOp_Div,
    ExprOp_Negate,
    ExprOp_LoneAtom,
    ExprOp_Invalid,
} ExprOp;

typedef struct Expr {
    ExprOp op_type;

    union {
        struct {
            Child atom;
        } one_arg_op;

        struct {
            Child lhs;
            Child rhs;
        } two_arg_op;
    };
} Expr;

typedef struct Program {
    Child variable_decl;
} Program;

typedef struct Node {
    NodeType node_type;

    union {
        IntegerNode integer;
        IdentifierNode identifier;
        ValueNode value;
        ExprAtom expr_atom;
        Expr expr;
        Program program_node;
    };
} Node;

// Prints a node tree to the console. Should be able to parse this tree back into the original.
Error Node_Print(DynamicString *out, Node *node);
