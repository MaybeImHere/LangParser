#pragma once

#include "err.h"
#include "strings.h"

typedef struct Node Node;

typedef struct IntegerNode {
    String src;
} IntegerNode;

typedef struct IdentifierNode {
    String src;
} IdentifierNode;

typedef struct Value {
    Node *identifier_or_integer;
} ValueNode;

typedef struct VariableExprAtom {
    bool neg;
    Node *value_or_variable_expr;
} VariableExprAtom;

typedef enum VariableExprType { Expr_Add, Expr_Sub, Expr_Mul, Expr_SingleAtom } VariableExprType;

typedef struct VariableExpr {
    VariableExprType type;

    Node *lhs;
    Node *rhs;
} VariableExpr;

typedef struct VariableDecl {
    // identifier node
    Node *variable_name;

    // VariableExpr
    Node *variable_expr;
} VariableDecl;

typedef enum BooleanExprType { BoolExpr_Eq } BooleanExprType;

typedef struct BooleanExpr {
    BooleanExprType type;

    // lhs and rhs are of type VariableExprAtom
    Node *lhs;
    Node *rhs;
} BooleanExpr;

typedef struct IfBlock {
    Node *boolean_expr;
    Node *first_statement;
} IfBlock;

typedef struct StatementList {
    Node *if_or_var_decl;
    Node *next_stmt;
} StatementList;

typedef struct Program {
    Node *variable_decl;
} Program;

typedef enum NodeType {
    Node_Integer,
    Node_Identifier,
    Node_Value,
    Node_VariableExprAtom,
    Node_VariableExpr,
    Node_VariableDecl,
    Node_BooleanExpr,
    Node_IfBlock,
    Node_StatementList,
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
        BooleanExpr boolean_expr;
        IfBlock if_block;
        StatementList stmt_list;
        Program program_node;
    };
} Node;