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

typedef struct VariableExpr {
    enum VariableExprType { Expr_Add, Expr_Sub, Expr_Mul, Expr_SingleAtom } type;

    Node *lhs;
    Node *rhs;
} VariableExpr;

typedef struct VariableDecl {
    // identifier node
    Node *variable_name;

    // VariableExpr
    Node *variable_expr;
} VariableDecl;

typedef struct Program {
    Node *variable_decl;
} Program;