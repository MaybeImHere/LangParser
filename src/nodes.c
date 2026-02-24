#include "nodes.h"
#include "lex.h"
#include <stdio.h>

Error ParseState_Init(ParseState *p, const String *src) {
    p->text_to_parse = *src;

    // Now initialize the DynamicArray that will hold the nodes.
    Error err = DynamicArray_Init(&p->node_array, sizeof(Node), 64);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

void ParseState_Free(ParseState *p) { DynamicArray_Free(&p->node_array); }

typedef struct ParseStateSave {
    ParseState *p;
    StringStream current_stream;

    // Counts how many nodes were pushed by this function, or by functions called within this
    // function.
    UInt nodes_pushed;

    // last_error should only be one of these errors:
    // Error_Internal, Error_ParseFailed, Error_Alloc, Error_UnknownToken
    Error last_error;
} ParseStateSave;

// Creates a parse save state from the ParseState. Should only be used once at the beginning of
// parsing. For any future parsing, just use ParseStateSave.
static ParseStateSave ParseState_InitSave(ParseState *p) {
    ParseStateSave save = {
        .p = p,
        .nodes_pushed = 0,
        .last_error = Error_Internal,
    };

    StringStream_Init(&save.current_stream, &p->text_to_parse);

    return save;
}

// Creates a new save state from a previous save state. Allows for undoing anything done on the new
// save state, including undoing any nodes pushed to the DynamicArray.
static ParseStateSave PSS_NewSave(ParseStateSave *p) {
    ParseStateSave save = *p;
    save.nodes_pushed = 0;
    save.last_error = Error_Internal;

    return save;
}

// Pops any nodes that were put onto the DynamicArray.
static void PSS_UndoSave(ParseStateSave *old_save, ParseStateSave *new_save,
                         Error reason_for_undo) {
    // pop all of the nodes we pushed to the stack.
    for (UInt i = 0; i < new_save->nodes_pushed; i++) {
        DynamicArray_UndoPushValue(&new_save->p->node_array);
    }

    // now set the old_save's last error
    old_save->last_error = reason_for_undo;
}

// Applies all of the changes made to save_to_apply. Mainly consists of putting all of the nodes
// allocated under save_to_apply under the management of old_save, by adding the number of nodes
// made to old_save's nodes_pushed. Also sets the last error to Error_Good. Also replaces the old
// StringStream with the new StringStream.
static void PSS_ApplySave(ParseStateSave *old_save, const ParseStateSave *save_to_apply) {
    old_save->current_stream = save_to_apply->current_stream;
    old_save->nodes_pushed += save_to_apply->nodes_pushed;
    old_save->last_error = Error_Good;
}

// Some errors (like Error_ParseFailed) can potentially be recovered from. Others, however, like
// Error_Alloc, probably are unrecoverable, so just bubble them up to the parser caller instead of
// trying to continue parsing.
static bool PSS_CanRecover(ParseStateSave *save) {
    return save->last_error == Error_Good || save->last_error == Error_ParseFailed;
}

// Initializes all of the stack variables needed for save states. Should be called at the very
// beginning of every parsing function.
#define PARSE_INIT ParseStateSave save = PSS_NewSave(p);

// Returns an error (indicated by false) from a parsing function, along with performing cleanup.
// Call this if there was an error.
#define PARSE_RET_ERROR_EX(reason_for_failure)                                                     \
    {                                                                                              \
        PSS_UndoSave(p, &save, reason_for_failure);                                                \
        return false;                                                                              \
    }

// this one just bubbles up errors instead of explicitly specifying them.
#define PARSE_RET_ERROR                                                                            \
    {                                                                                              \
        PSS_UndoSave(p, &save, save.last_error);                                                   \
        return false;                                                                              \
    }

// Returns true to indicate the function was successful, and applies all of the changes made to the
// save state.
#define PARSE_RET_GOOD                                                                             \
    {                                                                                              \
        PSS_ApplySave(p, &save);                                                                   \
        return true;                                                                               \
    }

// Tries to run the expression. If the expression fails, cleans up and returns false.
#define MUST_PARSE(expr)                                                                           \
    if (!(expr)) {                                                                                 \
        PARSE_RET_ERROR;                                                                           \
    }

#define CHECK_RECOVERY                                                                             \
    if (!PSS_CanRecover(&save)) {                                                                  \
        PARSE_RET_ERROR;                                                                           \
    }

// Tries to parse the expression. If parsing fails, but the error is potentially recoverable, then
// continue on. If not, then just immediately return, since there is nothing more we can do anyway.
// If parsing succeeds, skips ahead to the label defined by goto_if_good.
#define TRY_PARSE_GOTO(expr, goto_if_good)                                                         \
    {                                                                                              \
        if (!(expr)) {                                                                             \
            if (!PSS_CanRecover(&save)) {                                                          \
                PARSE_RET_ERROR;                                                                   \
            }                                                                                      \
        } else {                                                                                   \
            goto goto_if_good;                                                                     \
        }                                                                                          \
    }

#define TRY_PARSE_GOTO_FAIL(expr, goto_if_failed)                                                  \
    {                                                                                              \
        if (!(expr)) {                                                                             \
            if (!PSS_CanRecover(&save)) {                                                          \
                PARSE_RET_ERROR;                                                                   \
            }                                                                                      \
            goto goto_if_failed;                                                                   \
        }                                                                                          \
    }

// Parses a single token, with the expected token type being expected_token. Returns false and sets
// last_error to Error_ParseFailed if the wrong token is found. Sets last_error to
// Error_UnknownToken if the lexer failed. The token data is written to token_data_out.
static bool PSS_ParseToken(ParseStateSave *p, TokenType expected_token, String *token_data_out) {
    PARSE_INIT;

    Token token;
    Error err = Token_Parse(&save.current_stream, &token);
    if (err == Error_UnknownToken) {
        // didn't know the token, so we really can't do much beyond this.
        PARSE_RET_ERROR_EX(Error_UnknownToken);
    }

    // we did know the token, so was it the token we wanted?
    if (token.token_type != expected_token) {
        // wrong token.
        PARSE_RET_ERROR_EX(Error_ParseFailed);
    }

    // right token, so return the token info.
    if (token_data_out)
        *token_data_out = token.token_data;
    PARSE_RET_GOOD;
}

// Creates a new node with the data passed in through node_data, and returns the index through
// node_idx. If the function fails, last_error is set to Error_Alloc and the function returns false.
static bool PSS_CreateNode(ParseStateSave *p, const Node *node_data, Child *node_idx_out) {
    Error err =
        DynamicArray_PushValue(&p->p->node_array, (void *)node_data, &node_idx_out->next_idx);
    if (err == Error_Alloc) {
        // nothing was pushed, so don't incremenet the push counter.
        p->last_error = Error_Alloc;
        return false;
    } else if (err != Error_Good) {
        return false;
    }

    // pushed successfully, so increment node counter and return.
    p->nodes_pushed++;

    return true;
}

// Returns a pointer to the node at the given index. assumes index is an actual array index and not
// a pointer.
static Node *ParseState_GetNodePtr(ParseState *p, Child index) {
    return DynamicArray_GetPtr(&p->node_array, index.next_idx);
}

// Returns a pointer to the node with the given array index.
static Node *ParseState_GetNodePtrArrIdx(ParseState *p, ArrayIndex index) {
    return DynamicArray_GetPtr(&p->node_array, index);
}

// Parses an integer and creates an integer node.
static bool PSS_ParseInteger(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    // first parse the integer token.
    IntegerNode integer;
    MUST_PARSE(PSS_ParseToken(&save, Token_Integer, &integer.src));

    // parsing successful, now create the node.
    Node node = {.node_type = Node_Integer, .integer = integer};
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));

    // done creating the node, just return.
    PARSE_RET_GOOD;
}

// Parses an identifier and creates an identifier node.
static bool PSS_ParseIdentifier(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    // first parse the token.
    IdentifierNode identifier;
    MUST_PARSE(PSS_ParseToken(&save, Token_Identifier, &identifier.src));

    // parsing successful, now create the node.
    Node node = {.node_type = Node_Identifier, .identifier = identifier};
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));

    // done creating the node, just return.
    PARSE_RET_GOOD;
}

// Parses a value (either an identifier or an integer) and creates a value node.
static bool PSS_ParseValue(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    ValueNode value = {.child_node_type = Node_Integer,
                       .identifier_or_integer.next_idx = ARRAYINDEX_INVALID};

    // first try parsing integer.
    TRY_PARSE_GOTO(PSS_ParseInteger(&save, &value.identifier_or_integer), value_child_parsed);

    // try parsing identifier instead.
    value.child_node_type = Node_Identifier;
    TRY_PARSE_GOTO(PSS_ParseIdentifier(&save, &value.identifier_or_integer), value_child_parsed);

    // both failed
    PARSE_RET_ERROR;

    // parsing successful, now create the node.
value_child_parsed:;
    Node node = {.node_type = Node_Value, .value = value};
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));

    // done creating the node, just return.
    PARSE_RET_GOOD;
}

// forward declare so we can use it in PSS_ParseExprAtom
static bool PSS_ParseExpr(ParseStateSave *p, Child *node_idx_out);

// parses an expression atom, which is either a value, or a parenthesized expression like (a + b)
static bool PSS_ParseExprAtom(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    ExprAtom expr_atom = {
        .atom_type = ExprAtom_Invalid,
        .parenthesized_expr.next_idx = ARRAYINDEX_INVALID,
    };

    if (PSS_ParseToken(&save, Token_OpenParen, NULL)) {
        // parsing a parenthesized expression
        // set the type and parse an expression.
        expr_atom.atom_type = ExprAtom_Paren;
        MUST_PARSE(PSS_ParseExpr(&save, &expr_atom.parenthesized_expr));

        // now parse the closing parenthesis expression.
        MUST_PARSE(PSS_ParseToken(&save, Token_CloseParen, NULL));
    } else {
        CHECK_RECOVERY;

        // not a parenthesized atom, so just try parsing a value instead
        if (PSS_ParseValue(&save, &expr_atom.value)) {
            expr_atom.atom_type = ExprAtom_Value;
            // since we already parsed the actual value in the if condition, we don't have to worry
            // about parsing it here.
        } else {
            // wasn't a value or a parenthesized expression, so just an invalid atom.
            PARSE_RET_ERROR;
        }
    }

    // now actually allocate the node.
    Node node = {
        .node_type = Node_ExprAtom,
        .expr_atom = expr_atom,
    };
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));

    PARSE_RET_GOOD;
}

// Parsing negations or lone atoms.
// Will either return a negation Expr, or an ExprAtom
static bool PSS_ParseUnaryExpr(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Expr expr = {.op_type = ExprOp_Invalid};

    if (PSS_ParseToken(&save, Token_Minus, NULL)) {
        // set the type of operation.
        expr.op_type = ExprOp_Negate;
        // now parse the expression atom that is being negated.
        MUST_PARSE(PSS_ParseExprAtom(&save, &expr.one_arg_op.atom));

        Node expr_node = {.node_type = Node_Expr, .expr = expr};
        MUST_PARSE(PSS_CreateNode(&save, &expr_node, node_idx_out));

        PARSE_RET_GOOD;
    } else {
        CHECK_RECOVERY;
        // not negation, so must be a lone atom.
        MUST_PARSE(PSS_ParseExprAtom(&save, node_idx_out));
        PARSE_RET_GOOD;
    }
}

// Parsing multiplications and divisions
// Will return a ExprOp_Mul/ExprOp_Div if there is a multiplication/division, otherwise bubbles up
// return from PSS_ParseUnaryExpr.
static bool PSS_ParseMulDivExpr(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Child first_node;
    Child maybe_second_node;
    ExprOp op_type = ExprOp_Invalid;

    // we absolutely need the first node.
    MUST_PARSE(PSS_ParseUnaryExpr(&save, &first_node));

    while (true) {
        // found the first argument. check if there is a multiplication/division symbol.
        if (PSS_ParseToken(&save, Token_Asterisk, NULL)) {
            // multiplication expression. there can't be a hanging asterisk, so there must be
            // another.
            MUST_PARSE(PSS_ParseUnaryExpr(&save, &maybe_second_node));
            op_type = ExprOp_Mul;
            goto done_parsing;
        } else {
            CHECK_RECOVERY;
        }

        // try parsing division expression instead.
        if (PSS_ParseToken(&save, Token_Division, NULL)) {
            MUST_PARSE(PSS_ParseUnaryExpr(&save, &maybe_second_node));
            op_type = ExprOp_Div;
            goto done_parsing;
        } else {
            CHECK_RECOVERY;
        }

        // wasn't multiplication or division, so just bubble up the first node.
        // If there wasn't any binary operations (it was just a lone atom/negation), then first_node
        // will just contain that atom. If there was a binary operation, first_node will contain the
        // most recently created binary operation node.
        *node_idx_out = first_node;
        PARSE_RET_GOOD;
    done_parsing:;
        // since we found an operator, we have to create a new binary operator node. also, we want
        // to make sure to make this new binary node the next lhs, so that the next iteration of the
        // loop, we can check for chained binary operations, such as the expression a * b * c / d /
        // e * f

        // First create the expression struct, with the lhs being the previously parsed node or the
        // first ExprAtom. We don't have to worry about single atom expressions, as that was handled
        // in the area after the if blocks.
        Expr expr = {
            .op_type = op_type,
            .two_arg_op =
                {
                    .lhs = first_node,
                    .rhs = maybe_second_node,
                },
        };

        // Now allocate the node and push it to the stack.
        Node node = {.node_type = Node_Expr, .expr = expr};
        MUST_PARSE(PSS_CreateNode(&save, &node, &first_node));
    }
}

// Parsing additions and subtractions
// Only returns Add/Sub nodes if there is an plus/minus symbol.
static bool PSS_ParseAddSubExpr(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Child first_node;
    Child maybe_second_node;
    ExprOp op_type = ExprOp_Invalid;

    // we absolutely need the first node.
    MUST_PARSE(PSS_ParseMulDivExpr(&save, &first_node));

    while (true) {
        // found the first argument. check if there is a add/sub symbol.
        if (PSS_ParseToken(&save, Token_Plus, NULL)) {
            // add expression. there can't be a hanging plus, so there must be
            // another mul/div/atom expression.
            MUST_PARSE(PSS_ParseMulDivExpr(&save, &maybe_second_node));
            op_type = ExprOp_Add;
            goto done_parsing;
        } else {
            CHECK_RECOVERY;
        }

        // try parsing subtraction expression instead.
        if (PSS_ParseToken(&save, Token_Minus, NULL)) {
            MUST_PARSE(PSS_ParseMulDivExpr(&save, &maybe_second_node));
            op_type = ExprOp_Sub;
            goto done_parsing;
        } else {
            CHECK_RECOVERY;
        }

        // wasn't addition or subtraction, so just bubble up the first node.
        // If there wasn't any binary operations (it was just a lone atom/negation), then first_node
        // will just contain that atom. If there was a binary operation, first_node will contain the
        // most recently created binary operation node.
        *node_idx_out = first_node;
        PARSE_RET_GOOD;
    done_parsing:;
        // For details, see the MulDiv variant of this function.
        Expr expr = {
            .op_type = op_type,
            .two_arg_op =
                {
                    .lhs = first_node,
                    .rhs = maybe_second_node,
                },
        };

        // Now allocate the node and push it to the stack.
        Node node = {.node_type = Node_Expr, .expr = expr};
        MUST_PARSE(PSS_CreateNode(&save, &node, &first_node));
    }
}

// Helper macro for parsing continuations of binary operators.
#define IF_TOKEN_THEN_OP(token_type, new_op_type, lower_parse_func)                                \
    if (PSS_ParseToken(&save, token_type, NULL)) {                                                 \
        MUST_PARSE(lower_parse_func(&save, &maybe_second_node));                                   \
        op_type = new_op_type;                                                                     \
        goto done_parsing;                                                                         \
    } else {                                                                                       \
        CHECK_RECOVERY;                                                                            \
    }

// parse expressions containing comparison operators like ==, !=, <, >, <=, >=
static bool PSS_ParseComparisonExpr(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Child first_node;
    Child maybe_second_node;
    ExprOp op_type = ExprOp_Invalid;

    // we absolutely need the first node.
    MUST_PARSE(PSS_ParseAddSubExpr(&save, &first_node));

    while (true) {
        IF_TOKEN_THEN_OP(Token_GreaterThan, ExprOp_GreaterThan, PSS_ParseAddSubExpr);
        IF_TOKEN_THEN_OP(Token_LessThan, ExprOp_LessThan, PSS_ParseAddSubExpr);
        IF_TOKEN_THEN_OP(Token_GreaterOrEqual, ExprOp_GreaterOrEqual, PSS_ParseAddSubExpr);
        IF_TOKEN_THEN_OP(Token_LessOrEqual, ExprOp_LessOrEqual, PSS_ParseAddSubExpr);
        IF_TOKEN_THEN_OP(Token_EqualBool, ExprOp_IsEqual, PSS_ParseAddSubExpr);
        IF_TOKEN_THEN_OP(Token_NotEqual, ExprOp_IsNotEqual, PSS_ParseAddSubExpr);

        // wasn't addition or subtraction, so just bubble up the first node.
        // If there wasn't any binary operations (it was just a lone atom/negation), then first_node
        // will just contain that atom. If there was a binary operation, first_node will contain the
        // most recently created binary operation node.
        *node_idx_out = first_node;
        PARSE_RET_GOOD;
    done_parsing:;
        // For details, see the MulDiv variant of this function.
        Expr expr = {
            .op_type = op_type,
            .two_arg_op =
                {
                    .lhs = first_node,
                    .rhs = maybe_second_node,
                },
        };

        // Now allocate the node and push it to the stack.
        Node node = {.node_type = Node_Expr, .expr = expr};
        MUST_PARSE(PSS_CreateNode(&save, &node, &first_node));
    }
}

// parse expressions containing and/or
static bool PSS_ParseAndOrExpr(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Child first_node;
    Child maybe_second_node;
    ExprOp op_type = ExprOp_Invalid;

    // we absolutely need the first node.
    MUST_PARSE(PSS_ParseComparisonExpr(&save, &first_node));

    while (true) {
        IF_TOKEN_THEN_OP(Token_And, ExprOp_And, PSS_ParseComparisonExpr);
        IF_TOKEN_THEN_OP(Token_Or, ExprOp_Or, PSS_ParseComparisonExpr);

        // wasn't addition or subtraction, so just bubble up the first node.
        // If there wasn't any binary operations (it was just a lone atom/negation), then first_node
        // will just contain that atom. If there was a binary operation, first_node will contain the
        // most recently created binary operation node.
        *node_idx_out = first_node;
        PARSE_RET_GOOD;
    done_parsing:;
        // For details, see the MulDiv variant of this function.
        Expr expr = {
            .op_type = op_type,
            .two_arg_op =
                {
                    .lhs = first_node,
                    .rhs = maybe_second_node,
                },
        };

        // Now allocate the node and push it to the stack.
        Node node = {.node_type = Node_Expr, .expr = expr};
        MUST_PARSE(PSS_CreateNode(&save, &node, &first_node));
    }
}

#undef IF_TOKEN_THEN_OP

static bool PSS_ParseExpr(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    // just a wrapper for this for now.
    MUST_PARSE(PSS_ParseAndOrExpr(&save, node_idx_out));

    PARSE_RET_GOOD;
}

static bool PSS_ParseSetVariable(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    SetVariable var;

    MUST_PARSE(PSS_ParseToken(&save, Token_Identifier, &var.variable_name));
    MUST_PARSE(PSS_ParseToken(&save, Token_Eq, NULL));
    MUST_PARSE(PSS_ParseExpr(&save, &var.variable_value_expr));

    Node node = {.node_type = Node_SetVariable, .set_variable = var};
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));
    PARSE_RET_GOOD;
}

static bool PSS_ParseStmt(ParseStateSave *p, Child *node_idx_out);
static bool PSS_ParseIfStmt(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    IfStmt if_stmt;

    MUST_PARSE(PSS_ParseToken(&save, Token_If, NULL));
    MUST_PARSE(PSS_ParseExpr(&save, &if_stmt.condition));
    MUST_PARSE(PSS_ParseToken(&save, Token_OpenBracket, NULL));
    MUST_PARSE(PSS_ParseStmt(&save, &if_stmt.first_stmt));
    MUST_PARSE(PSS_ParseToken(&save, Token_CloseBracket, NULL));

    Node node = {.node_type = Node_IfStmt, .if_stmt = if_stmt};
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));
    PARSE_RET_GOOD;
}

static bool PSS_ParseOneStmt(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Stmt stmt = {.has_next_stmt = false, .type = Stmt_Invalid};

    if (PSS_ParseSetVariable(&save, &stmt.set_variable)) {
        stmt.type = Stmt_Assign;
        goto create_node;
    } else {
        CHECK_RECOVERY;
    }

    if (PSS_ParseIfStmt(&save, &stmt.if_stmt)) {
        stmt.type = Stmt_If;
        goto create_node;
    } else {
        CHECK_RECOVERY;
    }

    PARSE_RET_ERROR;
create_node:;
    Node node = {.node_type = Node_Stmt, .stmt = stmt};
    MUST_PARSE(PSS_CreateNode(&save, &node, node_idx_out));
    PARSE_RET_GOOD;
}

// this doesn't handle any of the logic of parsing an individual statement. it just handles parsing
// a sequence of statements. actual parsing logic is implemented in PSS_ParseOneStmt
static bool PSS_ParseStmt(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    Child first_stmt;

    // we parse the first required statement.
    MUST_PARSE(PSS_ParseOneStmt(&save, &first_stmt));

    // we set the output to the first statement in the statement chain.
    *node_idx_out = first_stmt;

    // now keep parsing statements until we reach an error.
    Child new_stmt = first_stmt;
    while (true) {
        // try and parse a new statement node.
        // we have to call ParseState_GetNodePtr from within the if blocks because the pointer to
        // the node may be invalidated after a call to PSS_ParseOneStmt
        if (!PSS_ParseOneStmt(&save, &new_stmt)) {
            CHECK_RECOVERY;

            // it failed, so we are done.
            Node *cur_node = ParseState_GetNodePtr(save.p, first_stmt);
            cur_node->stmt.has_next_stmt = false;
            PARSE_RET_GOOD;

        } else {
            // it didn't fail, so we have to continue.
            Node *cur_node = ParseState_GetNodePtr(save.p, first_stmt);
            cur_node->stmt.has_next_stmt = true;
            cur_node->stmt.next_stmt = new_stmt;

            // make sure to set the previous stmt index to the node we just created.
            first_stmt = new_stmt;
        }
    }

    PARSE_RET_ERROR;
}

// This is the actual entry point for parsing. This function, or one of it's callees, should be
// modified if changing the program parse tree structure.
static Error PSS_ParseProgram(ParseStateSave *p, Child *node_idx_out) {
    PARSE_INIT;

    // parse the node data
    Child idx;
    if (!PSS_ParseStmt(&save, &idx))
        PARSE_RET_ERROR;

    // create the node
    Node program_node = {.node_type = Node_Program, .program_node = {.variable_decl = idx}};

    if (!PSS_CreateNode(&save, &program_node, node_idx_out))
        PARSE_RET_ERROR;

    PARSE_RET_GOOD;
}

// Converts a child from an index type to a pointer type.
static void ParseState_ConvertChild(ParseState *p, Child *child_member) {
    child_member->next_ptr = ParseState_GetNodePtr(p, *child_member);
}

static bool Expr_IsOneArgOp(ExprOp op) { return op == ExprOp_Negate || op == ExprOp_LoneAtom; }
static bool Expr_IsTwoArgOp(ExprOp op) {
    return op == ExprOp_Add || op == ExprOp_Sub || op == ExprOp_Mul || op == ExprOp_Div ||
           op == ExprOp_GreaterThan || op == ExprOp_LessThan || op == ExprOp_GreaterOrEqual ||
           op == ExprOp_LessOrEqual || op == ExprOp_IsEqual || op == ExprOp_IsNotEqual ||
           op == ExprOp_And || op == ExprOp_Or;
}

// Converts node indices witin all nodes into pointers. Returns Error_Internal if an unrecognized
// node is found.
static Error ParseState_ConvertIndicesToPtrs(ParseState *p) {
    for (ArrayIndex node_idx = 0; node_idx < DynamicArray_Length(&p->node_array); node_idx++) {
        // first get the node we want to convert.
        Node *node_ptr = ParseState_GetNodePtrArrIdx(p, node_idx);
        NodeType t = node_ptr->node_type;

        // these don't have children to convert, so skip them.
        if (t == Node_Integer || t == Node_Identifier)
            continue;

        // all of these nodes need some conversion. we handle everything in this if chain.
        if (t == Node_Value) {
            ParseState_ConvertChild(p, &node_ptr->value.identifier_or_integer);
        } else if (t == Node_ExprAtom) {
            if (node_ptr->expr_atom.atom_type == ExprAtom_Paren) {
                ParseState_ConvertChild(p, &node_ptr->expr_atom.parenthesized_expr);
            } else if (node_ptr->expr_atom.atom_type == ExprAtom_Value) {
                ParseState_ConvertChild(p, &node_ptr->expr_atom.value);
            } else {
                return Error_Internal;
            }
        } else if (t == Node_Expr) {
            ExprOp op = node_ptr->expr.op_type;
            if (Expr_IsOneArgOp(op)) {
                ParseState_ConvertChild(p, &node_ptr->expr.one_arg_op.atom);
            } else if (Expr_IsTwoArgOp(op)) {
                ParseState_ConvertChild(p, &node_ptr->expr.two_arg_op.lhs);
                ParseState_ConvertChild(p, &node_ptr->expr.two_arg_op.rhs);
            } else {
                return Error_Internal;
            }
        } else if (t == Node_SetVariable) {
            ParseState_ConvertChild(p, &node_ptr->set_variable.variable_value_expr);
        } else if (t == Node_IfStmt) {
            ParseState_ConvertChild(p, &node_ptr->if_stmt.condition);
            ParseState_ConvertChild(p, &node_ptr->if_stmt.first_stmt);
        } else if (t == Node_Stmt) {
            // first convert this statement's children.
            if (node_ptr->stmt.type == Stmt_Assign) {
                ParseState_ConvertChild(p, &node_ptr->stmt.set_variable);
            } else if (node_ptr->stmt.type == Stmt_If) {
                ParseState_ConvertChild(p, &node_ptr->stmt.if_stmt);
            } else {
                return Error_Internal;
            }

            // now convert the pointer to the next statement.
            if (node_ptr->stmt.has_next_stmt) {
                ParseState_ConvertChild(p, &node_ptr->stmt.next_stmt);
            }
        } else if (t == Node_Program) {
            ParseState_ConvertChild(p, &node_ptr->program_node.variable_decl);
        } else {
            return Error_Internal;
        }
    }
    return Error_Good;
}

// This is just a wrapper around PSS_ParseProgram. Modify that function instead.
Error ParseState_ParseProgram(ParseState *p, Node **node_ptr_out) {
    ParseStateSave save = ParseState_InitSave(p);

    // just parse an integer for now, just for testing purposes.
    Child final_index;
    if (!PSS_ParseProgram(&save, &final_index)) {
        if (save.last_error == Error_Alloc) {
            return Error_Alloc;
        } else if (save.last_error == Error_ParseFailed) {
            return Error_ParseFailed;
        } else if (save.last_error == Error_Alloc) {
            return Error_Alloc;
        } else if (save.last_error == Error_UnknownToken) {
            return Error_UnknownToken;
        } else {
            // we don't check for Error_Good here because according to the return value of the
            // function above, the parsing should have failed. that should not result in Error_Good
            // being left in last_error.
            return Error_Internal;
        }
    }

    // parsing succeeded.

    // now convert everything to pointers so they are easier to use.
    if (ParseState_ConvertIndicesToPtrs(p) == Error_Internal) {
        return Error_Internal;
    }

    *node_ptr_out = ParseState_GetNodePtr(p, final_index);

    return Error_Good;
}

// Appends a String to the DynamicString out.
#define PRINT_STRING(str)                                                                          \
    {                                                                                              \
        err = DynamicString_AppendString(out, &str);                                               \
        BUBBLE(Error_Alloc);                                                                       \
        NOFAIL(err);                                                                               \
    }

#define PRINT_NODE(next_node)                                                                      \
    {                                                                                              \
        err = Child_Print(out, next_node);                                                         \
        BUBBLE(Error_Alloc);                                                                       \
        BUBBLE(Error_UnknownNodeType);                                                             \
        NOFAIL(err);                                                                               \
    }

#define PRINT_CONST_STR(str)                                                                       \
    {                                                                                              \
        err = DynamicString_AppendConstStr(out, str);                                              \
        BUBBLE(Error_Alloc);                                                                       \
        NOFAIL(err);                                                                               \
    }

// May return Error_Alloc or Error_UnknownNodeType
static Error Child_Print(DynamicString *out, Child child_node) {
    Node *node = child_node.next_ptr;
    Error err = Error_Internal;

    if (node == NULL)
        return Error_Good;

    switch (node->node_type) {
    case Node_Integer:
        PRINT_STRING(node->integer.src);
        break;

    case Node_Identifier:
        PRINT_STRING(node->integer.src);
        break;

    case Node_Value:
        if (node->value.child_node_type == Node_Integer ||
            node->value.child_node_type == Node_Identifier) {
            PRINT_NODE(node->value.identifier_or_integer);
        } else {
            return Error_Internal;
        }
        break;
    case Node_ExprAtom:
        if (node->expr_atom.atom_type == ExprAtom_Paren) {
            PRINT_CONST_STR("(");
            PRINT_NODE(node->expr_atom.parenthesized_expr);
            PRINT_CONST_STR(")");
        } else if (node->expr_atom.atom_type == ExprAtom_Value) {
            PRINT_NODE(node->expr_atom.value);
        } else {
            return Error_Internal;
        }
        break;
    case Node_Expr:
        if (node->expr.op_type == ExprOp_Add) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" + ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_Sub) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" - ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_Mul) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" * ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_Div) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" / ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_Negate) {
            PRINT_CONST_STR("-");
            PRINT_NODE(node->expr.one_arg_op.atom);
        } else if (node->expr.op_type == ExprOp_LoneAtom) {
            PRINT_NODE(node->expr.one_arg_op.atom);
        } else if (node->expr.op_type == ExprOp_GreaterThan) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" > ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_LessThan) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" < ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_GreaterOrEqual) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" >= ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_LessOrEqual) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" <= ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_IsEqual) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" == ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_IsNotEqual) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" != ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_And) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" && ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else if (node->expr.op_type == ExprOp_Or) {
            PRINT_NODE(node->expr.two_arg_op.lhs);
            PRINT_CONST_STR(" || ");
            PRINT_NODE(node->expr.two_arg_op.rhs);
        } else {
            return Error_Internal;
        }
        break;

    case Node_SetVariable:
        PRINT_STRING(node->set_variable.variable_name);
        PRINT_CONST_STR(" = ");
        PRINT_NODE(node->set_variable.variable_value_expr);
        break;

    case Node_IfStmt:
        PRINT_CONST_STR("if ");
        PRINT_NODE(node->if_stmt.condition);
        PRINT_CONST_STR(" {\n");
        PRINT_NODE(node->if_stmt.first_stmt);
        PRINT_CONST_STR("}");
        break;

    case Node_Stmt:
        if (node->stmt.type == Stmt_Assign) {
            PRINT_NODE(node->stmt.set_variable);
        } else if (node->stmt.type == Stmt_If) {
            PRINT_NODE(node->stmt.if_stmt);
        } else {
            return Error_Internal;
        }

        PRINT_CONST_STR("\n");

        if (node->stmt.has_next_stmt) {
            PRINT_NODE(node->stmt.next_stmt);
        }

        break;

    case Node_Program:
        PRINT_NODE(node->program_node.variable_decl);
        break;

    default:
        return Error_UnknownNodeType;
    }

    return Error_Good;
}
#undef PRINT_STRING
#undef PRINT_NODE

// Creates a new DynamicString, and prints out the contents of the node tree to the dynamic string.
// Returns Error_Alloc if unable to allocate memory. Returns Error_UnknownNodeType if an unknown
// node type is encountered.
Error Node_Print(DynamicString *str_out, Node *node) {
    Error err = DynamicString_Init(str_out);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    Child c;
    c.next_ptr = node;

    err = Child_Print(str_out, c);
    if (err != Error_Good) {
        DynamicString_Free(str_out);
    }
    BUBBLE(Error_Alloc);
    BUBBLE(Error_UnknownNodeType);
    NOFAIL(err);

    return Error_Good;
}