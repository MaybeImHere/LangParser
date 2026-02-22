#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "map.h"
#include "nodes.h"
#include "strings.h"

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

bool ParseState_CanRecover(ParseState *state) {
    return state->last_error == Error_Good || state->last_error == Error_UnexpectedToken ||
           state->last_error == Error_ParseFailed;
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

    // parse the semicolon
    if (!Node_ParseToken(&save, Token_Semicolon, NULL))
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

// boolean-expr: expr-atom "=" expr-atom
bool Node_ParseBooleanExpr(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    enum BooleanExprType type;
    Node *lhs = NULL;
    Node *rhs = NULL;

    if (!Node_ParseVariableExprAtom(&save, &lhs))
        PARSE_FUNC_DONE_ERR;

    // parse the equals
    if (!Node_ParseToken(&save, Token_Eq, NULL))
        PARSE_FUNC_DONE_ERR;
    type = BoolExpr_Eq;

    // parse the right side of the expression.
    if (!Node_ParseVariableExprAtom(&save, &rhs))
        PARSE_FUNC_DONE_ERR;

    // now create the node on the stack
    Node *new_bool_expr_node = ParseState_CreateNode(&save);
    if (!new_bool_expr_node)
        PARSE_FUNC_DONE_ERR;

    // initialize the node
    new_bool_expr_node->node_type = Node_BooleanExpr;
    new_bool_expr_node->boolean_expr.type = type;
    new_bool_expr_node->boolean_expr.lhs = lhs;
    new_bool_expr_node->boolean_expr.rhs = rhs;

    *node_ptr_out = new_bool_expr_node;
    PARSE_FUNC_DONE_GOOD;
}

bool Node_ParseStatementList(ParseState *state, Node **node_ptr_out);

bool Node_ParseIfBlock(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    Node *boolean_expr = NULL;
    Node *first_statement = NULL;

    // parse the if token
    if (!Node_ParseToken(&save, Token_If, NULL))
        PARSE_FUNC_DONE_ERR;

    // parse the open parenthesis
    if (!Node_ParseToken(&save, Token_OpenParen, NULL))
        PARSE_FUNC_DONE_ERR;

    // parse the condition
    if (!Node_ParseBooleanExpr(&save, &boolean_expr))
        PARSE_FUNC_DONE_ERR;

    // parse the close parenthesis
    if (!Node_ParseToken(&save, Token_CloseParen, NULL))
        PARSE_FUNC_DONE_ERR;

    // parse the opening bracket
    if (!Node_ParseToken(&save, Token_OpenBracket, NULL))
        PARSE_FUNC_DONE_ERR;

    // parse the inside of the statement block.
    if (!Node_ParseStatementList(&save, &first_statement))
        PARSE_FUNC_DONE_ERR;

    // parse the trailing close bracket.
    if (!Node_ParseToken(&save, Token_CloseBracket, NULL))
        PARSE_FUNC_DONE_ERR;

    // now that we are done, check to make sure that the nodes were actually created.

    // now create the node on the stack
    Node *new_if_block = ParseState_CreateNode(&save);
    if (!new_if_block)
        PARSE_FUNC_DONE_ERR;

    // initialize the node
    new_if_block->node_type = Node_IfBlock;
    new_if_block->if_block.boolean_expr = boolean_expr;
    new_if_block->if_block.first_statement = first_statement;

    *node_ptr_out = new_if_block;
    PARSE_FUNC_DONE_GOOD;
}

// Note: this function doesn't spit out a statement node, since that doesn't exist. Instead, it
// spits out either an if node, or a variable decl node.
bool Node_ParseStatement(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    Node *if_or_variable_decl = NULL;

    if (Node_ParseVariableDecl(&save, &if_or_variable_decl))
        goto create_node;

    if (!ParseState_CanRecover(&save))
        PARSE_FUNC_DONE_ERR;

    if (!Node_ParseIfBlock(&save, &if_or_variable_decl))
        PARSE_FUNC_DONE_ERR;

create_node:;
    // don't actually create a node, since there is no statement node. just set the pointer
    *node_ptr_out = if_or_variable_decl;

    PARSE_FUNC_DONE_GOOD;
}

bool Node_ParseStatementList(ParseState *state, Node **node_ptr_out) {
    PARSE_FUNC_INIT;

    Node *current_statement = NULL;
    Node *if_or_var_decl = NULL;

    if (!Node_ParseStatement(&save, &if_or_var_decl))
        PARSE_FUNC_DONE_ERR;

    // create this node first, since this is just a linked list.
    current_statement = ParseState_CreateNode(&save);
    if (!current_statement)
        PARSE_FUNC_DONE_ERR;

    current_statement->node_type = Node_StatementList;
    current_statement->stmt_list.if_or_var_decl = if_or_var_decl;
    current_statement->stmt_list.next_stmt = NULL;

    *node_ptr_out = current_statement;

    // keep parsing statements repeatedly.
    while (true) {
        if (!Node_ParseStatement(&save, &if_or_var_decl)) {
            if (ParseState_CanRecover(&save)) {
                break;
            } else {
                PARSE_FUNC_DONE_ERR;
            }
        }

        // since we parsed the statement successfully, create the node and make it the child of the
        // current node.
        current_statement->stmt_list.next_stmt = ParseState_CreateNode(&save);
        if (!current_statement->stmt_list.next_stmt)
            PARSE_FUNC_DONE_ERR;

        current_statement = current_statement->stmt_list.next_stmt;
        current_statement->node_type = Node_StatementList;
        current_statement->stmt_list.if_or_var_decl = if_or_var_decl;
        current_statement->stmt_list.next_stmt = NULL;
    }

    PARSE_FUNC_DONE_GOOD;
}

void ParseState_Free(ParseState *in) {
    if (!in)
        return;

    // nodes themselves have no allocated data.
    SaveStack_Free(&in->stack);
}

typedef enum StateInstructionType {
    SInstr_Assign,
} StateInstructionType;

typedef struct StateInstruction {
    StateInstructionType type;
    String operand1;
    String operand2;
} StateInstruction;

typedef struct State {
    // if the state switching is conditional. basically, whether or not the flag stack is used.
    bool is_conditional;

    // if conditional, use these values for the next state.
    union {
        struct {
            struct State *true_state;
            struct State *false_state;

            String lhs_bool_expr;
            String rhs_bool_expr;

            enum StateBoolExprType {
                StateBoolExpr_Eq,
                StateBoolExpr_LessThan,
                StateBoolExpr_GreaterThan,
            } type;
        } conditional;

        struct {
            struct State *next_state;
        } unconditional;
    };

    // stack of StateInstruction
    DynamicArray state_instructions;
} State;

void State_GetInstructionIter(const State *in, StateInstruction **first_instr, UInt *num_instr) {
    *first_instr = DynamicArray_GetPtr(&in->state_instructions);
    *num_instr = DynamicArray_Length(&in->state_instructions);
}

void State_Free(State *in) {
    if (in == NULL)
        return;
    DynamicArray_Free(&in->state_instructions);
}

typedef struct StateMachine {
    // currently, the map has no values, so it acts like a set.
    Map variables;
    // stack of State
    Stack states;

    State *starting_state;
} StateMachine;

Error StateMachine_Init(StateMachine *m, State **end_state_ptr_out) {
    Error err;

    err =
        Map_Init(&m->variables, sizeof(String), 0, (HashFunc)&String_Hash, (EqFunc)&String_IsEqual);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    err = Stack_Init(&m->states, sizeof(State), 8);
    if (err == Error_Alloc)
        goto error_state;
    NOFAIL(err);

    State end_state;
    end_state.is_conditional = false;
    end_state.unconditional.next_state = NULL;
    err = DynamicArray_Init(&end_state.state_instructions, sizeof(StateInstruction), 1);
    if (err == Error_Alloc)
        goto error_end_state_init_instr;

    err = Stack_Push(&m->states, &end_state, (void **)end_state_ptr_out);
    if (err == Error_Alloc)
        goto error_end_state;

    m->starting_state = *end_state_ptr_out;

    return Error_Good;

error_end_state:
    DynamicArray_Free(&end_state.state_instructions);

error_end_state_init_instr:
    Stack_Free(&m->states);

error_state:
    Map_Free(&m->variables);
    return Error_Alloc;
}

Error StateMachine_AppendInstruction(StateMachine *m, State *s,
                                     StateInstructionType instruction_type, String lhs,
                                     String rhs) {

    StateInstruction new_instruction = {
        .type = instruction_type,
        .operand1 = lhs,
        .operand2 = rhs,
    };

    // first check if the variable exists.
    Error err = Map_CreateIfNotExists(&m->variables, &lhs, NULL);
    if (instruction_type == SInstr_Assign) {
        err = DynamicArray_PushValue(&s->state_instructions, &new_instruction);
        BUBBLE(Error_Alloc);
        NOFAIL(err);
    }

    return Error_Good;
}

// Error_Alloc
#define APPEND_LINE(text, indent)                                                                  \
    err = DynamicString_AppendConstStrLine(out, text, indent * 4);                                 \
    BUBBLE(Error_Alloc);                                                                           \
    NOFAIL(err);

#define APPEND_STRING(text)                                                                        \
    err = DynamicString_AppendString(out, text);                                                   \
    BUBBLE(Error_Alloc);                                                                           \
    NOFAIL(err);

#define APPEND_CSTR(text)                                                                          \
    err = DynamicString_AppendConstStr(out, text);                                                 \
    BUBBLE(Error_Alloc);                                                                           \
    NOFAIL(err);

Error StateMachine_ToCFile(const StateMachine *m, DynamicString *out) {
    // first print out the header.
    Error err = Error_Internal;

    // print header
    APPEND_LINE("#include <stdio.h>", 0);
    APPEND_LINE("", 0);
    APPEND_LINE("int main(void) {", 0);

    State *current_state = m->starting_state;

    StateInstruction *first_instr = NULL;
    UInt instr_count = 0;
    State_GetInstructionIter(current_state, &first_instr, &instr_count);

    for (UInt i = 0; i < instr_count; i++) {
        if (first_instr[i].type == SInstr_Assign) {
            APPEND_CSTR("    ");
            APPEND_STRING(&first_instr[i].operand1);
            APPEND_CSTR(" = ");
            APPEND_STRING(&first_instr[i].operand2);
            APPEND_CSTR(";\n");
        }
    }

    // print footer
    APPEND_LINE("return 0;", 1);
    APPEND_LINE("}", 0);

    return Error_Good;
}
#undef APPEND_LINE

void StateMachine_Free(StateMachine *in) {
    if (in == NULL)
        return;
    Error err = Error_Good;

    Map_Free(&in->variables);

    State state_to_free;

    while (true) {
        err = Stack_Pop(&in->states, &state_to_free);
        if (err == Error_NothingToPop)
            break;

        State_Free(&state_to_free);
    }
}

#pragma clang diagnostic ignored "-Wunused-variable"

void error(const char *src, const char *msg, UInt line) {
    printf("%s(%u): %s\n", src, line, msg);
    exit(1);
}

// returns true if there was an error
bool PrintIfError(ParseState *state) {
    if (state->last_error != Error_Good) {
        if (state->last_error == Error_ParseFailed) {
            printf("parse failure: wrong token at pos %d\n", state->stream.pos);
        } else if (state->last_error == Error_Alloc) {
            printf("parse failure: unable to allocate at pos %d\n", state->stream.pos);
        } else if (state->last_error == Error_UnknownToken) {
            printf("parse failure: unknown token at pos %d\n", state->stream.pos);
        } else if (state->last_error == Error_Internal) {
            printf("parse failure: internal error at pos %d\n", state->stream.pos);
        } else {
            printf("parse failure: unexpected error (%d) at pos %d\n", state->last_error,
                   state->stream.pos);
        }
        return true;
    } else {
        return false;
    }
}

#define IF_ERR(_err, msg)                                                                          \
    if (_err == err) {                                                                             \
        error("main", msg, __LINE__);                                                              \
    }

#undef NOFAIL
#define NOFAIL                                                                                     \
    if (err != Error_Good) {                                                                       \
        printf("Error code: %d\n", err);                                                           \
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

    if (!Node_ParseStatementList(&parser, &node)) {
        PrintIfError(&parser);
        return 1;
    }

    Node_Print(node);
    printf("\n");

    StateMachine sm;
    State *end_state = NULL;
    err = StateMachine_Init(&sm, &end_state);
    if (err != Error_Good) {
        printf("state machine init: %d\n", err);
        return 1;
    }

    String a = StringFromLiteral("a");
    String b = StringFromLiteral("b");

    StateMachine_AppendInstruction(&sm, end_state, SInstr_Assign, a, b);
    StateMachine_AppendInstruction(&sm, end_state, SInstr_Assign, b, b);
    StateMachine_AppendInstruction(&sm, end_state, SInstr_Assign, b, a);

    DynamicString c_program;
    err = DynamicString_Init(&c_program);
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    err = StateMachine_ToCFile(&sm, &c_program);
    IF_ERR(Error_Alloc, "allocation failure.");
    NOFAIL;

    printf("\nC program:\n");

    UInt s_len = DynamicString_GetLength(&c_program);
    for (UInt i = 0; i < s_len; i++) {
        putchar((byte)DynamicString_At(&c_program, i));
    }
    putchar('\n');

    DynamicString_Free(&c_program);
    StateMachine_Free(&sm);
    ParseState_Free(&parser);
    free(program_data);
    return 0;
}
