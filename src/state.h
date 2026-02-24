#pragma once

#include "dyn.h"
#include "err.h"
#include "map.h"
#include "nodes.h"
#include "strings.h"

typedef struct Instruction {
    // the code for this instruction, represented as a C assignment expression.
    DynStrRef c_instruction;
} Instruction;

typedef enum StateTransitionType {
    StateTrans_Jmp, // unconditional transition
    StateTrans_Cmp, // conditional transition
} StateTransitionType;

typedef struct State {
    UInt state_id;
    // a slice from the string_arena.
    ArrayIndex instr_start_idx;
    ArrayIndex instr_end_idx;

    // when appending an instruction, we also have to append a comma. we don't want to do this for
    // the first instruction.
    bool has_first_instruction;

    StateTransitionType trans_type;
    union {
        UInt unconditional_next_state;
        struct {
            // a slice from string_arena.
            String condition;
            UInt truth_state;
            UInt false_state;
        } cond;
    };
} State;

typedef struct StateMachine {
    // Holds type State
    DynamicArray states;

    // all operations on the State graph will occur in this state.
    // note that pushing to states will invalidate this pointer.
    State *state_cursor;

    // holds strings for all of the states.
    DynamicString string_arena;

    // a map from String -> void
    // so really just a set. need this so we know what variables to declare at the start of
    // main.
    Map variables;

    // incremented everytime a new state is created. the exit state is 0. this should start at 1.
    UInt next_state_id;
} StateMachine;

// Initializes the state machine. May return Error_Alloc
Error StateMachine_Init(StateMachine *sm);

// Appends an assignment instruction to the current state with the given variable name and
// expression.
Error StateMachine_AppendAssignment(StateMachine *sm, const String *variable_name,
                                    const String *expression);

// Converts the state machine to a c program.
Error StateMachine_ToCProgram(const StateMachine *sm, DynamicString *out);

// Frees the state machine and any associated data.
void StateMachine_Free(StateMachine *sm);