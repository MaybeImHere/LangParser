#pragma once

#include "dyn.h"
#include "err.h"
#include "map.h"
#include "nodes.h"
#include "strings.h"

typedef struct Instruction {
    // the code for this instruction, represented as a C assignment expression.
    String c_instruction;
} Instruction;

typedef enum StateTransitionType {
    StateTrans_Jmp, // unconditional transition
    StateTrans_Cmp, // conditional transition
} StateTransitionType;

typedef struct State {
    UInt state_id;
    // a slice from the string_arena.
    String instructions;

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

    // holds strings for all of the states.
    DynamicString string_arena;

    // holds all of the instructions, is an array holding String.
    DynamicArray instructions;

    // a map from String -> void
    // so really just a set. need this so we know what variables to declare at the start of
    // main.
    Map variables;

    // incremented everytime a new state is created. the exit state is 0. this should start at 1.
    UInt next_state_id;
} StateMachine;

// Initializes the state machine. May return Error_Alloc
Error StateMachine_Init(StateMachine *sm);

// Frees the state machine and any associated data.
void StateMachine_Free(StateMachine *sm);