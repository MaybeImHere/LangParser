#include "state.h"
#include <stdlib.h>
#include <string.h>

#define EXIT_STATE 0
#define START_STATE 1

// static Error StateMachine_GetEndOfStrArenaPtr(StateMachine *sm) { return }

// Creates the initial state, and sets the StateMachine's cursor equal to the new state.
// Error_Alloc
static Error SM_CreateInitialState(StateMachine *sm) {
    State state = {
        .state_id = sm->next_state_id++,
        .instr_start_idx = 0,
        .instr_end_idx = 0,
        .has_first_instruction = false,
        .trans_type = StateTrans_Jmp,
        .unconditional_next_state = EXIT_STATE,
    };

    ArrayIndex new_state_index = ARRAYINDEX_INVALID;
    Error err = DynamicArray_PushValue(&sm->states, &state, &new_state_index);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    sm->state_cursor = DynamicArray_GetPtr(&sm->states, new_state_index);

    return Error_Good;
}

Error StateMachine_Init(StateMachine *sm) {
    // init the state array
    Error err = DynamicArray_Init(&sm->states, sizeof(State), 1);
    if (err != Error_Good)
        goto error_states_init;

    // init the string arena
    err = DynamicString_Init(&sm->string_arena);
    if (err != Error_Good)
        goto error_string_arena_init;

    // init the variable set
    err = Map_Init(&sm->variables, sizeof(String), (HashFunc)String_Hash, (EqFunc)String_IsEqual);
    if (err != Error_Good)
        goto error_map_init;

    sm->next_state_id = START_STATE;

    // now that all of the basic stuff is initialized, create the first state.
    err = SM_CreateInitialState(sm);
    if (err != Error_Good)
        goto error_first_state_init;

    return Error_Good;

error_first_state_init:
    Map_Free(&sm->variables);

error_map_init:
    DynamicString_Free(&sm->string_arena);

error_string_arena_init:
    DynamicArray_Free(&sm->states);

error_states_init:
    return err;
}

// Appends a string to the string_arena, and increases the string reference in the current state by
// the new string's length. basically, tacks the new string onto the end of the current state's
// instruction list.
// Error_Alloc
static Error SM_AppendStringToStateInstr(StateMachine *sm, const String *input) {
    Error err = DynamicString_AppendString(&sm->string_arena, input);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now increase the slice by the new string's length.
    sm->state_cursor->instr_end_idx += input->length;

    return Error_Good;
}

// Appends a constant string to the end of the current state's instruction list. does not do any
// processing such as inserting commas.
// Error_Alloc
static Error SM_AppendConstStringToStateInstr(StateMachine *sm, const char *input) {
    Error err = DynamicString_AppendConstStr(&sm->string_arena, input);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now increase the slice by the new string's length.
    sm->state_cursor->instr_end_idx += (UInt)strlen(input);

    return Error_Good;
}

Error StateMachine_AppendAssignment(StateMachine *sm, const String *variable_name,
                                    const String *expression) {
    Error err = Error_Internal;
    if (sm->state_cursor->has_first_instruction) {
        // appending the second, third, etc. instruction
        err = SM_AppendConstStringToStateInstr(sm, ", ");
        BUBBLE(Error_Alloc);
        NOFAIL(err);
    } else {
        // appending the first instruction
        sm->state_cursor->has_first_instruction = true;
    }

    err = SM_AppendStringToStateInstr(sm, variable_name);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    err = SM_AppendConstStringToStateInstr(sm, " = ");
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    err = SM_AppendStringToStateInstr(sm, expression);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

static UInt StateMachine_GetStateCount(const StateMachine *sm) { return sm->next_state_id - 1; }

Error StateMachine_ToCProgram(const StateMachine *sm, DynamicString *out) { return Error_Good; }

void StateMachine_Free(StateMachine *sm) {
    DynamicArray_Free(&sm->states);
    DynamicString_Free(&sm->string_arena);
    Map_Free(&sm->variables);
}