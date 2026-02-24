#include "state.h"

Error StateMachine_Init(StateMachine *sm) {
    // init the state array
    Error err = DynamicArray_Init(&sm->states, sizeof(State), 1);
    if (err != Error_Good)
        goto error_states_init;

    // init the string arena
    err = DynamicString_Init(&sm->string_arena);
    if (err != Error_Good)
        goto error_string_arena_init;

    // init the instruction array
    err = DynamicArray_Init(&sm->instructions, sizeof(Instruction), 1);
    if (err != Error_Good)
        goto error_instructions;

    // init the variable set
    err = Map_Init(&sm->variables, sizeof(String), (HashFunc)String_Hash, (EqFunc)String_IsEqual);
    if (err != Error_Good)
        goto error_map_init;

    sm->next_state_id = 1;

    return Error_Good;

error_map_init:
    DynamicArray_Free(&sm->instructions);

error_instructions:
    DynamicString_Free(&sm->string_arena);

error_string_arena_init:
    DynamicArray_Free(&sm->states);

error_states_init:
    return err;
}

void StateMachine_Free(StateMachine *sm) {
    DynamicArray_Free(&sm->states);
    DynamicString_Free(&sm->string_arena);
    DynamicArray_Free(&sm->instructions);
    Map_Free(&sm->variables);
}