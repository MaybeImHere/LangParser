#pragma once

#include "err.h"

typedef struct StackBlock StackBlock;

typedef struct Stack
{
    StackBlock *stack_block;
    StackBlock *last_block_with_items;
    UInt stack_size;
} Stack;

// Error_Alloc
Error Stack_Init(Stack *out, UInt bytes_per_item, UInt capacity);
void Stack_Free(Stack *out);
// Error_Alloc
Error Stack_Push(Stack *out, void *src, void **ptr_out);
// Error_OutOfBounds
Error Stack_Peek(Stack *in, void **ptr_out, UInt index_from_top);
// Error_NothingToPop
Error Stack_Pop(Stack *stack, void *out);

typedef struct SaveStack
{
    void *internal;
} SaveStack;

// just describes how many nodes to pop.
typedef UInt SaveStackSaveState;

// Error_Alloc
Error SaveStack_Init(SaveStack *in, UInt bytes_per_item);
// Error_Alloc
Error SaveStack_Push(SaveStack *in, void **ptr_out);

// saves the current state of the stack.
SaveStackSaveState SaveStack_SaveState(const SaveStack *in);

// restores the stack to it's previous state.
// should not fail.
Error SaveStack_RestoreState(SaveStack *in, const SaveStackSaveState *save_state_in);

void SaveStack_Free(SaveStack *out);