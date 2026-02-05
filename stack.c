#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "stack.h"

typedef struct StackBlock
{
    byte *data;
    UInt length;
    UInt capacity;
    UInt bytes_per_item;

    struct StackBlock *prev_block;
    struct StackBlock *next_block;
} StackBlock;

// Error_Alloc
Error StackBlock_Init(StackBlock *stack_block, UInt bytes_per_item, UInt capacity);
void StackBlock_Free(StackBlock *stack_block);

// Error_Alloc: if unable to allocate memory
Error StackBlock_Init(StackBlock *stack_block, UInt bytes_per_item, UInt capacity)
{
    stack_block->data = calloc(capacity, bytes_per_item);
    if (stack_block->data == NULL)
        return Error_Alloc;

    stack_block->length = 0;
    stack_block->capacity = capacity;
    stack_block->bytes_per_item = bytes_per_item;

    stack_block->prev_block = NULL;
    stack_block->next_block = NULL;

    return Error_Good;
}

void StackBlock_Free(StackBlock *stack_block)
{
    if (stack_block == NULL)
        return;
    free(stack_block->data);
    StackBlock_Free(stack_block->next_block);
}

// Error_Alloc
static Error StackBlock_CreateNextBlock(StackBlock *parent)
{
    StackBlock *next_block = malloc(sizeof(StackBlock));
    if (next_block == NULL)
        return Error_Alloc;

    parent->next_block = next_block;

    Error ret = StackBlock_Init(next_block, parent->bytes_per_item, parent->capacity + (parent->capacity >> 1) + 1);
    if (ret == Error_Alloc)
    {
        free(next_block);
        return Error_Alloc;
    }
    NOFAIL(ret);

    next_block->prev_block = parent;
    return Error_Good;
}

// Error_Alloc
Error StackBlock_Push(StackBlock *stack_block, void *src, void **ptr_out, StackBlock **final_block)
{
    Error ret = Error_Good;

    while (true)
    {
        // create or go to the next block if we are out of space
        if (stack_block->length >= stack_block->capacity)
        {
            // check if we have to create the block
            if (stack_block->next_block == NULL)
            {
                ret = StackBlock_CreateNextBlock(stack_block);
                if (ret == Error_Alloc)
                    return Error_Alloc;
                NOFAIL(ret);
                // we just let the loop finish so that way the other branch to write the data will be taken.
                stack_block = stack_block->next_block;
            }
            else
            {
                stack_block = stack_block->next_block;
            }
        }
        else
        {
            // just copy the data to the end
            byte *dest_ptr = stack_block->data + (uintptr_t)(stack_block->bytes_per_item * stack_block->length);
            if (ptr_out != NULL)
                *ptr_out = dest_ptr;
            if (src != NULL)
                memcpy(dest_ptr, src, stack_block->bytes_per_item);
            stack_block->length++;
            if (final_block != NULL)
                *final_block = stack_block;
            return Error_Good;
        }
    }
}

void *StackBlock_GetObjPtr(StackBlock *stack_block, UInt index)
{
    return &(stack_block->data[index * stack_block->bytes_per_item]);
}

void StackBlock_GetTopObj(StackBlock *stack_block, void *out)
{
    memcpy(out, StackBlock_GetObjPtr(stack_block, stack_block->length - 1), stack_block->bytes_per_item);
}

static void StackBlock_PopUnsafe(StackBlock *stack_block, void *out)
{
    if (out != NULL)
        StackBlock_GetTopObj(stack_block, out);
    stack_block->length--;
}

// Error_Alloc
Error Stack_Init(Stack *out, UInt bytes_per_item, UInt capacity)
{
    out->stack_block = malloc(sizeof(StackBlock));
    if (out->stack_block == NULL)
        return Error_Alloc;

    Error err = StackBlock_Init(out->stack_block, bytes_per_item, capacity);
    if (err == Error_Alloc)
        return Error_Alloc;

    out->last_block_with_items = out->stack_block;
    out->stack_size = 0;

    return Error_Good;
}

void Stack_Free(Stack *out)
{
    if (out == NULL)
        return;
    StackBlock_Free(out->stack_block);
    free(out->stack_block);
}

// Error_Alloc
Error Stack_Push(Stack *out, void *src, void **ptr_out)
{
    Error err = StackBlock_Push(out->last_block_with_items, src, ptr_out, &out->last_block_with_items);
    if (err == Error_Alloc)
        return Error_Alloc;
    NOFAIL(err);

    out->stack_size++;

    return Error_Good;
}

// Error_OutOfBounds
Error Stack_Peek(Stack *in, void **ptr_out, UInt index_from_top)
{
    StackBlock *current_block = in->last_block_with_items;

    if (!(index_from_top < in->stack_size))
        return Error_OutOfBounds;

    // the index of the object as a regular array index.
    UInt converted_index = in->stack_size - index_from_top - 1;
    // when we go to the previous block, we need to keep track of how many indices we skipped in total.
    UInt objects_skipped = 0;

    while (true)
    {
        UInt start_pos_of_block = in->stack_size - current_block->length - objects_skipped;
        // if the index is in the previous block
        if (converted_index < start_pos_of_block)
        {
            current_block = current_block->prev_block;
            objects_skipped += current_block->length;
            continue;
        }
        else
        {
            // the position of the object within the current block.
            UInt block_position = converted_index - start_pos_of_block;
            *ptr_out = &(current_block->data[block_position * current_block->bytes_per_item]);
            return Error_Good;
        }
    }
}

// Error_NothingToPop
Error Stack_Pop(Stack *stack, void *out)
{
    StackBlock *last_block = stack->last_block_with_items;
    const UInt block_length = last_block->length;

    if (block_length > 1)
    {
        // we don't have to worry about the block getting emptied.
        StackBlock_PopUnsafe(last_block, out);
        return Error_Good;
    }
    else if (block_length == 1)
    {
        // just have to make sure we go to the previous block after popping.
        StackBlock_PopUnsafe(last_block, out);
        if (last_block->prev_block != NULL)
        {
            stack->last_block_with_items = last_block->prev_block;
        }
        return Error_Good;
    }
    else
    {
        return Error_NothingToPop;
    }
}

Error SaveStack_Init(SaveStack *in, UInt bytes_per_item)
{
    in->internal = malloc(sizeof(Stack));
    if (in->internal == NULL)
        return Error_Alloc;

    Error err = Stack_Init(in->internal, bytes_per_item, 512);
    if (err == Error_Alloc)
    {
        free(in->internal);
        return Error_Alloc;
    }
    NOFAIL(err);
    return Error_Good;
}

Error SaveStack_Push(SaveStack *in, void **ptr_out)
{
    Error err = Stack_Push(in->internal, NULL, ptr_out);
    if (err == Error_Alloc)
        return Error_Alloc;
    NOFAIL(err);
    return Error_Good;
}

static UInt SaveStack_GetElementCount(const SaveStack *in)
{
    return ((Stack *)in->internal)->stack_size;
}

SaveStackSaveState SaveStack_SaveState(const SaveStack *in)
{
    return SaveStack_GetElementCount(in);
}

Error SaveStack_RestoreState(SaveStack *in, const SaveStackSaveState *save_state_in)
{
    for (UInt to_pop = SaveStack_GetElementCount(in) - (*save_state_in); to_pop > 0; to_pop--)
    {
        Error err = Stack_Pop(in->internal, NULL);
        if (err == Error_NothingToPop)
            return Error_Internal;
        NOFAIL(err);
    }
    return Error_Good;
}

void SaveStack_Free(SaveStack *out)
{
    Stack_Free(out->internal);
}