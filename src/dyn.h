#pragma once

#include "err.h"
#include "strings.h"

typedef UInt ArrayIndex;

#define ARRAYINDEX_INVALID UIntMax

typedef struct DynamicString {
    byte *src;
    UInt length;
    UInt capacity;
} DynamicString;

// A string that uses indices instead of pointers to reference a part of the array.
typedef struct DynStrRef {
    const DynamicString *dyn_str;
    ArrayIndex start_index;
    UInt length;
} DynStrRef;

// Initializes the heap allocated string.
// Error_Alloc
Error DynamicString_Init(DynamicString *out);

// NOTE: only call this function on string literals! looks for null byte at end of string.
// Error_Alloc
Error DynamicString_AppendConstStr(DynamicString *out, const char *s);

// Appends a String to the end of the dynamic string.
// Error_Alloc
Error DynamicString_AppendString(DynamicString *out, const String *s);

// returns the last valid index of the string, plus 1
UInt DynamicString_GetLength(const DynamicString *in);

// Returns the byte at the specified index. if out of bounds, returns 0.
byte DynamicString_At(const DynamicString *in, UInt index);

// Returns a zero length string reference to the given position within the DynamicString.
DynStrRef DynamicString_GetRefToIndex(const DynamicString *in, ArrayIndex index);

// Appends a space_count number of spaces to the string.
// Error_Alloc
Error DynamicString_StartLine(DynamicString *in, UInt space_count);

// Appends a newline to the string.
// Error_Alloc
Error DynamicString_EndLine(DynamicString *in);

// Appends s to the end of the dynamic string wtih the given indentation, and puts a newline at the
// end.
Error DynamicString_AppendConstStrLine(DynamicString *out, const char *s, UInt space_count);

void DynamicString_Free(DynamicString *in);

typedef struct DynamicArray {
    byte *src;
    UInt length;
    UInt capacity;
    UInt obj_size;
} DynamicArray;

// Error_Alloc
Error DynamicArray_Init(DynamicArray *out, UInt obj_size, UInt capacity);

// Copies the bytes at src to the end of the array, resizing if necessary. returns the new index in
// new_obj_index.
// Error_Alloc
Error DynamicArray_PushValue(DynamicArray *out, void *src, ArrayIndex *new_obj_index);

UInt DynamicArray_Length(const DynamicArray *in);

// Returns the element at the given index by value.
// Error_OutOfBounds
Error DynamicArray_At(const DynamicArray *in, UInt index, void *out);

// Gets a pointer to the element at index.
// Returns NULL if beyond the end of the array.
void *DynamicArray_GetPtr(const DynamicArray *in, ArrayIndex index);

// undoes the last call to DynamicArray_PushValue. Does nothing if the array is empty.
void DynamicArray_UndoPushValue(DynamicArray *in);

void DynamicArray_Free(DynamicArray *in);