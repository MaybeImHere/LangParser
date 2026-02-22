#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "dyn.h"
#include "err.h"

Error DynamicString_Init(DynamicString *out) {
    out->src = malloc(8);
    if (!out->src)
        return Error_Alloc;

    out->length = 0;
    out->capacity = 8;

    return Error_Good;
}

// Checks if more space needs to be allocated to fit an extra_bytes number of bytes. If more space
// is needed, reallocates the string. Otherwise, does nothing.
// Error_Alloc
static Error DynamicString_CheckRealloc(DynamicString *in, UInt extra_bytes) {
    if (in->capacity < in->length + extra_bytes) {
        UInt new_capacity = in->capacity;

        // increase capacity by 1.5x until the new bytes fit.
        while (new_capacity < in->length + extra_bytes) {
            // don't have enough space
            new_capacity = new_capacity + (new_capacity >> 1) + 1;
        }

        if (new_capacity != in->capacity) {
            // now reallocate
            byte *new_src = realloc(in->src, new_capacity);
            if (!new_src)
                return Error_Alloc;
            in->src = new_src;
            in->capacity = new_capacity;
        }

        return Error_Good;
    } else {
        return Error_Good;
    }
}

// Error_Alloc
static Error DynamicString_AppendBytes(DynamicString *out, const byte *bytes, UInt len) {
    if (len == 0)
        return Error_Good;

    // check if we have enough room
    Error err = DynamicString_CheckRealloc(out, len);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now copy the data
    for (UInt i = 0; i < len; i++) {
        out->src[i + out->length] = bytes[i];
    }

    out->length += len;

    return Error_Good;
}

// Appends a byte to the end of the string num times.
// Error_Alloc
static Error DynamicString_AppendByteRepeatedly(DynamicString *out, byte byte_to_append, UInt num) {
    if (num == 0)
        return Error_Good;

    // check if we have enough room
    Error err = DynamicString_CheckRealloc(out, num);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // now copy the data
    for (UInt i = 0; i < num; i++) {
        out->src[i + out->length] = byte_to_append;
    }

    out->length += num;

    return Error_Good;
}

Error DynamicString_AppendConstStr(DynamicString *out, const char *s) {
    UInt s_len = (UInt)strlen(s);
    Error err = DynamicString_AppendBytes(out, (const byte *)s, s_len);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

Error DynamicString_AppendString(DynamicString *out, const String *s) {
    Error err = DynamicString_AppendBytes(out, s->data, s->length);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

UInt DynamicString_GetLength(const DynamicString *in) { return in->length; }

byte DynamicString_At(const DynamicString *in, UInt index) {
    if (index >= in->length)
        return (byte)0;
    return in->src[index];
}

Error DynamicString_StartLine(DynamicString *in, UInt space_count) {
    Error err = DynamicString_AppendByteRepeatedly(in, ' ', space_count);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

Error DynamicString_EndLine(DynamicString *in) {
    Error err = DynamicString_AppendByteRepeatedly(in, '\n', 1);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

Error DynamicString_AppendConstStrLine(DynamicString *out, const char *s, UInt space_count) {
    Error err = Error_Internal;

    err = DynamicString_StartLine(out, space_count);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    DynamicString_AppendConstStr(out, s);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    DynamicString_EndLine(out);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    return Error_Good;
}

void DynamicString_Free(DynamicString *in) {
    free(in->src);
    in->src = NULL;
    in->length = 0;
    in->capacity = 0;
}

Error DynamicArray_Init(DynamicArray *out, UInt obj_size, UInt capacity) {
    out->src = calloc(capacity, obj_size);
    if (!out->src)
        return Error_Alloc;
    out->length = 0;
    out->capacity = capacity;
    out->obj_size = obj_size;
    return Error_Good;
}

// Error_Alloc
static Error DynamicArray_ReallocIfNeeded(DynamicArray *out, UInt additional_elem) {
    if (out->capacity < out->length + additional_elem) {
        UInt new_capacity = out->capacity + (out->capacity >> 1) + 1;
        while (new_capacity < out->length + additional_elem)
            new_capacity = new_capacity + (new_capacity >> 1) + 1;
        byte *new_src = realloc(out->src, new_capacity * out->obj_size);
        if (!new_src)
            return Error_Alloc;

        out->src = new_src;
        out->capacity = new_capacity;
    }
    return Error_Good;
}

Error DynamicArray_PushValue(DynamicArray *out, void *src, ArrayIndex *new_obj_index) {
    Error err = DynamicArray_ReallocIfNeeded(out, 1);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    // out->length is now a valid index since we increased capacity.
    // do ++ so that index 0 is valid (or the last index if not 0)
    out->length++;
    memcpy(DynamicArray_GetPtr(out, out->length - 1), src, out->obj_size);

    if (new_obj_index != NULL)
        *new_obj_index = out->length - 1;

    return Error_Good;
}

UInt DynamicArray_Length(const DynamicArray *in) { return in->length; }

Error DynamicArray_At(const DynamicArray *in, UInt index, void *out) {
    if (index < in->length) {
        memcpy(out, &in->src[index * in->obj_size], in->obj_size);
        return Error_Good;
    } else {
        return Error_OutOfBounds;
    }
}

void *DynamicArray_GetPtr(const DynamicArray *in, ArrayIndex index) {
    if (index >= in->length)
        return NULL;
    return &in->src[index * in->obj_size];
}

void DynamicArray_UndoPushValue(DynamicArray *in) {
    if (in->length > 0) {
        in->length--;
    }
}

void DynamicArray_Free(DynamicArray *in) {
    free(in->src);
    in->src = NULL;
    in->length = 0;
    in->capacity = 0;
    in->obj_size = 0;
}