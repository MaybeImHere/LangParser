#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strings.h"

Error String_FromFile(String *out, byte **data, const char *filename) {
    // first try and open the file
    FILE *file_handle = fopen(filename, "r");
    if (file_handle == NULL)
        return Error_UnableToOpenFile;

    // set up the allocated buffer with a starting size of 512 bytes.
    UInt current_capacity = 512;
    UInt current_length = 0;
    byte *buf = malloc(current_capacity);
    if (buf == NULL) {
        // didn't allocate, so close the file and return
        fclose(file_handle);
        return Error_Alloc;
    }

    // this will read the entire file into buf
    // since fread does not start from the beginning each time, we only read in the difference
    // between the capacity and the currently read portion in buf.
    UInt current_read_size = current_capacity;
    while (true) {
        // read the next few bytes
        size_t ret_val =
            fread(buf + (uintptr_t)current_length, sizeof(byte), current_read_size, file_handle);
        current_length += (UInt)ret_val;

        // we didn't read the specified number of bytes. either there weren't anymore bytes, or
        // there was some error.
        if (ret_val != current_read_size) {
            // check for end of file.
            if (feof(file_handle)) {
                *data = buf;
                out->data = buf;
                out->length = current_length;
                return Error_Good;
            } else if (ferror(file_handle)) {
                // there was an error, so just free the buffer and return.
                fclose(file_handle);
                free(buf);
                return Error_WhileReadingFile;
            }
        } else {
            // we read the entire specified read size, so there are probably more bytes to read.
            // we increase the reading size by 1.5x, and add that onto the buffer capacity.
            UInt new_reading_size = current_read_size + (current_read_size >> 1) + 1;
            buf = realloc(buf, current_capacity + new_reading_size);
            if (buf == NULL) {
                fclose(file_handle);
                return Error_Alloc;
            }
            current_capacity += new_reading_size;
        }
    }
}

String StringFromLiteral(const char *literal) {
    String ret = {.data = (const byte *)literal, .length = strlen(literal)};

    return ret;
}

String String_Create(const byte *src, UInt length) {
    String ret = {.data = src, .length = length};
    return ret;
}

void String_Print(const String *src) {
    for (UInt i = 0; i < src->length; i++) {
        putchar(src->data[i]);
    }
}

byte String_At(String *s, UInt pos) { return s->data[pos]; }

UInt String_Hash(const String *src) {
    UInt ret = 0;
    for (UInt i = 0; i < src->length; i++) {
        ret *= 17;
        ret += src->data[i];
    }

    return ret;
}

bool String_IsEqual(const String *s1, const String *s2) {
    if (s1->length != s2->length)
        return false;
    return memcmp(s1->data, s2->data, s1->length) == 0;
}

bool String_IsStaticEqual(const String *s1, const char *s2) {
    for (UInt i = 0; i < s1->length; i++) {
        if (s2[i] == '\0')
            return false;
        if ((byte)s2[i] != s1->data[i])
            return false;
    }
    return true;
}

void StringStream_Init(StringStream *s, const String *src) {
    s->src = *src;
    s->pos = 0;
    // if we are already at the end, make sure to set the eof bit.
    s->eof = src->length == 0;
}

// returns the byte at the current position, or 0 if at the end of file.
byte StringStream_Peek(StringStream *s) {
    if (s->eof) {
        return 0;
    } else {
        return s->src.data[s->pos];
    }
}

// Error_Eof: if the next peek call will result in Error_Eof
Error StringStream_Advance(StringStream *s) {
    if (s->eof)
        return Error_Eof;
    s->pos++;
    if (s->pos == s->src.length) {
        s->eof = true;
        return Error_Eof;
    }
    return Error_Good;
}

bool StringStream_IsEof(StringStream *s) { return s->eof; }

String StringStream_GetStringWithLength(StringStream *s, UInt length) {
    return String_Create(&s->src.data[s->pos - length], length);
}