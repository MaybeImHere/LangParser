#pragma once

#include "err.h"

typedef struct String {
    const byte *data;
    UInt length;
} String;

// Reads a file and turns it into a string. A pointer to the allocated data is placed into data,
// leaving it the caller's responsibility to free.
// Error_Alloc
// Error_UnableToOpenFile
// Error_WhileReadingFile
Error String_FromFile(String *out, byte **data, const char *filename);

// Converts a literal into a String.
String StringFromLiteral(const char *literal);

// Creates a String from an array of bytes.
String String_Create(const byte *src, UInt length);

// Prints the contents of the string to the console.
void String_Print(const String *src);

// Returns the byte at the specified position.
// Does not do error checking!
byte String_At(String *s, UInt pos);

// Returns a hash of the string.
UInt String_Hash(const String *src);

// Returns true if both strings contain the same sequence of bytes.
bool String_IsEqual(const String *s1, const String *s2);

// Returns true if the string contains the same bytes as the string literal, not counting the NULL
// byte.
bool String_IsStaticEqual(const String *s1, const char *s2);

// Used to convert a string into a stream, with the ability to peek the next byte, or advance, along
// with detecting the end of the string.
typedef struct StringStream {
    String src;
    UInt pos;
    bool eof;
} StringStream;

// Initializes a StringStream with the given string.
void StringStream_Init(StringStream *s, const String *src);

// Peeks at the next byte in the stream. Returns the byte, or 0 if there are no more bytes.
byte StringStream_Peek(StringStream *s);

// Increments the stream to the next byte. Returns Error_Eof if the next peek call won't read data
// due to eof.
Error StringStream_Advance(StringStream *s);

// Returns true if there are no more bytes in the stream.
bool StringStream_IsEof(StringStream *s);

// Returns a string containing the last length bytes from the stream, not including the currently
// peeked byte.
String StringStream_GetStringWithLength(StringStream *s, UInt length);