#pragma once
#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t UInt;
typedef int32_t Int;

typedef enum Error
{
    Error_Good,
    Error_VarExists,
    Error_Alloc,
    Error_ParseFailed,
    Error_Eof,
    Error_OutOfBounds,
    Error_UnexpectedToken,
    Error_NothingToPop,
    Error_FoundNothing,
    Error_MustCreateNewNode,
    Error_KeyExists,

    Error_UnableToOpenFile,
    Error_WhileReadingFile,

    Error_DuringFirstSlash,
    Error_DuringBackslash,
    Error_DuringOpenQuote,
    Error_DuringOpenQuoteBackslash,
    Error_DuringWhitespace,
    Error_DuringSingleQuote,
    Error_DuringSingleQuoteBackslash,
    Error_DuringLineComment,
    Error_DuringBlockComment,
    Error_DuringMaybeClosingBlockComment,
    Error_UnknownToken,

    Error_Internal
} Error;

#define NOFAIL(x)              \
    if ((x) != Error_Good)     \
    {                          \
        return Error_Internal; \
    }

#define BUBBLE(err_type) \
    if (err == err_type) \
    {                    \
        return err_type; \
    }

#define ASSERT(cond)           \
    if (!(cond))               \
    {                          \
        return Error_Internal; \
    }

#define NOFAIL_SKIP_PARSE_FAILURE(err)                                \
    if ((err) != Error_ParseFailed && (err) != Error_UnexpectedToken) \
    {                                                                 \
        NOFAIL(err);                                                  \
    }