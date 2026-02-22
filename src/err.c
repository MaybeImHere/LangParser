#include "err.h"

const char *Error_ToConstStr(Error err)
{
    switch (err)
    {
    case Error_Good:
        return "Error_Good";
    case Error_VarExists:
        return "Error_VarExists";
    case Error_Alloc:
        return "Error_Alloc";
    case Error_ParseFailed:
        return "Error_ParseFailed";
    case Error_Eof:
        return "Error_Eof";
    case Error_OutOfBounds:
        return "Error_OutOfBounds";
    case Error_UnexpectedToken:
        return "Error_UnexpectedToken";
    case Error_NothingToPop:
        return "Error_NothingToPop";
    case Error_FoundNothing:
        return "Error_FoundNothing";
    case Error_MustCreateNewNode:
        return "Error_MustCreateNewNode";
    case Error_KeyExists:
        return "Error_KeyExists";
    case Error_UnableToOpenFile:
        return "Error_UnableToOpenFile";
    case Error_WhileReadingFile:
        return "Error_WhileReadingFile";
    case Error_DuringFirstSlash:
        return "Error_DuringFirstSlash";
    case Error_DuringBackslash:
        return "Error_DuringBackslash";
    case Error_DuringOpenQuote:
        return "Error_DuringOpenQuote";
    case Error_DuringOpenQuoteBackslash:
        return "Error_DuringOpenQuoteBackslash";
    case Error_DuringWhitespace:
        return "Error_DuringWhitespace";
    case Error_DuringSingleQuote:
        return "Error_DuringSingleQuote";
    case Error_DuringSingleQuoteBackslash:
        return "Error_DuringSingleQuoteBackslash";
    case Error_DuringLineComment:
        return "Error_DuringLineComment";
    case Error_DuringBlockComment:
        return "Error_DuringBlockComment";
    case Error_DuringMaybeClosingBlockComment:
        return "Error_DuringMaybeClosingBlockComment";
    case Error_Internal:
        return "Error_Internal";
    default:
        return "Unknown error type.";
    }
}