#include "nodes.h"
#include "test.h"
#include <stdio.h>
#include <stdlib.h>

void TestParsing(const char *test_name, const char *to_parse, const char *expected) {
    String test_string = String_FromLiteral(to_parse);

    ParseState ps;
    Error err = ParseState_Init(&ps, &test_string);
    NOFAIL("initialization of parser failed");

    Node *node_ptr = NULL;
    err = ParseState_ParseProgram(&ps, &node_ptr);
    NOFAIL("ParseProgram failed");

    if (node_ptr == NULL) {
        ERROR("node ptr is NULL after parsing");
    }

    DynamicString str;
    err = Node_Print(&str, node_ptr);
    NOFAIL("unexpected error during printing");

    UInt length = DynamicString_GetLength(&str);

    // now check the string.
    for (UInt i = 0; i < length; i++) {
        if (DynamicString_At(&str, i) != expected[i] || expected[i] == '\0') {

            UInt min_index = 0;
            UInt max_index = i;
            if (i >= 19) {
                // 19 characters before the current character, then the current character.
                min_index = i - 19;
            } else {
                min_index = 0;
            }

            printf("Expected: ");
            for (UInt j = 0; j <= max_index; j++) {
                putchar(expected[min_index + j]);
            }

            printf("\nFound: ");
            for (UInt j = 0; j <= max_index; j++) {
                putchar(DynamicString_At(&str, min_index + j));
            }
            putchar('\n');

            ERROR("unexpected output string");
        }
    }

    DynamicString_Free(&str);
    ParseState_Free(&ps);
    printf("[PASSED] %s\n", test_name);
}

void ShouldFail(const char *test_name, const char *to_parse, Error expected_error) {
    String test_string = String_FromLiteral(to_parse);

    ParseState ps;
    Error err = ParseState_Init(&ps, &test_string);
    NOFAIL("initialization of parser failed");

    Node *node_ptr = NULL;
    err = ParseState_ParseProgram(&ps, &node_ptr);
    if (err != expected_error) {
        ERROR("expected a different error");
    }

    ParseState_Free(&ps);
    printf("[PASSED] %s\n", test_name);
}

void PrintOutput(const char *test_name, const char *to_parse, bool use_file) {
    String test_string;
    byte *test_string_data = NULL;
    if (use_file) {
        Error err = String_FromFile(&test_string, &test_string_data, to_parse);
        if (err != Error_Good) {
            ERROR("while reading file.");
        }
    } else {
        test_string = String_FromLiteral(to_parse);
    }

    ParseState ps;
    Error err = ParseState_Init(&ps, &test_string);
    NOFAIL("initialization of parser failed");

    Node *node_ptr = NULL;
    err = ParseState_ParseProgram(&ps, &node_ptr);
    if (err != Error_Good) {
        ERROR("unexpected error while parsing");
    }

    DynamicString str;
    err = Node_Print(&str, node_ptr);
    if (err != Error_Good) {
        ERROR("unexpected error while printing");
    }

    UInt len = DynamicString_GetLength(&str);
    for (UInt i = 0; i < len; i++) {
        putchar(DynamicString_At(&str, i));
    }

    free(test_string_data);
    DynamicString_Free(&str);
    ParseState_Free(&ps);
    printf("\n[PASSED] %s\n", test_name);
}

int main() {
    /*
    TestParsing("statement test 1", "a = abc   +   123\nb = 123\nc = happy\nd = a != b",
                "a = abc + 123\nb = 123\nc = happy\nd = a != b\n");

    ShouldFail("no equal symbol", "a + b - c", Error_ParseFailed);
    ShouldFail("invalid expression", "a = -", Error_ParseFailed);
    ShouldFail("nothing after equals sign", "a=", Error_ParseFailed);
    */

    // PrintOutput("if test 1", "if a == b { a = b\n b = 10*c\n d=-a+b-c*(-3*d+1)}");
    PrintOutput("File reading test1", "data/test.txt", true);
    return 0;
}