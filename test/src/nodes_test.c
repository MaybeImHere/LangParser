#include "nodes.h"
#include "test.h"
#include <stdio.h>
#include <stdlib.h>

void TestParsing(const char *test_name, const char *to_parse, const char *expected) {
    String test_string = StringFromLiteral(to_parse);

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

int main() {
    TestParsing("addition test", "abc   +   123", "abc + 123");
    TestParsing("subtraction test", "abc   -   123", "abc - 123");
    TestParsing("multiplication test", "abc   *   123", "abc * 123");
    TestParsing("division test", "abc   /   123", "abc / 123");
    TestParsing("negation test", "-   123", "-123");
    TestParsing("lone atom test", "123", "123");
    TestParsing("parenthesis test", "123 + ((a * 3) - 4)", "123 + ((a * 3) - 4)");
    return 0;
}