#include "state.h"
#include "test.h"

int main() {
    String file_data;
    byte *file_alloc;
    Error err = String_FromFile(&file_data, &file_alloc, "data/test.txt");
    const char *test_name = "state machine test";

    if (err != Error_Good) {
        ERROR("While reading file");
    }

    ParseState ps;
    err = ParseState_Init(&ps, &file_data);
    if (err != Error_Good) {
        ERROR("While initializing parser");
    }

    StateMachine sm;
    err = StateMachine_Init(&sm);
    if (err != Error_Good) {
        ERROR("While initializing state machine");
    }

    StateMachine_Free(&sm);
    ParseState_Free(&ps);
    free(file_alloc);

    printf("[PASSED] %s\n", test_name);

    return 0;
}