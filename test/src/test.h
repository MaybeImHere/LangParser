#pragma once

#include "err.h"

#include <stdio.h>
#include <stdlib.h>

void error(const char *test_name, const char *msg, Error err, UInt line) {
    printf("FAILURE: %s (Line %d): %s. Error code: %d\n", test_name, line, msg, err);
    exit(1);
}

#define ERROR(n) error(test_name, n, err, __LINE__);
#undef NOFAIL
#define NOFAIL(n)                                                                                  \
    if (err != Error_Good) {                                                                       \
        ERROR(n);                                                                                  \
    }