#include "dyn.h"
#include "test.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    DynamicArray arr;
    Error err = DynamicArray_Init(&arr, sizeof(int), 4);
    NOFAIL("DynamicArray_Init");

    // push a bunch of values.
    for (int i = 0; i < 1000; i++) {
        int j = i * 2;
        err = DynamicArray_PushValue(&arr, &j, NULL);
        if (err != Error_Good) {
            printf("value of i: %d\n", i);
        }
        NOFAIL("DynamicArray_PushValue");
    }

    for (int i = 0; i < 1000; i++) {
        int *int_ptr = DynamicArray_GetPtr(&arr, (ArrayIndex)i);
        if (*int_ptr != i * 2) {
            printf("Expected: %d, actual: %d\n", i * 2, *int_ptr);
            ERROR("DynamicArray_GetPtr");
        }
    }

    DynamicArray_Free(&arr);

    return 0;
}