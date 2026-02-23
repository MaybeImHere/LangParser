#include "map.h"
#include "test.h"
#include <stdio.h>

typedef struct KeyValue {
    String key;
    UInt value;
} KeyValue;

UInt KeyValue_Hash(const void *kv) {
    const KeyValue *kv_ = (const KeyValue *)kv;
    const String *kv_s = &kv_->key;
    return String_Hash(kv_s);
}

bool KeyValue_Eq(const void *kv1, const void *kv2) {
    const String *s1 = &((KeyValue *)kv1)->key;
    const String *s2 = &((KeyValue *)kv2)->key;

    return String_IsEqual(s1, s2);
}

int main() {
    Map map;
    Error err = Map_Init(&map, sizeof(KeyValue), KeyValue_Hash, KeyValue_Eq);
    NOFAIL("Map_Init");

    KeyValue kv1 = {.key = String_FromLiteral("hello"), .value = 8};
    KeyValue kv2 = {.key = String_FromLiteral("world"), .value = 7};
    KeyValue kv3 = {.key = String_FromLiteral("hello"), .value = 6};

    err = Map_CreateIfNotExists(&map, &kv1);
    if (err == Error_Alloc) {
        ERROR("Map_CreateIfNotExists alloc");
    } else if (err == Error_KeyExists) {
        ERROR("Map_CreateIfNotExists key exists");
    } else {
        NOFAIL("Map_CreateIfNotExists");
    }

    err = Map_CreateIfNotExists(&map, &kv2);
    if (err == Error_Alloc) {
        ERROR("Map_CreateIfNotExists alloc");
    } else if (err == Error_KeyExists) {
        ERROR("Map_CreateIfNotExists key exists");
    } else {
        NOFAIL("Map_CreateIfNotExists");
    }

    err = Map_CreateIfNotExists(&map, &kv3);
    if (err == Error_Alloc) {
        ERROR("Map_CreateIfNotExists alloc");
    } else if (err == Error_KeyExists) {
        // should happen.
        ;
    } else {
        NOFAIL("Map_CreateIfNotExists");
        if (err == Error_Good) {
            ERROR("Map_CreateIfNotExists should be duplicate.");
        }
    }

    Map_Free(&map);

    return 0;
}