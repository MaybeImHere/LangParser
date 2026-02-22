#pragma once

#include "dyn.h"

typedef UInt MapNodeFlags;

// The greater index is initialized with a valid index.
#define MAPNODE_GR_INIT 0b001

// the equal index points to a valid mapnode.
#define MAPNODE_EQ_INIT 0b010

// the less than index points to a valid mapnode.
#define MAPNODE_LE_INIT 0b100

// greater, equal, and lesser do not point to valid mapnodes.
#define MAPNODE_NOTHING_INIT 0

typedef struct MapNode {
    ArrayIndex kv_index;

    UInt key_hash;

    // map node with greater hashes.
    ArrayIndex greater;

    // map node with equal hashes.
    ArrayIndex equal;

    // map node with lesser hashes.
    ArrayIndex lesser;

    // which of the above 3 are valid,
    MapNodeFlags initialized_child_nodes;
} MapNode;

typedef struct Map {
    // Holds map nodes.
    DynamicArray map_nodes;

    // holds the actual key-value data. we can't really do much with this, since we don't know what
    // key type or value type is being used
    DynamicArray kv_pairs;

    // Takes in a key-value pair, and returns a hash of the key.
    HashFunc hash_key_func;

    // Takes in 2 key-value pairs, and returns whether or not the keys are equal.
    EqFunc eq_key_func;
} Map;

// Initializes the map with keys of size key_byte_size and values of value_byte_size. Maps copy both
// keys and values by value (simple memory copy).
// If value_byte_size is 0, the Map acts like a set, and no space is allocated for values.
// Trying to retrieve 0 byte values will do nothing except check if the key exists.
// Error_Alloc
Error Map_Init(Map *out, UInt key_value_byte_size, HashFunc hash_key_func, EqFunc eq_key_func);

// Error_Alloc
// Error_KeyExists
Error Map_CreateIfNotExists(Map *out, void *kv_pair);

void Map_Free(Map *in);