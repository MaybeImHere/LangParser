#include <stdlib.h>

#include "map.h"

// Error_Alloc
Error Map_Init(Map *out, UInt key_value_byte_size, HashFunc hash_key_func, EqFunc eq_key_func) {
    Error err = DynamicArray_Init(&out->map_nodes, sizeof(MapNode), 256);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    err = DynamicArray_Init(&out->kv_pairs, key_value_byte_size, 256);
    if (err == Error_Alloc)
        goto err_kv_init;
    NOFAIL(err);

    out->hash_key_func = hash_key_func;
    out->eq_key_func = eq_key_func;

    return Error_Good;

err_kv_init:
    DynamicArray_Free(&out->map_nodes);
    return err;
}

// Error_OutOfBounds
static Error Map_GetMapNode(const Map *in, ArrayIndex node_index, MapNode **node_ptr_out) {
    MapNode *node = DynamicArray_GetPtr(&in->map_nodes, node_index);
    if (node == NULL)
        return Error_OutOfBounds;
    *node_ptr_out = node;
    return Error_Good;
}

// Error_Alloc
static Error Map_CreateMapNode(Map *in, void *kv_pair, UInt key_hash, ArrayIndex *node_index_out) {
    ArrayIndex kv_pair_index = 0;
    Error err = DynamicArray_PushValue(&in->kv_pairs, kv_pair, &kv_pair_index);
    BUBBLE(Error_Alloc);
    NOFAIL(err);

    MapNode map_node = {.kv_index = kv_pair_index,
                        .key_hash = key_hash,
                        .greater = ARRAYINDEX_INVALID,
                        .equal = ARRAYINDEX_INVALID,
                        .lesser = ARRAYINDEX_INVALID,
                        .initialized_child_nodes = MAPNODE_NOTHING_INIT};

    err = DynamicArray_PushValue(&in->map_nodes, &map_node, node_index_out);
    if (err == Error_Alloc)
        goto err_push_node;
    NOFAIL(err);

    return Error_Good;

err_push_node:
    DynamicArray_UndoPushValue(&in->kv_pairs);

    return err;
}

static void MapNode_SetEqualChild(MapNode *node, ArrayIndex child_idx) {
    node->equal = child_idx;
    node->initialized_child_nodes |= MAPNODE_EQ_INIT;
}

static void MapNode_SetGreaterChild(MapNode *node, ArrayIndex child_idx) {
    node->greater = child_idx;
    node->initialized_child_nodes |= MAPNODE_GR_INIT;
}

static void MapNode_SetLesserChild(MapNode *node, ArrayIndex child_idx) {
    node->lesser = child_idx;
    node->initialized_child_nodes |= MAPNODE_LE_INIT;
}

// This function takes in an index corresponding to a MapNode, and checks to see whether the node
// matches the key. If it does, it returns Error_KeyExists. If it doesn't, it checks to see if the
// greater/equal/lesser indices are defined. If they are, it chooses the index that corresponds to
// the comparison between the new key hash and the old key hash, such that greater will contain the
// nodes that have bigger hashes than the current node. If the corresponding index is not defined in
// the MapNode, it creates the correct MapNode child, and sets the MapNode passed in through
// node_idx. Otherwise, it just returns the next ArrayIndex that has to be checked through node_idx
// and returns Error_MoreNodes. This function assumes that node_idx is defined and is a valid node.
// Error_Alloc
// Error_MoreNodes
// Error_KeyExists
static Error Map_CreateChildOrGetNextNode(Map *map, ArrayIndex *node_idx, void *kv_pair,
                                          UInt key_hash) {
    Error err = Error_Internal;
    // first get the actual MapNode at node_idx
    MapNode *current_node_ptr = DynamicArray_GetPtr(&map->map_nodes, *node_idx);
    if (current_node_ptr == NULL)
        return Error_Internal;

    // get the key value pair for the current node.
    void *current_node_kv = DynamicArray_GetPtr(&map->kv_pairs, current_node_ptr->kv_index);
    if (current_node_kv == NULL)
        return Error_Internal;

    // are the hashes equal?
    if (current_node_ptr->key_hash == key_hash) {
        // hashes are equal, so now compare the actual keys.
        // are the keys equal?
        if (map->eq_key_func(kv_pair, current_node_kv)) {
            // equal, so key exists.
            return Error_KeyExists;
        } else {
            // not equal, check if there is an equal index.
            if (current_node_ptr->initialized_child_nodes & MAPNODE_EQ_INIT) {
                // equal nodes are initialized, so return the equal node.
                *node_idx = current_node_ptr->equal;
                return Error_MoreNodes;
            } else {
                // no more nodes are initialized, so we have to create a new one.
                ArrayIndex new_node_idx = ARRAYINDEX_INVALID;
                err = Map_CreateMapNode(map, kv_pair, key_hash, &new_node_idx);
                BUBBLE(Error_Alloc);
                NOFAIL(err);

                // now set the current node to have this node as a child.
                MapNode_SetEqualChild(current_node_ptr, new_node_idx);
                return Error_Good;
            }
        }
    } else if (key_hash > current_node_ptr->key_hash) {
        // the new kv pair has a greater hash, so check the greater index.
        if (current_node_ptr->initialized_child_nodes & MAPNODE_GR_INIT) {
            // greater hash nodes exist, so return those.
            *node_idx = current_node_ptr->greater;
            return Error_MoreNodes;
        } else {
            // there isn't a greater index, so create a node.
            ArrayIndex new_node_idx = ARRAYINDEX_INVALID;
            err = Map_CreateMapNode(map, kv_pair, key_hash, &new_node_idx);
            BUBBLE(Error_Alloc);
            NOFAIL(err);

            // now set the current node to have this node as a child.
            MapNode_SetGreaterChild(current_node_ptr, new_node_idx);
            return Error_Good;
        }
    } else if (key_hash < current_node_ptr->key_hash) {
        // the new kv pair has a lesser hash, so check the lesser index of the MapNode.
        if (current_node_ptr->initialized_child_nodes & MAPNODE_LE_INIT) {
            // lesser hash nodes exist, so return those.
            *node_idx = current_node_ptr->lesser;
            return Error_MoreNodes;
        } else {
            // there isn't a lesser index, so create a node.
            ArrayIndex new_node_idx = ARRAYINDEX_INVALID;
            err = Map_CreateMapNode(map, kv_pair, key_hash, &new_node_idx);
            BUBBLE(Error_Alloc);
            NOFAIL(err);

            // now set the current node to have this node as a child.
            MapNode_SetLesserChild(current_node_ptr, new_node_idx);
            return Error_Good;
        }
    } else {
        return Error_Internal;
    }
}

// Error_Alloc
Error Map_CreateIfNotExists(Map *map, void *kv_pair) {
    Error err = Error_Good;
    UInt key_hash = map->hash_key_func(kv_pair);

    // first try to find the key if it exists.
    // start at the first node.
    MapNode *current_node_ptr = NULL;
    err = Map_GetMapNode(map, 0, &current_node_ptr);
    if (err == Error_OutOfBounds) {
        // not even a single node, so create a new one.
        err = Map_CreateMapNode(map, kv_pair, key_hash, NULL);
        BUBBLE(Error_Alloc);
        NOFAIL(err);

        return Error_Good;
    }

    ArrayIndex current_node_idx = 0;
    while (true) {
        // get the correct child node, or create the child node.
        err = Map_CreateChildOrGetNextNode(map, &current_node_idx, kv_pair, key_hash);
        BUBBLE(Error_Alloc);
        if (err == Error_KeyExists) {
            // the key already exists
            return Error_KeyExists;
        } else if (err == Error_Good) {
            // found and created the node.
            break;
        } else if (err == Error_MoreNodes) {
            // still have to check more nodes.
        } else {
            // shouldn't get any other errors.
            return Error_Internal;
        }
    }

    return Error_Good;
}

void Map_Free(Map *in) {
    if (in == NULL)
        return;
    DynamicArray_Free(&in->map_nodes);
    DynamicArray_Free(&in->kv_pairs);
}